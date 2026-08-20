# -*- coding: utf-8 -*-
# Copyright (c) 2026 Emerson Felipe
# Apache License 2.0 (see LICENSE)

"""
Client for the netbox-openbao REST API.

Deliberately small and dependency-light: it speaks to the plugin's documented
REST contract and nothing else. That contract is the whole reason
`netbox-openbao` resolves secrets server-side, and it is far more stable than
the plugin's internals — which is why this collection is packaged separately
from it rather than shipped in the same wheel.

Two behaviours here are the ones that matter operationally:

* **Errors are actionable.** A 429 from the reveal rate limit, a 403 from a
  token without `reveal_credential`, and a 404 from an object-permission
  constraint all look like generic HTTP failures unless something explains
  them. Each is the kind of thing an operator would otherwise spend an
  afternoon on.
* **Reveals are cached in-process.** The reveal endpoint is rate limited per
  user, default `30/hour`, and a play that resolves the same credential for
  every host would otherwise burn one call per host. See `ResolverCache` for
  what that does and does not cover.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request

__metaclass__ = type

DEFAULT_TIMEOUT = 30

# Environment variables consulted for the API token, in order. Both are
# supported because an estate that already exports NETBOX_TOKEN for other
# tooling should not need a second one.
TOKEN_ENV_VARS = ('NETBOX_OPENBAO_TOKEN', 'NETBOX_TOKEN')
URL_ENV_VARS = ('NETBOX_OPENBAO_URL', 'NETBOX_URL', 'NETBOX_API')

# NetBox 4.7 issues v2 API tokens, presented as `Bearer nbt_<key>.<token>`.
# Legacy v1 tokens use `Token <token>` and are on their way out. Which scheme a
# token needs is decidable from the token itself, so the collection accepts
# either rather than making the operator declare it.
V2_TOKEN_PREFIX = 'nbt_'


class OpenBaoLookupError(Exception):
    """Base for every error this client raises. Message is operator-facing."""


class OpenBaoAuthError(OpenBaoLookupError):
    pass


class OpenBaoRateLimited(OpenBaoLookupError):
    pass


class OpenBaoNotFound(OpenBaoLookupError):
    pass


class ResolverCache:
    """
    Process-local memo for resolved credentials and revealed material.

    **What it covers:** repeated resolution within a single Ansible process.
    Lookups evaluated in play-level `vars`, in a `run_once` task, or inside a
    single fork all share it, so a credential is resolved and revealed once
    rather than once per use.

    **What it does not cover:** Ansible forks worker processes for host
    execution, and each fork gets its own copy of this. A lookup written inline
    on a task that runs against 200 hosts will therefore still make up to one
    reveal per fork, which at the default `30/hour` rate limit fails partway
    through.

    That limitation is documented rather than papered over, because the fix is
    a playbook pattern rather than a library trick: resolve once with
    `run_once: true` and register the result. The README leads with it.
    """

    def __init__(self):
        self._reveals = {}
        self._resolutions = {}

    def reveal(self, key, produce):
        if key not in self._reveals:
            self._reveals[key] = produce()
        return self._reveals[key]

    def resolve(self, key, produce):
        if key not in self._resolutions:
            self._resolutions[key] = produce()
        return self._resolutions[key]


class OpenBaoClient:
    """Reads credentials from a NetBox running `netbox-openbao`."""

    def __init__(self, url=None, token=None, validate_certs=True, ca_path=None,
                 timeout=DEFAULT_TIMEOUT, cache=None, warn=None):
        self.url = self._resolve_url(url)
        self.token = self._resolve_token(token)
        self.validate_certs = validate_certs
        self.ca_path = ca_path or os.environ.get('NETBOX_CA_BUNDLE') or None
        self.timeout = timeout
        self.cache = cache if cache is not None else ResolverCache()
        self._warn = warn or (lambda message: None)

        if not self.validate_certs:
            # Loud on purpose. Every request this client makes carries an API
            # token able to reveal secrets, and every response carries the
            # material itself. Turning verification off makes both readable to
            # anyone positioned on the path.
            self._warn(
                'netbox-openbao: TLS certificate verification is DISABLED. The API token and the '
                'revealed secret material are exposed to anyone able to intercept this connection. '
                'For an internal CA, set ca_path (or NETBOX_CA_BUNDLE) instead — that verifies '
                'properly rather than not at all.'
            )

    # -- configuration --------------------------------------------------

    @staticmethod
    def _resolve_url(url):
        candidate = url or _first_env(URL_ENV_VARS)
        if not candidate:
            raise OpenBaoLookupError(
                'No NetBox URL. Pass url=, or set one of: {names}.'.format(
                    names=', '.join(URL_ENV_VARS),
                )
            )
        return candidate.rstrip('/')

    @staticmethod
    def _resolve_token(token):
        """
        Resolve the API token.

        A token may be passed explicitly for the sake of testability and of
        deployments that source it from a vault of their own, but the plugin's
        documentation never shows a literal — a token in a playbook is a token
        in version control.
        """
        candidate = token or _first_env(TOKEN_ENV_VARS)
        if not candidate:
            raise OpenBaoLookupError(
                'No NetBox API token. Set one of: {names}. Do not put a token in a playbook.'.format(
                    names=', '.join(TOKEN_ENV_VARS),
                )
            )
        return candidate

    # -- transport ------------------------------------------------------

    def _request(self, path, params=None):
        query = f'?{urllib.parse.urlencode(params, doseq=True)}' if params else ''
        url = f'{self.url}{path}{query}'

        request = urllib.request.Request(url, method='GET')
        request.add_header('Authorization', self._authorization())
        request.add_header('Accept', 'application/json')

        context = self._ssl_context()

        try:
            with urllib.request.urlopen(request, timeout=self.timeout, context=context) as response:
                return json.loads(response.read().decode())
        except urllib.error.HTTPError as exc:
            raise self._translate(exc, url) from None
        except urllib.error.URLError as exc:
            raise OpenBaoLookupError(
                f'Could not reach NetBox at {self.url}: {exc.reason}'
            ) from None

    def _authorization(self):
        """
        Build the Authorization header for whichever token scheme this is.

        NetBox 4.7 issues v2 tokens (`Bearer nbt_<key>.<token>`) and still
        accepts v1 (`Token <token>`), which it is removing. Sending the wrong
        keyword produces a 403 that says nothing useful, so this is decided
        from the token's own shape rather than left to configuration.
        """
        if self.token.startswith(V2_TOKEN_PREFIX):
            return f'Bearer {self.token}'
        return f'Token {self.token}'

    def _ssl_context(self):
        """
        Build the TLS context.

        `ca_path` is the supported answer for an internal CA: it verifies
        against your own root instead of abandoning verification. `validate_certs=False`
        remains available because Ansible modules conventionally offer it and
        someone will need it on a lab box, but it warns loudly (see `__init__`)
        and should never appear in a production playbook.
        """
        import ssl

        if not self.validate_certs:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            return context

        if self.ca_path:
            return ssl.create_default_context(cafile=self.ca_path)

        # Default: the system trust store, hostname checking on.
        return None

    def _translate(self, exc, url):
        """
        Turn an HTTP status into something an operator can act on.

        Every one of these would otherwise surface as an opaque HTTPError, and
        the 429 in particular reads as a plugin bug rather than as a quota.
        """
        status = exc.code

        if status == 429:
            retry_after = exc.headers.get('Retry-After') if exc.headers else None
            wait = f' Retry after {retry_after}s.' if retry_after else ''
            return OpenBaoRateLimited(
                'NetBox refused the reveal: rate limit exceeded (HTTP 429).{wait} '
                'The reveal endpoint is limited per user (netbox-openbao default: 30/hour), and a '
                'play that reveals once per host will exhaust it. Resolve the credential once with '
                '`run_once: true` and register the result, or raise `reveal_rate_limit` in '
                'PLUGINS_CONFIG.'.format(wait=wait)
            )

        if status in (401, 403):
            return OpenBaoAuthError(
                f'NetBox rejected the token (HTTP {status}). Revealing a credential needs both '
                f'`netbox_openbao.view_credential` and `netbox_openbao.reveal_credential`. '
                f'Note that `add_credential` is deliberately not sufficient.'
            )

        if status == 404:
            return OpenBaoNotFound(
                f'Not found (HTTP 404): {url}. If the credential does exist, the token\'s '
                f'object-permission constraints may exclude it — netbox-openbao returns 404 rather '
                f'than 403 so a response cannot confirm that a credential you may not read exists.'
            )

        return OpenBaoLookupError(f'NetBox returned HTTP {status} for {url}.')

    # -- API ------------------------------------------------------------

    def find_credentials(self, *, device=None, virtual_machine=None, service=None,
                         purpose=None, credential_id=None, uuid=None, name=None,
                         credential_type=None):
        """
        Return credential records matching the selectors, most-primary first.

        Selection by assigned object goes through the assignment endpoint,
        because that is where `purpose` and `is_primary` live — the fields that
        make "which credential does this device use to log in?" answerable
        rather than ambiguous.
        """
        if credential_id is not None:
            return [self._get_credential(credential_id)]

        params = {}
        if uuid:
            params['uuid'] = uuid
        if name:
            params['name'] = name
        if credential_type:
            params['credential_type'] = credential_type

        target = _single_target(device=device, virtual_machine=virtual_machine, service=service)
        if target is None:
            if not params:
                raise OpenBaoLookupError(
                    'Nothing to look up. Give a device, virtual_machine, or service, or a '
                    'credential_id, uuid, or name.'
                )
            return self._list('/api/plugins/openbao/credentials/', params)

        kind, value = target
        object_id = self._resolve_object_id(kind, value)
        assignment_params = {
            'assigned_object_type': _OBJECT_TYPES[kind],
            'assigned_object_id': object_id,
        }
        if purpose:
            assignment_params['purpose'] = purpose

        assignments = self._list('/api/plugins/openbao/assignments/', assignment_params)
        if not assignments:
            raise OpenBaoNotFound(
                f'No credential assigned to {kind} "{value}"'
                + (f' for purpose "{purpose}"' if purpose else '')
                + '.'
            )

        # is_primary first: the plugin enforces at most one primary per
        # (object, purpose), which is precisely so this ordering is decisive.
        assignments.sort(key=lambda a: not a.get('is_primary'))
        results = []
        for assignment in assignments:
            credential = assignment.get('credential') or {}
            if credential.get('id') is not None:
                results.append(self._get_credential(credential['id']))
        return results

    def _resolve_object_id(self, kind, value):
        """Accept a name or a numeric id for the assigned object."""
        if isinstance(value, int) or (isinstance(value, str) and value.isdigit()):
            return int(value)

        path, key = _OBJECT_LOOKUPS[kind]
        matches = self._list(path, {key: value})
        if not matches:
            raise OpenBaoNotFound(f'No {kind} named "{value}" in NetBox.')
        if len(matches) > 1:
            raise OpenBaoLookupError(
                f'"{value}" matches {len(matches)} {kind} objects. Use the numeric id instead.'
            )
        return matches[0]['id']

    def _get_credential(self, credential_id):
        return self.cache.resolve(
            ('credential', credential_id),
            lambda: self._request(f'/api/plugins/openbao/credentials/{credential_id}/'),
        )

    def _list(self, path, params):
        params = dict(params or {})
        params.setdefault('limit', 50)
        payload = self._request(path, params)
        return payload.get('results', [])

    def reveal(self, credential_id, reason=None, version=None):
        """
        Return the secret payload for a credential.

        Cached per process — see `ResolverCache` for exactly how far that
        reaches, which is less far than it looks under Ansible's forking.
        """
        params = {}
        if reason:
            params['reason'] = reason
        if version:
            params['version'] = version

        key = ('reveal', credential_id, params.get('version'))
        return self.cache.reveal(
            key,
            lambda: self._request(f'/api/plugins/openbao/credentials/{credential_id}/reveal/', params),
        )


_OBJECT_TYPES = {
    'device': 'dcim.device',
    'virtual_machine': 'virtualization.virtualmachine',
    'service': 'ipam.service',
}

_OBJECT_LOOKUPS = {
    'device': ('/api/dcim/devices/', 'name'),
    'virtual_machine': ('/api/virtualization/virtual-machines/', 'name'),
    'service': ('/api/ipam/services/', 'name'),
}


def _single_target(**candidates):
    """Return the one (kind, value) given, or None. More than one is an error."""
    given = [(kind, value) for kind, value in candidates.items() if value]
    if not given:
        return None
    if len(given) > 1:
        raise OpenBaoLookupError(
            'Give only one of: {names}.'.format(names=', '.join(sorted(candidates))),
        )
    return given[0]


def _first_env(names):
    for name in names:
        value = os.environ.get(name)
        if value:
            return value.strip()
    return None

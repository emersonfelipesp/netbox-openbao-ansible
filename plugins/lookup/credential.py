# -*- coding: utf-8 -*-
# Copyright (c) 2026 Emerson Felipe
# Apache License 2.0 (see LICENSE)

from __future__ import annotations

__metaclass__ = type

DOCUMENTATION = r'''
name: credential
author: Emerson Felipe (@emersonfelipesp)
short_description: Resolve a netbox-openbao credential from NetBox
version_added: "0.1.0"
description:
  - Looks up a credential in NetBox and returns its secret material from OpenBao.
  - >-
    The material is fetched over the NetBox REST API by the control node. The token
    used must hold both C(netbox_openbao.view_credential) and
    C(netbox_openbao.reveal_credential); C(add_credential) is deliberately not sufficient.
  - >-
    B(Every task consuming this result needs C(no_log: true).) A lookup result lands in
    Ansible's output by default, which would put the secret in the play recap, in AWX or
    Tower job output, and in whatever aggregates those logs.
  - >-
    B(Mind the reveal rate limit.) netbox-openbao limits reveals per user, by default
    30/hour. A lookup written inline on a task that runs against many hosts will exhaust
    it partway through. Resolve once with C(run_once: true) and register the result.
options:
  _terms:
    description:
      - Optional credential name to match. Equivalent to passing I(name).
    type: list
    elements: str
    required: false
  device:
    description: Name or numeric ID of a device the credential is assigned to.
    type: str
  virtual_machine:
    description: Name or numeric ID of a virtual machine the credential is assigned to.
    type: str
  service:
    description: Name or numeric ID of an application service the credential is assigned to.
    type: str
  purpose:
    description:
      - Narrow the assignment by purpose, for example C(login), C(enable), or C(oob).
    type: str
  credential_id:
    description: Resolve a credential directly by its numeric ID.
    type: int
  uuid:
    description: Resolve a credential directly by its immutable UUID.
    type: str
  name:
    description: Match a credential by name.
    type: str
  credential_type:
    description: Narrow results by credential type, for example C(ssh-keypair).
    type: str
  reason:
    description:
      - Justification recorded in the credential access log.
      - Required when the credential's policy sets C(require_reason).
    type: str
  version:
    description:
      - Read a specific KV version rather than the one currently in service.
      - Leave unset unless you are deliberately reading a superseded version.
    type: int
  field:
    description:
      - Return only this field of the payload, for example C(private_key).
      - When unset, the whole payload is returned as a dictionary.
    type: str
  url:
    description: Base URL of NetBox. Falls back to C(NETBOX_OPENBAO_URL), C(NETBOX_URL), then C(NETBOX_API).
    type: str
    env:
      - name: NETBOX_OPENBAO_URL
      - name: NETBOX_URL
  token:
    description:
      - NetBox API token.
      - >-
        Prefer the environment. A token written into a playbook is a token in version
        control; none of the examples below show one.
    type: str
    env:
      - name: NETBOX_OPENBAO_TOKEN
      - name: NETBOX_TOKEN
  validate_certs:
    description:
      - Whether to verify the NetBox TLS certificate.
      - >-
        Leave enabled. Both the API token and the returned material are exposed to anyone
        on the path when this is off. For an internal CA use I(ca_path) instead, which
        verifies properly rather than not at all.
    type: bool
    default: true
  ca_path:
    description: Path to a CA bundle used to verify the NetBox certificate.
    type: str
    env:
      - name: NETBOX_CA_BUNDLE
  timeout:
    description: HTTP timeout in seconds.
    type: int
    default: 30
'''

EXAMPLES = r'''
# Resolve once, then reuse. This is the pattern to copy: it costs one reveal for
# the whole play rather than one per host, which matters because the reveal
# endpoint is rate limited per user.
- name: Resolve the switch login credential
  ansible.builtin.set_fact:
    switch_login: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                             device=inventory_hostname, purpose='login') }}"
  run_once: true
  delegate_to: localhost
  no_log: true

- name: Use it
  ansible.builtin.debug:
    msg: "Connecting as {{ switch_login.username }}"
  no_log: true

# Return a single field rather than the whole payload.
- name: Fetch just the private key
  ansible.builtin.set_fact:
    deploy_key: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                           device='core-sw-01', purpose='login', field='private_key') }}"
  no_log: true

# A policy that requires a justification.
- name: Read a production credential
  ansible.builtin.set_fact:
    prod: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                     credential_id=142, reason='CHG-1234') }}"
  no_log: true

# Direct resolution by UUID, which never changes even if the credential is
# renamed or reassigned.
- name: Resolve by UUID
  ansible.builtin.set_fact:
    cred: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                     uuid='0d2f8f6e-1c4b-4a3f-9b2e-8a1d5c7e4b90') }}"
  no_log: true
'''

RETURN = r'''
_raw:
  description:
    - The secret payload as a dictionary, or the single value when I(field) is given.
    - >-
      The dictionary also carries the credential's non-secret identity — C(id), C(uuid),
      C(name), C(username), C(credential_type), and C(ttl) — so a play can use the
      username without a second lookup.
  type: list
  elements: raw
'''

from ansible.errors import AnsibleLookupError  # noqa: E402
from ansible.plugins.lookup import LookupBase  # noqa: E402
from ansible.utils.display import Display  # noqa: E402
from ansible_collections.emersonfelipesp.netbox_openbao.plugins.module_utils.openbao import (  # noqa: E402
    OpenBaoClient,
    OpenBaoLookupError,
    ResolverCache,
)

display = Display()

# Shared for the lifetime of this process. Ansible forks for host execution, so
# each worker gets its own — see ResolverCache for why that is documented
# rather than worked around.
_CACHE = ResolverCache()


class LookupModule(LookupBase):

    def run(self, terms, variables=None, **kwargs):
        self.set_options(var_options=variables, direct=kwargs)

        name = self.get_option('name')
        if not name and terms:
            name = terms[0]

        try:
            client = OpenBaoClient(
                url=self.get_option('url'),
                token=self.get_option('token'),
                validate_certs=self.get_option('validate_certs'),
                ca_path=self.get_option('ca_path'),
                timeout=self.get_option('timeout'),
                cache=_CACHE,
                warn=display.warning,
            )

            credentials = client.find_credentials(
                device=self.get_option('device'),
                virtual_machine=self.get_option('virtual_machine'),
                service=self.get_option('service'),
                purpose=self.get_option('purpose'),
                credential_id=self.get_option('credential_id'),
                uuid=self.get_option('uuid'),
                name=name,
                credential_type=self.get_option('credential_type'),
            )

            if not credentials:
                raise AnsibleLookupError('No credential matched.')

            credential = self._choose(credentials)
            payload = client.reveal(
                credential['id'],
                reason=self.get_option('reason'),
                version=self.get_option('version'),
            )
        except OpenBaoLookupError as exc:
            # These carry operator-facing guidance already; wrapping them in a
            # generic message would throw that away.
            raise AnsibleLookupError(str(exc)) from None

        result = dict(payload.get('secret_data') or {})
        # Non-secret identity alongside the material, so a play can use the
        # username without paying for a second lookup.
        for key in ('id', 'uuid', 'name', 'username', 'credential_type', 'kv_version', 'ttl'):
            if key in payload:
                result.setdefault(key, payload[key])

        field = self.get_option('field')
        if field:
            if field not in result:
                available = ', '.join(sorted(k for k in result if k not in ('id', 'uuid')))
                raise AnsibleLookupError(
                    f'Credential {credential["id"]} has no field "{field}". Available: {available}.'
                )
            return [result[field]]

        return [result]

    @staticmethod
    def _choose(credentials):
        """
        Pick one credential, or refuse to guess.

        `find_credentials` already sorts primary assignments first, so more than
        one result here means several matched and none was marked primary —
        which is genuinely ambiguous. Silently taking the first would make a
        play's behaviour depend on database ordering.
        """
        if len(credentials) == 1:
            return credentials[0]

        names = ', '.join(f'{c["name"]} (id {c["id"]})' for c in credentials[:5])
        raise AnsibleLookupError(
            f'{len(credentials)} credentials matched and none is marked primary: {names}. '
            f'Narrow the lookup with purpose= or credential_type=, or mark one assignment '
            f'as primary in NetBox.'
        )

# -*- coding: utf-8 -*-
"""
Client behaviour, against a stubbed API.

Weighted toward the error paths. A lookup that works is easy to notice; a
lookup that fails unhelpfully at 3am against 200 hosts is the thing that
actually costs someone an afternoon, and the 429 in particular reads as a
plugin bug unless the message says otherwise.
"""

import os
import sys
import urllib.error

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from plugins.module_utils.openbao import (  # noqa: E402
    OpenBaoAuthError,
    OpenBaoClient,
    OpenBaoLookupError,
    OpenBaoNotFound,
    OpenBaoRateLimited,
    ResolverCache,
    _object_pk,
)

BASE = 'https://netbox.example.net'
TOKEN = 'test-token'


class StubClient(OpenBaoClient):
    """An OpenBaoClient whose transport is a scripted dict of responses."""

    def __init__(self, responses, **kwargs):
        kwargs.setdefault('url', BASE)
        kwargs.setdefault('token', TOKEN)
        super().__init__(**kwargs)
        self.responses = responses
        self.calls = []

    def _request(self, path, params=None):
        self.calls.append((path, dict(params or {})))
        try:
            value = self.responses[path]
        except KeyError:
            raise AssertionError(f'unexpected request: {path} {params}') from None
        if isinstance(value, Exception):
            raise value
        return value


def http_error(status, headers=None):
    return urllib.error.HTTPError(
        url=f'{BASE}/x', code=status, msg='err', hdrs=headers or {}, fp=None,
    )


class TestConfiguration:

    def test_url_and_token_come_from_the_environment(self, monkeypatch):
        monkeypatch.setenv('NETBOX_URL', 'https://nb.example.net/')
        monkeypatch.setenv('NETBOX_TOKEN', 'from-env')

        client = OpenBaoClient()
        assert client.url == 'https://nb.example.net'
        assert client.token == 'from-env'

    def test_openbao_specific_vars_win(self, monkeypatch):
        monkeypatch.setenv('NETBOX_URL', 'https://generic.example.net')
        monkeypatch.setenv('NETBOX_OPENBAO_URL', 'https://specific.example.net')
        monkeypatch.setenv('NETBOX_TOKEN', 'generic')
        monkeypatch.setenv('NETBOX_OPENBAO_TOKEN', 'specific')

        client = OpenBaoClient()
        assert client.url == 'https://specific.example.net'
        assert client.token == 'specific'

    def test_a_missing_token_says_not_to_put_one_in_a_playbook(self, monkeypatch):
        for name in ('NETBOX_OPENBAO_TOKEN', 'NETBOX_TOKEN'):
            monkeypatch.delenv(name, raising=False)

        with pytest.raises(OpenBaoLookupError) as exc:
            OpenBaoClient(url=BASE)
        assert 'do not put a token in a playbook' in str(exc.value).lower()

    def test_disabling_verification_warns_loudly(self):
        warnings = []
        OpenBaoClient(url=BASE, token=TOKEN, validate_certs=False, warn=warnings.append)

        assert len(warnings) == 1
        message = warnings[0].lower()
        assert 'disabled' in message
        # It must name what is exposed, not just that something is off.
        assert 'token' in message and 'material' in message
        # ...and point at the correct fix.
        assert 'ca_path' in message

    def test_verification_on_by_default_does_not_warn(self):
        warnings = []
        OpenBaoClient(url=BASE, token=TOKEN, warn=warnings.append)
        assert warnings == []


class TestTokenScheme:
    """
    NetBox 4.7 issues v2 tokens and still accepts v1. Sending the wrong keyword
    produces a 403 that explains nothing, so the scheme is decided from the
    token's own shape.
    """

    def test_a_v2_token_uses_bearer(self):
        client = OpenBaoClient(url=BASE, token='nbt_abc123.deadbeef')
        assert client._authorization() == 'Bearer nbt_abc123.deadbeef'

    def test_a_legacy_token_uses_token(self):
        client = OpenBaoClient(url=BASE, token='0123456789abcdef0123456789abcdef01234567')
        assert client._authorization() == 'Token 0123456789abcdef0123456789abcdef01234567'


class TestErrorTranslation:
    """
    Each of these would otherwise surface as an opaque HTTPError.

    Exercised through the real `_request`, with only the socket stubbed, so the
    translation is tested where it actually runs rather than in isolation.
    """

    def _client(self, error, monkeypatch):
        def boom(*args, **kwargs):
            raise error

        monkeypatch.setattr('urllib.request.urlopen', boom)
        return OpenBaoClient(url=BASE, token=TOKEN)

    def test_rate_limit_explains_the_quota_and_the_fix(self, monkeypatch):
        client = self._client(http_error(429), monkeypatch)

        with pytest.raises(OpenBaoRateLimited) as exc:
            client._get_credential(1)

        message = str(exc.value)
        assert '429' in message
        assert '30/hour' in message
        # The actionable part: the playbook pattern that avoids it.
        assert 'run_once' in message

    def test_rate_limit_surfaces_retry_after(self, monkeypatch):
        client = self._client(http_error(429, headers={'Retry-After': '120'}), monkeypatch)

        with pytest.raises(OpenBaoRateLimited) as exc:
            client._get_credential(1)
        assert '120' in str(exc.value)

    def test_an_unreachable_host_names_the_url(self, monkeypatch):
        def boom(*args, **kwargs):
            raise urllib.error.URLError('Name or service not known')

        monkeypatch.setattr('urllib.request.urlopen', boom)
        client = OpenBaoClient(url=BASE, token=TOKEN)

        with pytest.raises(OpenBaoLookupError) as exc:
            client._get_credential(1)
        assert BASE in str(exc.value)

    def test_forbidden_names_the_permissions_needed(self, monkeypatch):
        client = self._client(http_error(403), monkeypatch)

        with pytest.raises(OpenBaoAuthError) as exc:
            client._get_credential(1)

        message = str(exc.value)
        assert 'reveal_credential' in message
        # The distinction that only recently became real upstream.
        assert 'add_credential' in message

    def test_not_found_explains_the_404_that_is_really_a_403(self, monkeypatch):
        client = self._client(http_error(404), monkeypatch)

        with pytest.raises(OpenBaoNotFound) as exc:
            client._get_credential(1)
        assert 'constraint' in str(exc.value).lower()

    def test_other_statuses_are_still_reported(self, monkeypatch):
        client = self._client(http_error(500), monkeypatch)

        with pytest.raises(OpenBaoLookupError) as exc:
            client._get_credential(1)
        assert '500' in str(exc.value)


class TestResolution:

    def _client(self, **overrides):
        responses = {
            '/api/dcim/devices/': {'results': [{'id': 88, 'name': 'core-sw-01'}]},
            '/api/plugins/openbao/assignments/': {'results': [
                {'id': 1, 'is_primary': False, 'purpose': 'login',
                 'credential': {'id': 11, 'name': 'secondary'}},
                {'id': 2, 'is_primary': True, 'purpose': 'login',
                 'credential': {'id': 22, 'name': 'primary'}},
            ]},
            '/api/plugins/openbao/credentials/11/': {'id': 11, 'name': 'secondary'},
            '/api/plugins/openbao/credentials/22/': {'id': 22, 'name': 'primary'},
        }
        responses.update(overrides)
        return StubClient(responses)

    def test_primary_assignment_is_returned_first(self):
        """
        The plugin enforces at most one primary per (object, purpose) precisely
        so this ordering is decisive rather than arbitrary.
        """
        client = self._client()
        results = client.find_credentials(device='core-sw-01', purpose='login')

        assert [c['id'] for c in results] == [22, 11]

    def test_device_name_is_resolved_to_an_id(self):
        client = self._client()
        client.find_credentials(device='core-sw-01', purpose='login')

        assignment_call = next(
            params for path, params in client.calls
            if path == '/api/plugins/openbao/assignments/'
        )
        assert assignment_call['assigned_object_type'] == 'dcim.device'
        assert assignment_call['assigned_object_id'] == 88

    def test_a_numeric_device_skips_the_name_lookup(self):
        client = self._client()
        client.find_credentials(device='88', purpose='login')

        assert not any(path == '/api/dcim/devices/' for path, _ in client.calls)

    def test_purpose_is_passed_through(self):
        client = self._client()
        client.find_credentials(device='core-sw-01', purpose='enable')

        assignment_call = next(
            params for path, params in client.calls
            if path == '/api/plugins/openbao/assignments/'
        )
        assert assignment_call['purpose'] == 'enable'

    def test_no_assignment_is_an_actionable_error(self):
        client = self._client(**{'/api/plugins/openbao/assignments/': {'results': []}})

        with pytest.raises(OpenBaoNotFound) as exc:
            client.find_credentials(device='core-sw-01', purpose='login')

        message = str(exc.value)
        assert 'core-sw-01' in message and 'login' in message

    def test_an_ambiguous_device_name_refuses_to_guess(self):
        client = self._client(**{'/api/dcim/devices/': {'results': [
            {'id': 1, 'name': 'sw'}, {'id': 2, 'name': 'sw'},
        ]}})

        with pytest.raises(OpenBaoLookupError) as exc:
            client.find_credentials(device='sw')
        assert 'numeric id' in str(exc.value)

    def test_two_targets_is_an_error(self):
        client = self._client()

        with pytest.raises(OpenBaoLookupError):
            client.find_credentials(device='core-sw-01', virtual_machine='vm-01')

    def test_no_selectors_at_all_is_an_error(self):
        client = self._client()

        with pytest.raises(OpenBaoLookupError) as exc:
            client.find_credentials()
        assert 'nothing to look up' in str(exc.value).lower()


class TestCaching:
    """
    The reveal endpoint is rate limited per user. Repeated resolution inside
    one process must not cost repeated calls.
    """

    def test_a_repeated_reveal_hits_the_api_once(self):
        client = StubClient({
            '/api/plugins/openbao/credentials/1/reveal/': {
                'id': 1, 'secret_data': {'password': 'hunter2'},
            },
        })

        first = client.reveal(1)
        second = client.reveal(1)

        assert first == second
        assert len(client.calls) == 1

    def test_a_different_version_is_a_different_cache_entry(self):
        client = StubClient({
            '/api/plugins/openbao/credentials/1/reveal/': {
                'id': 1, 'secret_data': {'password': 'x'},
            },
        })

        client.reveal(1)
        client.reveal(1, version=2)

        assert len(client.calls) == 2

    def test_the_cache_can_be_shared_between_clients(self):
        """
        The lookup plugin passes one process-wide cache into every client it
        builds, which is what makes repeated lookups in a play cheap.
        """
        cache = ResolverCache()
        responses = {
            '/api/plugins/openbao/credentials/1/reveal/': {
                'id': 1, 'secret_data': {'password': 'hunter2'},
            },
        }
        first = StubClient(responses, cache=cache)
        second = StubClient(responses, cache=cache)

        first.reveal(1)
        second.reveal(1)

        assert len(second.calls) == 0


class TestGenericObjectSelector:
    """
    The escape hatch for object types this collection has never heard of.

    netbox-openbao's assignable-model allowlist is operator-configurable and can
    also be extended by an installed plugin, so the three friendly selectors
    cannot be exhaustive without a collection release per integration. These
    tests pin the pair's validation, because every one of these failures would
    otherwise surface as an empty result set that reads as "no credential
    assigned" — which sends an operator looking in entirely the wrong place.
    """

    ENDPOINT = 'netbox_proxbox.proxmoxendpoint'

    def _client(self, **overrides):
        responses = {
            '/api/plugins/openbao/assignments/': {'results': [
                {'id': 3, 'is_primary': True, 'purpose': 'api',
                 'credential': {'id': 33, 'name': 'proxmox api token'}},
            ]},
            '/api/plugins/openbao/credentials/33/': {'id': 33, 'name': 'proxmox api token'},
        }
        responses.update(overrides)
        return StubClient(responses)

    def test_a_plugin_owned_type_resolves(self):
        client = self._client()
        results = client.find_credentials(
            assigned_object_type=self.ENDPOINT, assigned_object_id=3, purpose='api',
        )

        assert [c['id'] for c in results] == [33]
        params = next(
            p for path, p in client.calls
            if path == '/api/plugins/openbao/assignments/'
        )
        assert params['assigned_object_type'] == self.ENDPOINT
        assert params['assigned_object_id'] == 3
        assert params['purpose'] == 'api'

    def test_no_name_lookup_is_attempted(self):
        """
        This collection cannot know the model's natural key, so it must not
        guess `name` — the StubClient would raise on the unexpected request.
        """
        client = self._client()
        client.find_credentials(assigned_object_type=self.ENDPOINT, assigned_object_id=3)

        assert [path for path, _ in client.calls] == [
            '/api/plugins/openbao/assignments/',
            '/api/plugins/openbao/credentials/33/',
        ]

    def test_a_digit_string_id_is_accepted_and_normalized(self):
        client = self._client()
        client.find_credentials(assigned_object_type=self.ENDPOINT, assigned_object_id='3')

        params = next(
            p for path, p in client.calls
            if path == '/api/plugins/openbao/assignments/'
        )
        assert params['assigned_object_id'] == 3

    @pytest.mark.parametrize('bad_id', [1.9, 3.0, True, False, ' 3 ', '3 ', '0x3', '3.0'])
    def test_ids_that_int_would_silently_accept_are_refused(self, bad_id):
        """
        `int()` is the wrong coercion here, and wrong in a way that does not
        error: `int(1.9)` is 1 and `int(True)` is 1, so a templated value that
        arrived as a float or a boolean would query a *different* object and
        reveal its credential. Every one of these must fail before any request.
        """
        client = self._client()
        with pytest.raises(OpenBaoLookupError):
            client.find_credentials(assigned_object_type=self.ENDPOINT, assigned_object_id=bad_id)

        assert client.calls == []

    @pytest.mark.parametrize('bad_id', [0, -1, '0'])
    def test_non_positive_ids_are_refused(self, bad_id):
        """No NetBox primary key is zero or negative, so this is a play bug."""
        client = self._client()
        with pytest.raises(OpenBaoLookupError):
            client.find_credentials(assigned_object_type=self.ENDPOINT, assigned_object_id=bad_id)

        assert client.calls == []

    def test_a_leading_underscore_app_label_is_accepted(self):
        """
        Django only requires an app label to be a valid Python identifier, so
        `_internal.thing` is legal. Refusing it would reject a plugin that had
        done nothing wrong.
        """
        client = StubClient({
            '/api/plugins/openbao/assignments/': {'results': [
                {'id': 4, 'is_primary': True, 'credential': {'id': 44}},
            ]},
            '/api/plugins/openbao/credentials/44/': {'id': 44},
        })
        client.find_credentials(assigned_object_type='_internal.thing', assigned_object_id=1)

        params = next(
            p for path, p in client.calls
            if path == '/api/plugins/openbao/assignments/'
        )
        assert params['assigned_object_type'] == '_internal.thing'

    def test_the_label_is_lowercased(self):
        client = self._client()
        client.find_credentials(
            assigned_object_type='NetBox_Proxbox.ProxmoxEndpoint', assigned_object_id=3,
        )

        params = next(
            p for path, p in client.calls
            if path == '/api/plugins/openbao/assignments/'
        )
        assert params['assigned_object_type'] == self.ENDPOINT

    def test_type_without_id_is_refused(self):
        client = self._client()
        with pytest.raises(OpenBaoLookupError) as exc:
            client.find_credentials(assigned_object_type=self.ENDPOINT)
        assert 'assigned_object_id' in str(exc.value)

    def test_id_without_type_is_refused(self):
        client = self._client()
        with pytest.raises(OpenBaoLookupError) as exc:
            client.find_credentials(assigned_object_id=3)
        assert 'assigned_object_type' in str(exc.value)

    def test_a_malformed_label_is_refused_before_any_request(self):
        client = self._client()
        with pytest.raises(OpenBaoLookupError) as exc:
            client.find_credentials(assigned_object_type='proxmoxendpoint', assigned_object_id=3)

        assert 'app_label.model' in str(exc.value)
        assert client.calls == []

    def test_a_non_numeric_id_is_refused_before_any_request(self):
        client = self._client()
        with pytest.raises(OpenBaoLookupError) as exc:
            client.find_credentials(
                assigned_object_type=self.ENDPOINT, assigned_object_id='core-sw-01',
            )

        assert 'positive integer' in str(exc.value)
        assert client.calls == []

    def test_combining_with_a_named_selector_is_refused(self):
        """
        Two selectors that disagree have no correct answer, so this is an error
        rather than a precedence rule nobody wrote down.
        """
        client = self._client()
        with pytest.raises(OpenBaoLookupError) as exc:
            client.find_credentials(
                device='core-sw-01',
                assigned_object_type=self.ENDPOINT,
                assigned_object_id=3,
            )

        message = str(exc.value)
        assert 'device' in message and 'assigned_object' in message

    def test_neither_half_leaves_the_other_selectors_working(self):
        """Passing neither must not be mistaken for passing one."""
        client = StubClient({'/api/plugins/openbao/credentials/': {'results': [{'id': 9}]}})
        results = client.find_credentials(name='some credential')

        assert [c['id'] for c in results] == [9]

    def test_missing_assignment_names_the_allowlist_as_a_cause(self):
        """
        An allowlist that rejects the content type produces an empty result set
        that is indistinguishable from "this object has no credential". Saying
        so is the difference between a five-minute fix and an afternoon.
        """
        client = self._client(**{'/api/plugins/openbao/assignments/': {'results': []}})

        with pytest.raises(OpenBaoNotFound) as exc:
            client.find_credentials(
                assigned_object_type=self.ENDPOINT, assigned_object_id=3, purpose='api',
            )

        message = str(exc.value)
        assert self.ENDPOINT in message
        assert 'allowlist' in message


class TestLookupOptionTypes:
    """
    The declared option type is part of the validation, not decoration.

    Ansible coerces an option to its declared type **before** the plugin sees
    the value, so a strict check inside the client is unreachable if the
    declaration has already destroyed the evidence. Declaring
    `assigned_object_id` as `int` did exactly that: `True` arrived as `1` and
    `3.0` arrived as `3`, both of which `_object_pk()` then accepted as
    perfectly ordinary primary keys — and the play got a different object's
    credential.

    Round 1's fix passed every direct-client test and was defeated in the only
    path that ships. These tests close that gap from both ends: the declaration
    itself, and the coercion behaviour that makes it matter.
    """

    @staticmethod
    def _documented_options():
        import yaml

        path = os.path.join(
            os.path.dirname(__file__), '..', '..', 'plugins', 'lookup', 'credential.py',
        )
        namespace = {}
        exec(  # noqa: S102 - reading the plugin's own DOCUMENTATION constant
            compile(
                ''.join(
                    line for line in open(path)
                    if not line.startswith(('from ', 'import '))
                ).split("EXAMPLES = r'''")[0],
                path, 'exec',
            ),
            namespace,
        )
        return yaml.safe_load(namespace['DOCUMENTATION'])['options']

    def test_assigned_object_id_is_declared_str(self):
        """
        Not `int`. Changing it back re-opens the hole silently, because every
        client-level test would still pass.
        """
        assert self._documented_options()['assigned_object_id']['type'] == 'str'

    def test_assigned_object_type_is_declared_str(self):
        assert self._documented_options()['assigned_object_type']['type'] == 'str'

    @pytest.mark.parametrize(
        'hostile',
        [True, 3.0, ' 3 '],
        ids=['bool', 'float', 'padded'],
    )
    def test_int_coercion_would_destroy_the_evidence(self, hostile):
        """
        Why the declaration matters, proven against Ansible rather than assumed.

        Under `type: int` each of these becomes a plain, plausible integer.
        Under `type: str` it survives in a form `_object_pk()` refuses.
        """
        ensure_type = pytest.importorskip('ansible.config.manager').ensure_type

        as_int = ensure_type(hostile, 'int')
        assert isinstance(as_int, int) and not isinstance(as_int, bool)

        as_str = ensure_type(hostile, 'str')
        with pytest.raises(OpenBaoLookupError):
            _object_pk(as_str)

    @pytest.mark.parametrize('value', ['²', '٣', '3​'])
    def test_non_ascii_digits_are_refused(self, value):
        """
        `str.isdigit()` is true for all three and `int()` disagrees with itself
        about them — it accepts Arabic-Indic digits and raises a bare
        `ValueError` on a superscript. Requiring ASCII removes the question, and
        no NetBox primary key arrives any other way.
        """
        with pytest.raises(OpenBaoLookupError):
            _object_pk(value)


class TestFiltersAreNotSilentlyDropped:
    """
    A filter that is accepted and ignored hands back the wrong secret.

    `uuid`, `name`, and `credential_type` were collected into query parameters
    for the credentials endpoint — which the assignment path never calls. So a
    play written as a safety constraint got whatever credential was primary for
    the object and purpose, with no error and nothing to notice. Returning the
    wrong secret is the worst way for a lookup to fail.
    """

    def _client(self):
        return StubClient({
            '/api/dcim/devices/': {'results': [{'id': 88, 'name': 'core-sw-01'}]},
            '/api/plugins/openbao/assignments/': {'results': [
                {'id': 1, 'is_primary': True, 'purpose': 'login',
                 'credential': {'id': 11}},
                {'id': 2, 'is_primary': False, 'purpose': 'login',
                 'credential': {'id': 22}},
            ]},
            '/api/plugins/openbao/credentials/11/': {
                'id': 11, 'name': 'switch password', 'credential_type': 'password',
                'uuid': 'aaaa-1111',
            },
            '/api/plugins/openbao/credentials/22/': {
                'id': 22, 'name': 'switch key', 'credential_type': 'ssh-keypair',
                'uuid': 'bbbb-2222',
            },
        })

    def test_credential_type_narrows_an_assignment_lookup(self):
        """
        The regression. Without the filter this returns credential 11 first —
        the primary, a password — for a play that asked for a key.
        """
        client = self._client()
        results = client.find_credentials(
            device='core-sw-01', purpose='login', credential_type='ssh-keypair',
        )

        assert [c['id'] for c in results] == [22]

    def test_uuid_narrows_an_assignment_lookup(self):
        client = self._client()
        results = client.find_credentials(device='core-sw-01', uuid='bbbb-2222')

        assert [c['id'] for c in results] == [22]

    def test_name_narrows_an_assignment_lookup(self):
        client = self._client()
        results = client.find_credentials(device='core-sw-01', name='switch key')

        assert [c['id'] for c in results] == [22]

    def test_the_same_filter_works_through_the_generic_selector(self):
        client = self._client()
        results = client.find_credentials(
            assigned_object_type='netbox_proxbox.proxmoxendpoint',
            assigned_object_id=3,
            credential_type='ssh-keypair',
        )

        assert [c['id'] for c in results] == [22]

    def test_a_filter_matching_nothing_is_an_error_not_an_empty_list(self):
        """
        The caller stated a constraint and nothing satisfied it. That is exactly
        the case they wrote the constraint to catch, so it must not return the
        unfiltered set and must not return nothing quietly.
        """
        client = self._client()
        with pytest.raises(OpenBaoNotFound) as exc:
            client.find_credentials(
                device='core-sw-01', purpose='login', credential_type='x509-keypair',
            )

        message = str(exc.value)
        assert 'x509-keypair' in message
        assert 'ssh-keypair' in message and 'password' in message

    def test_no_filter_returns_every_assignment_primary_first(self):
        """The unfiltered path is unchanged: this is a narrowing, not a rewrite."""
        client = self._client()
        results = client.find_credentials(device='core-sw-01', purpose='login')

        assert [c['id'] for c in results] == [11, 22]

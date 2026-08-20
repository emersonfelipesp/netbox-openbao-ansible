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

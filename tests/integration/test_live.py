# -*- coding: utf-8 -*-
"""
Against a live NetBox running netbox-openbao.

Skipped unless `NETBOX_OPENBAO_TEST_URL` and `NETBOX_OPENBAO_TEST_TOKEN` are
set, so the suite still runs anywhere.

Worth having despite the unit tests: the only bug these caught that a stub
could not was in `netbox-openbao` itself — creating a credential failed against
a real OpenBao because the plugin sent an empty `custom_metadata` value, which
its own fake backend had happily accepted. Stubs agree with whatever you
believe; servers do not.

The token used here should hold `view_credential` and `reveal_credential` and
**not** `add_credential`, which is what proves the README's permission claim
rather than merely asserting it.
"""

import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..'))

from plugins.module_utils.openbao import (  # noqa: E402
    OpenBaoClient,
    OpenBaoLookupError,
    OpenBaoNotFound,
)

URL = os.environ.get('NETBOX_OPENBAO_TEST_URL')
TOKEN = os.environ.get('NETBOX_OPENBAO_TEST_TOKEN')
DEVICE = os.environ.get('NETBOX_OPENBAO_TEST_DEVICE', 'core-sw-01')

pytestmark = pytest.mark.skipif(
    not (URL and TOKEN),
    reason='Set NETBOX_OPENBAO_TEST_URL and NETBOX_OPENBAO_TEST_TOKEN to run live tests',
)


@pytest.fixture
def client():
    return OpenBaoClient(url=URL, token=TOKEN)


class TestLiveResolution:

    def test_resolve_by_device_and_purpose(self, client):
        credentials = client.find_credentials(device=DEVICE, purpose='login')

        assert credentials
        assert credentials[0]['id']

    def test_reveal_returns_material(self, client):
        credential = client.find_credentials(device=DEVICE, purpose='login')[0]
        payload = client.reveal(credential['id'])

        assert payload['secret_data']
        # The non-secret identity travels with it, so a play does not need a
        # second call to learn the username.
        assert payload['id'] == credential['id']
        assert 'ttl' in payload

    def test_resolve_by_uuid(self, client):
        credential = client.find_credentials(device=DEVICE, purpose='login')[0]
        by_uuid = client.find_credentials(uuid=credential['uuid'])

        assert by_uuid[0]['id'] == credential['id']

    def test_a_missing_device_says_which_one(self, client):
        with pytest.raises(OpenBaoNotFound) as exc:
            client.find_credentials(device='definitely-not-a-real-device')
        assert 'definitely-not-a-real-device' in str(exc.value)

    def test_reveals_are_cached_within_a_client(self, client):
        credential = client.find_credentials(device=DEVICE, purpose='login')[0]

        first = client.reveal(credential['id'])
        second = client.reveal(credential['id'])

        # Same object, not merely equal: the second call never left the process.
        assert first is second

    def test_a_bad_token_is_an_auth_error_naming_the_permissions(self):
        """
        A rejected token is the single most common first-run failure, so the
        message has to say what the token needs rather than just "403".
        """
        broken = OpenBaoClient(url=URL, token='nbt_bogus.bogus')

        with pytest.raises(OpenBaoLookupError) as exc:
            broken.find_credentials(device=DEVICE)

        message = str(exc.value)
        assert 'reveal_credential' in message
        assert 'add_credential' in message


class TestLivePlugin:
    """
    Drive the lookup through Ansible itself.

    The client tests above exercise the logic; this one proves the plugin is
    actually loadable and wired into the collection namespace, which is a
    separate way to be broken and one no unit test notices.
    """

    def _ansible(self, expression):
        collections = os.environ.get('ANSIBLE_COLLECTIONS_PATH')
        if not collections:
            pytest.skip('Set ANSIBLE_COLLECTIONS_PATH to run the plugin-level tests')

        env = dict(os.environ)
        env.update({
            'NETBOX_URL': URL,
            'NETBOX_TOKEN': TOKEN,
            'ANSIBLE_LOCALHOST_WARNING': 'False',
            'ANSIBLE_INVENTORY_UNPARSED_WARNING': 'False',
        })
        return subprocess.run(
            ['ansible', 'localhost', '-c', 'local', '-m', 'debug', '-a', f'msg={expression}'],
            capture_output=True, text=True, env=env, timeout=120,
        )

    def test_lookup_resolves_through_ansible(self):
        result = self._ansible(
            "{{ lookup('emersonfelipesp.netbox_openbao.credential', "
            f"device='{DEVICE}', purpose='login', field='username') }}}}"
        )
        assert result.returncode == 0, result.stdout + result.stderr
        assert 'SUCCESS' in result.stdout

    def test_documentation_parses(self):
        """A malformed DOCUMENTATION block only fails at load time."""
        collections = os.environ.get('ANSIBLE_COLLECTIONS_PATH')
        if not collections:
            pytest.skip('Set ANSIBLE_COLLECTIONS_PATH')

        result = subprocess.run(
            ['ansible-doc', '-t', 'lookup', 'emersonfelipesp.netbox_openbao.credential'],
            capture_output=True, text=True, env=dict(os.environ), timeout=120,
        )
        assert result.returncode == 0, result.stderr
        # The two warnings that must be impossible to miss.
        assert 'no_log' in result.stdout
        assert 'rate limit' in result.stdout.lower()

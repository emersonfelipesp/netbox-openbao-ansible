# netbox-openbao-ansible

Resolve [`netbox-openbao`](https://git.nmulti.cloud/emersonfelipesp/netbox-openbao)
credentials from NetBox at play time. The material stays in OpenBao; NetBox
authorizes and audits every read.

```yaml
- name: Resolve the switch login
  ansible.builtin.set_fact:
    switch_login: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                             device=inventory_hostname, purpose='login') }}"
  run_once: true
  delegate_to: localhost
  no_log: true
```

---

## Read this first: `no_log: true`

**Every task that consumes a lookup result needs `no_log: true`.**

A lookup result lands in Ansible's output by default. Without `no_log`, the
secret ends up in the play recap, in AWX or Tower job output, and in whatever
aggregates those logs — which would undo the entire point of keeping it in
OpenBao. This is the single most likely way to get this wrong, and Ansible will
not warn you.

```yaml
- name: Correct
  ansible.builtin.debug:
    msg: "Connecting as {{ switch_login.username }}"
  no_log: true        # <- not optional
```

## Read this second: the reveal rate limit

`netbox-openbao` rate limits reveals **per user**, by default `30/hour`.

A lookup written inline on a task that runs against 200 hosts will exhaust that
partway through, and the failure looks like a plugin bug rather than a quota.
The collection raises a specific, actionable error when it happens — but the
fix is a playbook pattern, not a library trick:

```yaml
# Resolve once for the whole play, then reuse.
- name: Resolve
  ansible.builtin.set_fact:
    creds: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                      credential_id=142) }}"
  run_once: true
  delegate_to: localhost
  no_log: true
```

The collection caches reveals **in process**, which helps for lookups evaluated
in play-level `vars`, in a `run_once` task, or repeatedly within one fork.
Ansible forks workers for host execution, and each fork gets its own cache — so
the cache is not a substitute for `run_once`. That limit is stated here rather
than glossed, because relying on a cache that silently does not apply is how
you hit the rate limit anyway.

If a fleet-wide per-host reveal is genuinely what you need, raise
`reveal_rate_limit` in the plugin's `PLUGINS_CONFIG` deliberately, rather than
discovering the ceiling at run time.

## Install

```bash
ansible-galaxy collection install git+https://git.nmulti.cloud/emersonfelipesp/netbox-openbao-ansible.git
```

## Configure

Both from the environment. **Never put a token in a playbook** — a token in a
playbook is a token in version control.

```bash
export NETBOX_URL=https://netbox.example.net
export NETBOX_TOKEN=nbt_xxxxxxxx.yyyyyyyy      # or NETBOX_OPENBAO_TOKEN
```

NetBox 4.7 issues v2 tokens (`nbt_<key>.<token>`) and still accepts legacy v1
tokens. The collection detects which scheme a token needs from its own shape,
so there is nothing to configure.

### Permissions

The token needs **`netbox_openbao.view_credential`** and
**`netbox_openbao.reveal_credential`**.

Explicitly **not** `add_credential`. That distinction is real and recent: NetBox
maps `POST` to `add_<model>` by default, which had made the dedicated reveal
permission decorative until the plugin overrode it. The collection's live tests
run with a token holding exactly view + reveal, which is what makes this claim
verified rather than asserted.

### TLS

Verification is on by default. For an internal CA, point at your bundle:

```bash
export NETBOX_CA_BUNDLE=/etc/ssl/certs/internal-ca.pem
```

`validate_certs: false` exists because Ansible modules conventionally offer it,
but it warns loudly and should never appear in a production playbook — with it
off, both the API token and the revealed material are readable by anyone on the
path.

## Selecting a credential

| Selector | Example |
|---|---|
| Device + purpose | `device='core-sw-01', purpose='login'` |
| Virtual machine | `virtual_machine='vm-01', purpose='login'` |
| Service | `service='ssh'` |
| By ID | `credential_id=142` |
| By UUID | `uuid='0d2f8f6e-…'` |
| By name | `lookup(..., 'core-sw-01 login')` |

Devices, VMs, and services accept a name or a numeric ID.

Resolution prefers the assignment marked **primary** — which is exactly what
`netbox-openbao`'s single-primary-per-(object, purpose) constraint exists to
make unambiguous. If several match and none is primary, the lookup **fails
rather than guessing**, because silently taking the first would make a play's
behaviour depend on database ordering.

## What you get back

The secret payload, plus the credential's non-secret identity so a play does
not need a second lookup to learn the username:

```json
{
  "password": "…",
  "id": 142,
  "uuid": "0d2f8f6e-…",
  "name": "core-sw-01 login",
  "username": "admin",
  "credential_type": "password",
  "kv_version": 3,
  "ttl": 300
}
```

`field='password'` returns just that value instead.

## Other options

- `reason='CHG-1234'` — recorded in the credential's access log, and **required**
  when the credential's policy sets `require_reason`.
- `version=2` — read a superseded KV version. Leave unset unless that is
  deliberately what you want; by default you get the version currently in
  service, which is not necessarily the latest one written if a rotation is
  staged.

## Why this is a separate collection

The lookup runs on the Ansible control node, which has no NetBox, no Django, and
no database. Shipping it inside the plugin's wheel would put an Ansible
dependency in a Django package, make every NetBox installation carry code it
will never execute, and chain the lookup's releases to the plugin's — when the
two have quite different compatibility surfaces. The REST API is the contract
between them, and a separate package makes that boundary explicit.

## Development

```bash
pip install ansible-core pytest ruff
pytest tests/unit          # no server needed
ruff check .
```

Against a live NetBox:

```bash
export NETBOX_OPENBAO_TEST_URL=http://127.0.0.1:8000
export NETBOX_OPENBAO_TEST_TOKEN=nbt_…
export ANSIBLE_COLLECTIONS_PATH=/path/to/collections
pytest tests
```

The live tests are worth running. The only defect they have caught that a stub
could not was in `netbox-openbao` itself — creating a credential failed against
a real OpenBao because the plugin sent an empty `custom_metadata` value, which
its own fake backend had happily accepted. Stubs agree with whatever you
believe; servers do not.

## License

Apache-2.0.

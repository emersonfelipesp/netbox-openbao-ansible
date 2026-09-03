# Usage patterns

The README covers the two things that must not be got wrong — `no_log` and the
reveal rate limit. This is the rest.

## Resolve once, use everywhere

The pattern to copy. One reveal for the whole play, regardless of host count:

```yaml
- hosts: switches
  tasks:
    - name: Resolve the fleet SSH key
      ansible.builtin.set_fact:
        fleet_key: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                              credential_id=142, field='private_key') }}"
      run_once: true
      delegate_to: localhost
      no_log: true

    - name: Write it where the connection plugin will find it
      ansible.builtin.copy:
        content: "{{ fleet_key }}"
        dest: /root/.ssh/fleet_key
        mode: '0600'
      no_log: true
```

## Per-host credentials

When each host genuinely has its own credential, resolve per host — and size
the rate limit for it deliberately, rather than finding the ceiling at run
time:

```yaml
- name: Resolve this host's login
  ansible.builtin.set_fact:
    login: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                      device=inventory_hostname, purpose='login') }}"
  no_log: true
```

For a 200-host play that is 200 reveals. The plugin's default ceiling is
`30/hour`; raise `reveal_rate_limit` in `PLUGINS_CONFIG` to match what you
actually intend.

## Connecting with a resolved credential

```yaml
- hosts: switches
  gather_facts: false
  tasks:
    - name: Resolve
      ansible.builtin.set_fact:
        creds: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                          device=inventory_hostname, purpose='login') }}"
      no_log: true

    - name: Use it
      ansible.builtin.raw: show version
      vars:
        ansible_user: "{{ creds.username }}"
        ansible_password: "{{ creds.password }}"
      no_log: true
```

Note the username comes from the same lookup. The credential's non-secret
identity travels with the payload precisely so this does not cost a second
call.

## Policies that require a reason

A `CredentialPolicy` may set `require_reason`, in which case a reveal without
one is refused — and the refusal is itself recorded in the access log.

```yaml
- name: Read a production credential
  ansible.builtin.set_fact:
    prod: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                     credential_id=142, reason='CHG-1234') }}"
  no_log: true
```

Put something traceable there. "ansible" is not a reason; a change ticket is.

## Staged rotations

By default you get the version **currently in service**, which is not
necessarily the latest one written. If a rotation is staged, the new version
exists in OpenBao but has not been promoted, and this lookup will keep
returning the working one — which is the entire point of staging.

Pass `version=` only when you deliberately want a specific one.

## Errors you will actually see

| Message | Meaning |
|---|---|
| `rate limit exceeded (HTTP 429)` | You are revealing per host. Use `run_once`, or raise `reveal_rate_limit`. |
| `NetBox rejected the token (HTTP 403)` | The token lacks `view_credential` or `reveal_credential`. `add_credential` does not substitute. |
| `Not found (HTTP 404)` | Either it does not exist, or the token's object-permission constraints exclude it. `netbox-openbao` returns 404 rather than 403 so a response cannot confirm a credential you may not read exists. |
| `N credentials matched and none is marked primary` | Narrow with `purpose=`, or mark one assignment primary in NetBox. |
| `N credential(s) are assigned to … but none matches …` | You narrowed with `credential_type=`, `uuid=`, or `name=` and nothing satisfied it. The message lists the types that are present. Note that these filters used to be accepted and ignored alongside an object selector, so a play relying on one was silently served whichever credential was primary. |
| `No device named "x" in NetBox` | The selector did not resolve. Names are exact. |
| `No credential assigned to <type> #<id>` | Either nothing is assigned, or that content type is not in the target NetBox's assignable-model allowlist — an assignment cannot exist for a type the allowlist rejects, and the two look identical from here. |
| `"x" is not a NetBox content-type label` | `assigned_object_type` must be `app_label.model`, for example `netbox_proxbox.proxmoxendpoint`. Caught before the request, so it cannot be mistaken for an empty result. |
| `assigned_object_id must be a positive integer` | Name resolution is only available for `device`, `virtual_machine`, and `service`. Quote the id: the option is declared `str` so Ansible does not coerce it first, and floats, booleans, whitespace-padded strings, and non-ASCII digits are then refused rather than silently turned into a different object's primary key. |

## Objects beyond devices, VMs, and services

`netbox-openbao`'s assignable-model allowlist is configurable and can be
extended by an installed plugin, so the three named selectors cannot cover
everything. Give the content type and the primary key instead:

```yaml
- name: Resolve the Proxmox endpoint API token
  ansible.builtin.set_fact:
    proxmox_api: "{{ lookup('emersonfelipesp.netbox_openbao.credential',
                            assigned_object_type='netbox_proxbox.proxmoxendpoint',
                            assigned_object_id='3',
                            purpose='api') }}"
  run_once: true
  delegate_to: localhost
  no_log: true
```

Both halves are required — one alone is far more likely to be a mistake than a
request to ignore it, and ignoring it silently would widen the query to every
assignment of that type. Mixing this pair with `device`, `virtual_machine`, or
`service` is an error rather than a precedence rule: two selectors that disagree
have no correct answer, and picking one would make a play's behaviour depend on
an ordering nobody wrote down.

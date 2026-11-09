# Static Ansible inventory

In the **Add server** dialog, choose the Ansible inventory tab and select a local file. Cyberbot reads static INI, YAML, or JSON, including flat JSON with `_meta.hostvars`. The content determines the format. A filename extension is optional. Ansible itself is unnecessary.

The file is reread every five minutes. A failed parse keeps the previous server list and history. To remove all hosts intentionally, use an explicitly empty group such as `[web]` in INI or `all: {hosts: {}}` in YAML. A blank file is an error.

```ini
[all:vars]
ansible_user=ops
ansible_port=22

[web]
web[01:03] ansible_port=2222
database ansible_host=192.0.2.10 ansible_user=diagnostic
```

```yaml
all:
  vars:
    ansible_user: ops
  children:
    web:
      hosts:
        web01:
          ansible_host: 192.0.2.20
          ansible_port: 2222
```

Cyberbot supports explicit `ansible_host`, `ansible_user`, `ansible_port`, `ansible_ssh_private_key_file`, and their SSH aliases. An inventory host without a user inherits a group user or defaults to `root`. The default port is 22. Configure jump hosts and compatible SSH options in OpenSSH configuration. Inventory entries with custom SSH executable or arbitrary SSH arguments are rejected.

Connection settings inherit from `all`, parent groups, child groups, and then the host. Within one level, group priority and alphabetical order determine precedence. Groups and host ranges are flattened when importing. Group cycles are rejected. Inventory structure is used for parsing and inheritance and stays separate from the application's server names and [dependency graph](INCIDENT_GROUPS.md).

The parser reads only the selected UTF-8 file. It supports literal connection settings and skips unrelated variables. Dynamic inventory, Jinja, Vault, external variable files, YAML aliases, and multi-document files are unsupported. The limits are 8 MiB per file, 64 KiB per line, 5,000 unique servers, 1,024 groups, 50,000 direct and 50,000 transitive relationships, and 32 nesting levels. Updates apply only after the whole file parses successfully.

See the [Ansible inventory guide](https://docs.ansible.com/projects/ansible/latest/inventory_guide/intro_inventory.html) for background on the formats.

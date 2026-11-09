use cyberbot_lib::{
    inventory::{parse_ansible, read_source},
    model::{now, Source},
    store::Store,
};
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

#[test]
fn missing_user_defaults_to_root_in_all_static_formats() {
    for input in [
        "[web]\nnode\n",
        "all:\n  hosts:\n    node:\n",
        r#"{"all":{"hosts":{"node":{}}}}"#,
        r#"{"all":{"hosts":["node"]},"_meta":{"hostvars":{"node":{}}}}"#,
    ] {
        let hosts = parse_ansible(input).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].endpoint.user, "root");
        assert_eq!(hosts[0].endpoint.port, 22);
    }
}

#[test]
fn ini_inherits_literal_settings_with_host_overrides_and_quoted_paths() {
    let hosts = parse_ansible(
        r#"
        [all:vars]
        ansible_user = fleet
        ansible_port = 2222
        ansible_ssh_private_key_file = "/Users/test/my key"
        password = not-retained
        [prod:vars]
        ansible_user=production
        [prod:children]
        web
        [web]
        web01 ansible_host=10.1.2.3 ansible_user=alice # comment
        web02
        [ungrouped]
        backup:2200 ansible_ssh_user=ops
        [::1]:2201 ansible_user=local
    "#,
    )
    .unwrap();
    assert_eq!(hosts.len(), 4);
    let first = hosts.iter().find(|h| h.name == "web01").unwrap();
    assert_eq!(first.endpoint.host, "10.1.2.3");
    assert_eq!(first.endpoint.user, "alice");
    assert_eq!(first.endpoint.port, 2222);
    assert_eq!(
        first.endpoint.identity_file.as_deref(),
        Some("/Users/test/my key")
    );
    assert_eq!(
        hosts
            .iter()
            .find(|h| h.name == "web02")
            .unwrap()
            .endpoint
            .user,
        "production"
    );
    let backup = hosts.iter().find(|h| h.name == "backup").unwrap();
    assert_eq!(backup.endpoint.port, 2200);
    assert_eq!(backup.endpoint.user, "ops");
    assert_eq!(
        hosts
            .iter()
            .find(|h| h.name == "::1")
            .unwrap()
            .endpoint
            .port,
        2201
    );
}

#[test]
fn yaml_nested_groups_merge_globals_and_priority_without_labels() {
    let hosts = parse_ansible(
        r#"
all:
  vars:
    ansible_user: fleet
    ansible_port: 2222
  children:
    parent:
      vars:
        ansible_user: parent
      children:
        a_web:
          vars:
            ansible_group_priority: 10
            ansible_user: preferred
          hosts:
            web: {ansible_host: 10.0.0.1}
            other: {ansible_ssh_user: override, ansible_ssh_port: 2200}
        z_web:
          vars:
            ansible_user: secondary
          hosts:
            web:
outside:
  hosts:
    standalone:
"#,
    )
    .unwrap();
    assert_eq!(hosts.len(), 3);
    let web = hosts.iter().find(|h| h.name == "web").unwrap();
    assert_eq!(web.endpoint.user, "preferred");
    assert_eq!(web.endpoint.host, "10.0.0.1");
    let other = hosts.iter().find(|h| h.name == "other").unwrap();
    assert_eq!(other.endpoint.user, "override");
    assert_eq!(other.endpoint.port, 2200);
    assert_eq!(
        hosts
            .iter()
            .find(|h| h.name == "standalone")
            .unwrap()
            .endpoint
            .user,
        "fleet"
    );
}

#[test]
fn flat_json_export_and_static_json_are_supported() {
    for input in [
        r#"{"_meta":{"hostvars":{"node":{"ansible_user":"ops","ansible_host":"10.0.0.4","ansible_port":2200}}},"all":{"children":["web"]},"web":{"hosts":["node"]}}"#,
        r#"{"all":{"vars":{"ansible_user":"ops","ansible_port":2200},"hosts":{"node":{"ansible_host":"10.0.0.4"}}}}"#,
    ] {
        let hosts = parse_ansible(input).unwrap();
        assert_eq!(hosts.len(), 1);
        assert_eq!(hosts[0].name, "node");
        assert_eq!(hosts[0].endpoint.host, "10.0.0.4");
        assert_eq!(hosts[0].endpoint.port, 2200);
    }
}

#[test]
fn numeric_alphabetic_ranges_stride_dedup_and_ipv6() {
    let hosts = parse_ansible("[all:vars]\nansible_user=ops\n[web]\nnode[01:05:2]\nnode03\ncache[a:c]:2200\n2001:db8::1\n").unwrap();
    assert_eq!(hosts.len(), 7);
    assert_eq!(
        hosts.iter().map(|h| h.name.as_str()).collect::<Vec<_>>(),
        vec![
            "2001:db8::1",
            "cachea",
            "cacheb",
            "cachec",
            "node01",
            "node03",
            "node05"
        ]
    );
    assert_eq!(
        hosts
            .iter()
            .find(|h| h.name == "cachea")
            .unwrap()
            .endpoint
            .port,
        2200
    );
    let yaml = parse_ansible(
        "all:\n  vars: {ansible_user: ops}\n  hosts:\n    'rack[1:2]-node[01:02]':\n",
    )
    .unwrap();
    assert_eq!(yaml.len(), 4);
    for input in [
        "[all]\n[2001:db8:0:0:0:0:0:2]:2201 ansible_user=ops\n",
        "all: {vars: {ansible_user: ops}, hosts: {'[2001:db8:0:0:0:0:0:2]:2201': {}}}",
    ] {
        let hosts = parse_ansible(input).unwrap();
        assert_eq!(hosts[0].endpoint.host, "2001:db8:0:0:0:0:0:2");
        assert_eq!(hosts[0].endpoint.port, 2201);
    }
}

#[test]
fn invalid_or_executable_inventory_cannot_partially_import() {
    for input in [
        "",
        "# only comments\n; no inventory\n",
        "plugin: amazon.aws.aws_ec2\nregions: [eu-west-1]",
        "#!/usr/bin/env python3\nprint('not inventory')",
        "$ANSIBLE_VAULT;1.1;AES256\n0011",
        "all: !python/object/apply:os.system ['touch marker']",
        "all:\n  vars: &defaults {ansible_user: ops}\n  hosts: *defaults",
        "all: {vars: {ansible_user: ops}, vars: {ansible_user: root}}",
        "all: {hosts: {node: {ansible_user: ops}}}\n---\nall: {}",
        "all: {vars: {ansible_user: ops}, hosts: {node: {}}, children: {all: {}}}",
        "[a:children]\nb\n[b:children]\na",
        "[web]\nnode ansible_user=ops\ninvalid ansible_user=ops ansible_port=0",
        "[web]\nnode ansible_user='unclosed",
        "[web]\nnode ansible_user=''",
        "[web]\nnode ansible_user=ops ansible_connection=local",
        "[all:vars]\nansible_user=ops\n[web]\nnode\nbad;host",
        "[all:vars]\nansible_user=ops\n[web]\nnode[01:05:0]",
    ] {
        assert!(
            parse_ansible(input).is_err(),
            "unexpectedly accepted {input}"
        );
    }
    assert!(parse_ansible("[web]\n").unwrap().is_empty());
    assert!(parse_ansible("all :\n  hosts: {}\n").unwrap().is_empty());
}

#[test]
fn templates_commands_and_bad_endpoints_are_rejected_without_echoing_values() {
    for vars in [
        "ansible_host: '{{ lookup(\"pipe\", \"SECRET_PAYLOAD\") }}'",
        "ansible_user: '{{ SECRET_PAYLOAD }}'",
        "ansible_ssh_private_key_file: '{{ SECRET_PAYLOAD }}'",
        "ansible_ssh_common_args: '-oProxyCommand=SECRET_PAYLOAD'",
        "ansible_ssh_extra_args: '-oLocalCommand=SECRET_PAYLOAD'",
        "ansible_ssh_executable: 'SECRET_PAYLOAD'",
        "ansible_port: SECRET_PAYLOAD",
        "ansible_host: '$(SECRET_PAYLOAD)'",
        "ansible_host: '-oProxyCommand=SECRET_PAYLOAD'",
    ] {
        let input =
            format!("all:\n  vars: {{ansible_user: ops}}\n  hosts:\n    node:\n      {vars}\n");
        let error = parse_ansible(&input).unwrap_err();
        assert!(!error.contains("SECRET_PAYLOAD"));
    }
    let error = parse_ansible("all: {hosts: {node: {ansible_user: ops, secret: [SECRET_PAYLOAD}}}")
        .unwrap_err();
    assert!(!error.contains("SECRET_PAYLOAD"));
}

#[test]
fn unrelated_variables_are_data_and_never_become_connection_options() {
    let hosts = parse_ansible(
        r#"all:
  vars:
    ansible_user: ops
    arbitrary: '{{ lookup("pipe", "echo SECRET_PAYLOAD") }}'
    password: SECRET_PAYLOAD
    complex: {one: [1, 2], two: false}
  hosts:
    node:
"#,
    )
    .unwrap();
    assert_eq!(hosts[0].endpoint.user, "ops");
    assert!(!serde_json::to_string(&hosts[0].endpoint)
        .unwrap()
        .contains("SECRET_PAYLOAD"));
}

#[test]
fn parsing_is_bounded_before_expanding_or_recursing() {
    assert!(parse_ansible(&" ".repeat(8 * 1024 * 1024 + 1)).is_err());
    assert!(parse_ansible(&format!("#{}", "a".repeat(64 * 1024))).is_err());
    assert!(parse_ansible("[all:vars]\nansible_user=ops\n[web]\nnode[1:4294967295]\n").is_err());
    assert!(
        parse_ansible("[all:vars]\nansible_user=ops\n[web]\nnode[1:100]-rack[1:100]\n").is_err()
    );
    let deep = format!("all: {}0{}", "[".repeat(40), "]".repeat(40));
    assert!(parse_ansible(&deep).is_err());
    let groups = (0..1025).map(|i| format!("[g{i}]\n")).collect::<String>();
    assert!(parse_ansible(&groups).is_err());
    let too_many_nodes = format!(
        "all:\n  vars:\n    ignored:\n{}",
        (0..50_001)
            .map(|i| format!("      k{i}: value\n"))
            .collect::<String>()
    );
    assert!(parse_ansible(&too_many_nodes)
        .unwrap_err()
        .contains("100,000"));
    let too_many_members = format!(
        "[all:vars]\nansible_user=ops\n{}",
        (0..12)
            .map(|i| format!("[g{i}]\nnode[1:5000]\n"))
            .collect::<String>()
    );
    assert!(parse_ansible(&too_many_members).is_err());
    let inherited_members = format!(
        "[all:vars]\nansible_user=ops\n[g0]\nnode[1:5000]\n{}",
        (1..12)
            .map(|i| format!("[g{i}:children]\ng{}\n", i - 1))
            .collect::<String>()
    );
    assert!(parse_ansible(&inherited_members)
        .unwrap_err()
        .contains("50,000"));
}

#[test]
fn handles_a_500_server_static_inventory_without_a_model_or_subprocess() {
    let input = "[all:vars]\nansible_user=ops\n[web]\nnode[001:500] ansible_port=2222\n";
    let started = std::time::Instant::now();
    let hosts = parse_ansible(input).unwrap();
    assert_eq!(hosts.len(), 500);
    assert_eq!(hosts[0].name, "node001");
    assert_eq!(hosts[499].name, "node500");
    assert!(hosts.iter().all(|h| h.endpoint.port == 2222));
    eprintln!(
        "static inventory: {} bytes, {} servers, {:?}",
        input.len(),
        hosts.len(),
        started.elapsed()
    );
}

#[test]
fn actual_file_refresh_preserves_last_snapshot_on_parse_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("hosts");
    let db = Store::open(Path::new(":memory:")).unwrap();
    let source = Source {
        id: "static".into(),
        name: "hosts".into(),
        kind: "ansible".into(),
        location: path.to_str().unwrap().into(),
        last_sync: Some(now()),
        error: None,
    };
    fs::write(
        &path,
        "[all:vars]\nansible_user=ops\n[web]\nfirst\nsecond\n",
    )
    .unwrap();
    db.import(
        &source,
        read_source(&source.kind, &source.location).unwrap(),
    )
    .unwrap();
    let before = db.snapshot().unwrap();
    let first_id = before
        .servers
        .iter()
        .find(|s| s.name == "first")
        .unwrap()
        .id
        .clone();
    fs::write(&path, "all: {hosts: {broken: [").unwrap();
    let error = read_source(&source.kind, &source.location).unwrap_err();
    db.source_error(&source, error).unwrap();
    let failed = db.snapshot().unwrap();
    assert_eq!(failed.servers.len(), 2);
    assert_eq!(failed.sources[0].last_sync, before.sources[0].last_sync);
    assert!(failed.sources[0].error.is_some());
    fs::write(
        &path,
        "[web]\nfirst ansible_user=ops\nthird ansible_user=ops\n",
    )
    .unwrap();
    db.import(
        &source,
        read_source(&source.kind, &source.location).unwrap(),
    )
    .unwrap();
    let recovered = db.snapshot().unwrap();
    assert_eq!(recovered.servers.len(), 2);
    assert!(recovered.sources[0].error.is_none());
    assert_eq!(
        recovered
            .servers
            .iter()
            .find(|s| s.name == "first")
            .unwrap()
            .id,
        first_id
    );
    assert!(recovered.servers.iter().any(|s| s.name == "third"));
    assert!(!recovered.servers.iter().any(|s| s.name == "second"));
}

#[test]
fn rejects_non_regular_oversized_non_utf8_and_relative_files() {
    let dir = tempfile::tempdir().unwrap();
    assert!(read_source("ansible", dir.path().to_str().unwrap()).is_err());
    assert!(read_source("ansible", "relative.ini").is_err());
    let path = dir.path().join("hosts");
    fs::write(&path, [0xff]).unwrap();
    assert!(read_source("ansible", path.to_str().unwrap()).is_err());
    let file = fs::File::create(&path).unwrap();
    file.set_len(8 * 1024 * 1024 + 1).unwrap();
    assert!(read_source("ansible", path.to_str().unwrap()).is_err());
    let fifo = dir.path().join("fifo");
    let c_path = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(c_path.as_ptr(), 0o600) }, 0);
    assert!(read_source("ansible", fifo.to_str().unwrap()).is_err());
}

#[test]
fn importing_never_launches_ansible_scripts_or_adjacent_configuration() {
    // Separate process sets a booby-trapped PATH/cwd without changing the test
    // runner environment or touching the operator's Ansible/SSH configuration.
    if let Ok(root) = std::env::var("CYBERBOT_STATIC_INVENTORY_TEST") {
        let root = Path::new(&root);
        let hosts = read_source("ansible", root.join("hosts").to_str().unwrap()).unwrap();
        assert_eq!(hosts[0].endpoint.user, "ops");
        assert!(read_source("ansible", root.join("dynamic.py").to_str().unwrap()).is_err());
        assert!(!root.join("executed").exists());
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    for name in ["ansible-inventory", "dynamic.py"] {
        let path = dir.path().join(name);
        fs::write(&path, "#!/bin/sh\n/usr/bin/touch executed\nprintf '{}'").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }
    fs::write(
        dir.path().join("ansible.cfg"),
        "[defaults]\ninventory_plugins = .\nvars_plugins = .\n",
    )
    .unwrap();
    fs::create_dir(dir.path().join("group_vars")).unwrap();
    fs::write(
        dir.path().join("group_vars/all.yml"),
        "ansible_user: wrong\n",
    )
    .unwrap();
    fs::write(dir.path().join("hosts"), "[web]\nnode ansible_user=ops\n").unwrap();
    fs::set_permissions(dir.path().join("hosts"), fs::Permissions::from_mode(0o700)).unwrap();
    let output = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "importing_never_launches_ansible_scripts_or_adjacent_configuration",
        ])
        .env("CYBERBOT_STATIC_INVENTORY_TEST", dir.path())
        .env("PATH", dir.path())
        .current_dir(dir.path())
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!dir.path().join("executed").exists());
}

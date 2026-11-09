use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
};

fn source(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn identifier(name: &str) -> bool {
    !name.is_empty()
        && name.as_bytes()[0].is_ascii_alphabetic()
        && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

fn main() {
    let root = PathBuf::from("../collectors");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    println!("cargo:rerun-if-changed=../collectors");
    println!("cargo:rerun-if-changed=../src/components/service-panels");

    let catalog = source(&root.join("connectors/catalog.json"));
    let services: BTreeMap<String, Value> =
        serde_json::from_str(&catalog).expect("Service catalog");
    let mut files = vec![root.join("platforms/runtime.py")];
    let mut platforms: Vec<_> = fs::read_dir(root.join("platforms"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.extension().is_some_and(|ext| ext == "py")
                && path.file_name().unwrap() != "runtime.py"
        })
        .collect();
    platforms.sort();
    files.append(&mut platforms);
    files.extend(
        [
            "runtime_identity.py",
            "connectors/runtime.py",
            "actions.py",
            "remote_read.py",
            "system.py",
        ]
        .map(|part| root.join(part)),
    );
    let literal = |text: &str| serde_json::to_string(text).unwrap();
    let mut bundle = format!(
        "import json\nCONNECTOR_CATALOG = json.loads({})\n",
        literal(&catalog)
    );
    for path in files {
        bundle.push_str(&source(&path));
        bundle.push('\n');
    }
    let mut adapters = BTreeMap::new();
    let mut bindings = Vec::new();
    let mut modules = BTreeSet::new();
    let mut backends = String::from("const SERVICE_BACKENDS: &[(&str, ServiceBackend)] = &[\n");
    for (kind, spec) in services {
        assert!(
            identifier(&kind.replace('-', "_")),
            "Invalid service ID {kind}"
        );
        let python = spec["python"].as_str().expect("Python adapter");
        assert!(identifier(python), "Invalid Python adapter {python}");
        let path = root.join(format!("connectors/{python}.py"));
        let code = source(&path);
        let entry = format!("{}_ADAPTER", python.to_ascii_uppercase());
        assert!(
            code.lines()
                .any(|line| line.starts_with(&format!("{entry} = "))),
            "Missing {entry} in {}",
            path.display()
        );
        assert!(
            adapters.insert(python.to_owned(), code).is_none(),
            "Duplicate adapter {python}"
        );
        bindings.push(format!("{}: {entry}", literal(&kind)));

        if let Some(module) = spec["rust"].as_str() {
            assert!(identifier(module), "Invalid Rust adapter {module}");
            let path = PathBuf::from(format!("src/{module}.rs"))
                .canonicalize()
                .expect("Rust adapter");
            assert!(
                modules.insert(format!(
                    "#[path = {:?}]\nmod {module};\n",
                    path.to_str().unwrap()
                )),
                "Duplicate Rust adapter {module}"
            );
            backends.push_str(&format!(
                "    ({}, crate::{module}::BACKEND),\n",
                literal(&kind)
            ));
        }
        if let Some(panel) = spec["panel"].as_str() {
            assert!(
                identifier(panel)
                    && Path::new(&format!("../src/components/service-panels/{panel}.vue"))
                        .is_file(),
                "Missing service panel {panel}"
            );
        }
        if let Some(presentation) = spec["actionPresentation"].as_str() {
            assert!(
                identifier(presentation)
                    && Path::new(&format!(
                        "../src/components/service-panels/{presentation}.ts"
                    ))
                    .is_file(),
                "Missing action presentation {presentation}"
            );
        }
    }
    for code in adapters.values() {
        bundle.push_str(code);
        bundle.push('\n');
    }
    bundle.push_str(&format!("SERVICE_ADAPTERS = {{{}}}\n", bindings.join(", ")));
    bundle.push_str("RUNTIME_IDENTITIES = RuntimeIdentityRegistry({kind: adapter.identity for kind, adapter in SERVICE_ADAPTERS.items()})\n");
    bundle.push_str("register_service_actions(SERVICE_ADAPTERS)\n");
    bundle.push_str(&source(&root.join("entrypoint.py")));
    fs::write(out.join("collector.py"), bundle).unwrap();
    fs::write(
        out.join("service_modules.rs"),
        modules.into_iter().collect::<String>(),
    )
    .unwrap();
    backends.push_str("];\n");
    fs::write(out.join("service_backends.rs"), backends).unwrap();
    tauri_build::build()
}

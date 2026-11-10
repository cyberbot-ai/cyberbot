"""Build the same single-file collector as the desktop build."""
import json
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).parent


def source():
    catalog = (ROOT / "connectors/catalog.json").read_text()
    services = json.loads(catalog)
    stems = sorted(spec["python"] for spec in services.values())
    if len(set(stems)) != len(stems):
        raise ValueError("Duplicate collector implementation")
    parts = [
        "platforms/runtime.py",
        *sorted(f"platforms/{p.name}" for p in (ROOT / "platforms").glob("*.py") if p.name != "runtime.py"),
        "runtime_identity.py",
        "connectors/runtime.py",
        "actions.py",
        "remote_read.py",
        "system.py",
        "server_poll.py",
        *(f"connectors/{stem}.py" for stem in stems),
    ]
    bindings = ", ".join(f"{json.dumps(kind)}: {spec['python'].upper()}_ADAPTER" for kind, spec in sorted(services.items()))
    return (
        f"import json\nCONNECTOR_CATALOG = json.loads({json.dumps(catalog, ensure_ascii=False)})\n"
        + "".join((ROOT / part).read_text() + "\n" for part in parts)
        + f"SERVICE_ADAPTERS = {{{bindings}}}\n"
        + "RUNTIME_IDENTITIES = RuntimeIdentityRegistry({kind: adapter.identity for kind, adapter in SERVICE_ADAPTERS.items()})\n"
        + "register_service_actions(SERVICE_ADAPTERS)\n"
        + (ROOT / "entrypoint.py").read_text()
    )


def module():
    collector = ModuleType("collector_test")
    exec(compile(source(), "collector_bundle", "exec"), collector.__dict__)
    return collector


def namespace():
    return module().__dict__

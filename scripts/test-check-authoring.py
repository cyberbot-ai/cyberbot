"""Opt-in real agent test: drafts/tests only, no infrastructure or activation."""
import argparse,json,pathlib,subprocess,tempfile
parser=argparse.ArgumentParser();parser.add_argument('--agent',choices=['codex','claude'],required=True);args=parser.parse_args()
root=pathlib.Path(__file__).resolve().parents[1]
with tempfile.TemporaryDirectory(prefix='cyberbot-check-authoring-') as directory:
    result=subprocess.run([str(root/'src-tauri/target/debug/cyberbot'),'--checks-smoke',args.agent,directory],capture_output=True,text=True,timeout=360)
    if not result.stdout.strip():raise RuntimeError(result.stderr[-1000:])
    report=json.loads(result.stdout);out=root/'.runtime'/f'check-authoring-{args.agent}.json';out.parent.mkdir(exist_ok=True);out.write_text(json.dumps(report,ensure_ascii=False,indent=2));print(json.dumps(report,ensure_ascii=False))
    assert result.returncode==0 and report['testedDraft'] and not report['enabled'],report

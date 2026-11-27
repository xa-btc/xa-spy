"""End-to-end tests against synthetic fixtures only; never issue a live audit command."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile

CHECKS = ["processes", "services", "drivers", "startup_registry", "startup_folders",
          "scheduled_tasks", "installed_apps", "security", "event_logs", "connections", "devices"]
PAYLOAD = b"XA Spy harmless synthetic hash fixture. This is not executable machine code.\n"


def prepare(root):
    root.mkdir(parents=True, exist_ok=True)
    (root / "iocs").mkdir(exist_ok=True)
    (root / "files").mkdir(exist_ok=True)
    (root / "browser").mkdir(exist_ok=True)
    sample = root / "files" / "fixture.exe"
    sample.write_bytes(PAYLOAD)
    (root / "files" / "readme.txt").write_text("unsupported benign file")
    private = root / "files" / "Login Data"
    private.mkdir(exist_ok=True)
    (private / "secret.exe").write_bytes(PAYLOAD)
    (root / "iocs" / "adfection_iocs.txt").write_text(hashlib.sha256(PAYLOAD).hexdigest() + "\tsample\tprimary\tsynthetic-hash-source\n")
    (root / "iocs" / "curated_mercenary.txt").write_text("fixture.example.test\tinfrastructure\tprimary\tsynthetic-domain-source\n2001:db8::1\tinfrastructure-ip\tprimary\tsynthetic-ipv6-source\n")
    for name in [*CHECKS, "settings"]:
        record = {"name": "PRIVATE_SENTINEL_" + name, "detail": "synthetic inventory"}
        if name == "processes":
            record.update(executable=str(sample), pid=4242)
        if name == "connections":
            record.update(address="fixture.example.test", pid=4242)
        (root / (name + ".json")).write_text(json.dumps({"outcome": "checked_no_matches", "records": [record]}))
    (root / "browser" / "Bookmarks").write_text(json.dumps({"roots": {"bookmark_bar": {"type": "folder", "children": [
        {"type": "url", "url": "https://user:SECRET_PASSWORD@fixture.example.test/path?TOKEN_SECRET=1", "name": "SECRET_TITLE"},
        {"type": "url", "url": "https://notfixture.example.test/", "name": "not a match"}]}}}))
    return root


def run(exe, *args, expected=None):
    process = subprocess.run([str(exe), *map(str, args)], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, encoding="utf-8", errors="strict", timeout=60)
    if expected is not None:
        assert process.returncode == expected, (process.returncode, process.stdout[-1000:], process.stderr)
    assert not process.stderr, process.stderr
    rows = [json.loads(line) for line in process.stdout.splitlines() if line]
    assert rows, process.stdout
    return rows


def validate(exe, root):
    count = 0
    def check(value, label):
        nonlocal count
        assert value, label
        count += 1
    # Every scan command specifies --fixture and an explicit mode.
    rows = run(exe, "--scan", "--mode", "system", "--fixture", root, "--browser", expected=2)
    final = rows[-1]
    check(final["state"] == "completed" and final["fixture"] is True, "fixture completion")
    check(len(final["checks"]) == 13, "all required modules")
    check(final["hash_leads"] == 1, "known hash match and excluded credential directory")
    check(final["reference_leads"] == 2, "connection and structured bookmark matches")
    serialized = json.dumps(rows)
    check(all(s not in serialized for s in ["PRIVATE_SENTINEL", "TOKEN_SECRET", "SECRET_PASSWORD", str(root), "fixture.example.test"]), "filtered console privacy")
    check(final["clean_bill_of_health"] is False, "no clean system claim")
    run_dir = exe.parent / "findings" / final["run_id"]
    evidence = (run_dir / "private-evidence.jsonl").read_text(encoding="utf-8")
    check("synthetic-hash-source" in evidence and "synthetic-domain-source" in evidence, "match provenance")
    check("browser_reference" in evidence and "known_sample_hash" in evidence, "evidence grades")
    check("SECRET_PASSWORD" not in evidence and "TOKEN_SECRET" not in evidence, "no URL secrets retained")
    check(run(exe, "--status", final["run_id"], expected=0)[-1]["state"] == "completed", "status")
    progress_path = run_dir / "progress.jsonl"
    original_progress = progress_path.read_bytes()
    progress_path.write_bytes(original_progress + b'{"state":"PRIVATE_PARTIAL')
    check(run(exe, "--status", final["run_id"], expected=0)[-1]["state"] == "completed", "partial last line ignored")
    progress_path.write_bytes(b'x' * 70000)
    check(run(exe, "--status", final["run_id"], expected=1)[-1]["state"] == "failed", "oversized unterminated progress bounded")
    progress_path.write_bytes(original_progress)
    summary_path = run_dir / "summary.json"
    summary = json.loads(summary_path.read_text())
    summary["password"] = "PRIVATE_SENTINEL"
    summary_path.write_text(json.dumps(summary))
    safe = run(exe, "--summary", final["run_id"], expected=0)[-1]
    check("password" not in safe and "PRIVATE_SENTINEL" not in json.dumps(safe), "summary reprojects allowlist")
    summary["checks"][0]["id"] = "PRIVATE_SENTINEL"
    summary_path.write_text(json.dumps(summary))
    check(run(exe, "--summary", final["run_id"], expected=1)[-1]["state"] == "failed", "invalid summary rejected")
    check(run(exe, "--cancel", final["run_id"], expected=1)[-1]["state"] == "failed", "terminal cancel refused")
    check(run(exe, "--status", "../../PRIVATE_SENTINEL", expected=1)[-1].get("exit_code", 1) == 1, "traversal refused")
    folder = run(exe, "--scan", "--mode", "folder", "--target", root / "files", "--fixture", root, expected=2)[-1]
    check(folder["mode"] == "folder" and len(folder["checks"]) == 2, "targeted mode isolated")
    check(next(c for c in folder["checks"] if c["id"] == "browser")["outcome"] == "unsupported", "browser opt in")
    (root / "services.json").write_text(json.dumps({"outcome": "access_denied", "denied": 1, "records": []}))
    (root / "event_logs.json").write_text(json.dumps({"outcome": "partial", "errors": 1, "records": [{"name": "retained partial"}]}))
    (root / "devices.json").unlink()
    partial = run(exe, "--scan", "--mode", "system", "--fixture", root, expected=2)[-1]
    by_id = {c["id"]: c for c in partial["checks"]}
    check(by_id["services"]["outcome"] == "access_denied", "access denied distinct")
    check(by_id["event_logs"]["outcome"] == "partial" and by_id["event_logs"]["checked"] == 1, "partial retained")
    check(by_id["devices"]["outcome"] == "failed", "absent fixture never falls back live")
    check(run(exe, "--scan", "--mode", "folder", "--target", root.parent, "--fixture", root, expected=1)[-1]["state"] == "failed", "fixture escape refused")
    prepare(root)
    settings = root / "settings.json"
    settings.write_text(json.dumps({"outcome": "checked_no_matches", "records": [
        {"name": "Public firewall", "detail": "Disabled (synthetic)", "address": "fixture.example.test"}]}))
    feed = root / "iocs" / "curated_mercenary.txt"
    feed.write_text(feed.read_text().replace("\tinfrastructure\t", "\treclaimable\t"))
    detailed = run(exe, "--scan", "--mode", "system", "--security-settings", "--fixture", root, expected=2)[-1]
    dr = exe.parent / "findings" / detailed["run_id"]
    review = (dr / "private-review.txt").read_text(encoding="utf-8")
    check("Ownership may have changed" in review and "Next step:" in review, "reclaimed host contextualized")
    check("Public firewall: Disabled (synthetic)" in review and detailed["reference_leads"] == 1,
          "configuration review does not add threat leads")
    check("fixture.example.test" not in json.dumps(detailed) and "Disabled (synthetic)" not in json.dumps(detailed),
          "review details stay local")
    projected = run(exe, "--summary", detailed["run_id"], expected=0)[-1]
    check(len(projected["checks"]) == 14 and any(c["id"] == "settings" for c in projected["checks"]),
          "settings summary round trip")
    check(all(c["id"] != "settings" for c in final["checks"]), "settings off by default")
    run(exe, "--scan", "--mode", "folder", "--target", root / "files", "--security-settings", "--fixture", root, expected=1)
    settings.unlink()
    gap = run(exe, "--scan", "--mode", "system", "--security-settings", "--fixture", root, expected=2)[-1]
    check(next(c for c in gap["checks"] if c["id"] == "settings")["outcome"] == "failed", "missing settings fixture cannot fall back live")
    prepare(root)
    (root / "connections.json").write_text(json.dumps({"outcome": "checked_no_matches", "records": [{"address": "2001:0db8:0:0:0:0:0:1", "pid": 4242}]}))
    ipv6 = run(exe, "--scan", "--mode", "system", "--fixture", root, expected=2)[-1]
    check(ipv6["reference_leads"] == 1, "IPv6 numeric equivalence without DNS")
    prepare(root)
    (root / "browser" / "Bookmarks").write_text('{"invalid_schema":true}')
    unsupported = run(exe, "--scan", "--mode", "system", "--fixture", root, "--browser", expected=2)[-1]
    check(next(c for c in unsupported["checks"] if c["id"] == "browser")["outcome"] == "unsupported", "actual unsupported browser schema")
    (root / "browser" / "Bookmarks").write_text('not json at all')
    failed = run(exe, "--scan", "--mode", "system", "--fixture", root, "--browser", expected=2)[-1]
    check(next(c for c in failed["checks"] if c["id"] == "browser")["outcome"] == "failed", "actual malformed browser input")
    prepare(root)
    # Plenty of local records provide deterministic time for the separate control process.
    many = [{"name": "synthetic_" + str(i), "detail": "x" * 1000} for i in range(10000)]
    (root / "processes.json").write_text(json.dumps({"outcome": "checked_no_matches", "records": many[:3000]}))
    child = subprocess.Popen([str(exe), "--scan", "--mode", "system", "--fixture", str(root)],
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
    try:
        first = json.loads(child.stdout.readline())
        request = run(exe, "--cancel", first["run_id"], expected=0)[-1]
        check(request["state"] == "cancel_requested", "local cancel accepted")
        rest, error = child.communicate(timeout=30)
        cancelled = json.loads(rest.splitlines()[-1])
        check(cancelled["state"] == "cancelled" and child.returncode == 1 and not error, "cancellation persisted")
        check(any(c["outcome"] == "cancelled" for c in cancelled["checks"]), "pending checks cancelled not clean")
    finally:
        if child.poll() is None:
            child.kill()  # Exact fixture process only, never a user's app.
            child.wait()
    prepare(root)
    print(f"PASS: {count} synthetic end-to-end assertions; fixtures retained at {root}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--exe", type=Path, required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--fixture", type=Path)
    args = parser.parse_args()
    fixture = args.fixture or Path(tempfile.mkdtemp(prefix="xa-spy-fixture-"))
    prepare(fixture.absolute())
    if args.prepare_only:
        print(fixture.absolute())
    else:
        validate(args.exe.absolute(), fixture.absolute())

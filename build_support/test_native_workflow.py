"""Isolated backup/receipt fixtures. No compiler, app, network or live evidence."""
import ast
import json
import os
from pathlib import Path
import sys
import tempfile

from .native_workflow import capture, complete, native_inputs, stable_inventory, write_state
from .source_backup import load_snapshot, object_path, restore_snapshot


def main():
    # Match the backup's resolved paths when TEMP uses a Windows short name.
    fixture = Path(tempfile.mkdtemp(prefix='xa-spy-build-fixtures-')).resolve(strict=True)

    def audit(event, args):
        if event.startswith(('subprocess.', 'socket.', 'os.system', 'os.exec', 'os.spawn')):
            raise AssertionError('Process/network operation forbidden in build fixtures')
        if event == 'open' and isinstance(args[0], (str, bytes, os.PathLike)):
            mode, flags = args[1], args[2]
            writing = (isinstance(mode, str) and any(c in mode for c in 'wax+')) or (isinstance(flags, int) and flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT | os.O_TRUNC))
            if writing and not Path(os.fsdecode(args[0])).absolute().is_relative_to(fixture):
                raise AssertionError('Write outside synthetic fixture refused')
        if event in {'os.mkdir', 'os.remove', 'os.rmdir', 'os.chmod'}:
            if not Path(os.fsdecode(args[0])).absolute().is_relative_to(fixture):
                raise AssertionError('Filesystem mutation outside fixture refused')
        if event in {'os.rename', 'os.replace'}:
            if any(not Path(os.fsdecode(p)).absolute().is_relative_to(fixture) for p in args[:2]):
                raise AssertionError('Move outside fixture refused')
    sys.addaudithook(audit)
    root = fixture / 'project'
    root.mkdir()
    for name in ['native', 'assets', 'iocs', 'docs', 'xapr', 'native/backups', 'native/.archive', 'out', 'findings']:
        (root / name).mkdir(parents=True, exist_ok=True)
    (root / 'CMakeLists.txt').write_text('project(fixture)\n')
    (root / 'native/main.cpp').write_text('int main() { return 0; }\n')
    (root / 'docs/guide.md').write_text('Fixture guide.\n')
    (root / 'xapr/config.json').write_text('{"fixture":true}\n')
    for name in ['native/backups/old.cpp', 'native/.archive/old.cpp', 'out/private.txt', 'findings/private.json']:
        (root / name).write_text('must not be backed up\n')
    first = capture(root)
    inventory = load_snapshot(first)
    assert len(inventory['files']) == 4
    assert 'xapr/config.json' in inventory['files']
    assert 'docs/guide.md' in inventory['files']
    assert not any('private' in name or 'old.cpp' in name for name in inventory['files'])
    objects_before = sorted(p for p in (root / 'backups/source/objects').rglob('*') if p.is_file())
    second = capture(root)
    assert first == second
    assert sorted(p for p in (root / 'backups/source/objects').rglob('*') if p.is_file()) == objects_before
    (root / 'native/main.cpp').write_text('int main() { return 1; }\n')
    third = capture(root)
    record = load_snapshot(third)
    assert record['changes']['modified'] == ['native/main.cpp']
    assert len([p for p in (root / 'backups/source/objects').rglob('*') if p.is_file()]) == len(objects_before) + 1
    assert 'native/main.cpp' in third.with_suffix('.changes.txt').read_text()
    (root / 'native/main.cpp').unlink()
    fourth = capture(root)
    assert load_snapshot(fourth)['changes']['deleted'] == ['native/main.cpp']
    restored = fixture / 'restored'
    restore_snapshot(first, restored)
    assert (restored / 'native/main.cpp').read_text() == 'int main() { return 0; }\n'
    assert (restored / 'xapr/config.json').read_text() == '{"fixture":true}\n'
    build = root / 'out/candidate'
    build.mkdir()
    exe = build / 'fixture.exe'
    exe.write_bytes(b'synthetic build output')
    write_state(build, 'in_progress')
    receipt = complete(root, build, fourth, {'fixture': True}, [exe])
    assert receipt['status'] == 'success' and receipt['source_tree_sha256'] == load_snapshot(fourth)['tree_sha256']
    write_state(build, 'in_progress')
    assert json.loads((build / 'build-receipt.json').read_text())['status'] == 'in_progress'
    (root / 'native/new.cpp').write_text('new source during build')
    try:
        complete(root, build, fourth, {'fixture': True}, [exe])
    except ValueError:
        pass
    else:
        raise AssertionError('Source drift accepted')
    write_state(build, 'failed')
    assert json.loads((build / 'build-receipt.json').read_text())['status'] == 'failed'
    damaged = object_path(root / 'backups/source', inventory['files']['native/main.cpp'])
    damaged.write_bytes(b'corrupt object')
    destination = fixture / 'must-not-restore'
    try:
        restore_snapshot(first, destination)
    except ValueError:
        pass
    else:
        raise AssertionError('Corrupt object accepted')
    assert not destination.exists()
    assert list(native_inputs(root))
    print('PASS: incremental reuse/change/delete/recovery, exclusions/private inputs, corruption, source drift and receipt invalidation fixtures')


if __name__ == '__main__':
    main()

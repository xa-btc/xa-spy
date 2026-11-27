"""XA Spy native build inventory, incremental recovery, and source-bound receipts.

Only native build inputs are selected; the unrelated retained upstream scanner is
not a runtime dependency. This module never invokes a compiler or scans evidence.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path

from .backup import create_project_backup
from .source_backup import atomic_write, file_hash, load_snapshot, safe_path, selected_files


ROOT_FILES = frozenset({
    'CMakeLists.txt', '1. build.py', 'AGENTS.md', 'README.md', 'PRIVACY.md',
    'CHANGELOG.md', 'LICENSE', 'NOTICE', '.gitignore', '.gitattributes',
})
SOURCE_DIRS = ('native', 'assets', 'iocs', 'build_support', 'tools', 'docs', 'xapr')
EXCLUDED_DIRS = frozenset({
    'backups', '.archive', 'out', 'findings', '.git', '__pycache__', '.pytest_cache',
    'node_modules', '.venv', 'bin', 'obj', 'previous releases',
})
EXCLUDED_SUFFIXES = frozenset({'.pyc', '.pyo', '.log', '.db', '.sqlite', '.db-wal', '.db-shm'})


def native_inputs(root):
    root = safe_path(root)
    for name in sorted(ROOT_FILES):
        path = safe_path(root / name)
        if path.exists():
            if not path.is_file():
                raise ValueError('Native input must be a regular file: ' + str(path))
            yield name, path
    for folder in SOURCE_DIRS:
        start = safe_path(root / folder)
        if not start.exists():
            continue
        if not start.is_dir():
            raise ValueError('Native input directory is not a directory: ' + str(start))
        def fail(error):
            raise error
        for directory, dirs, files in os.walk(start, followlinks=False, onerror=fail):
            dirs[:] = sorted(name for name in dirs if name.casefold() not in EXCLUDED_DIRS)
            for name in dirs:
                safe_path(Path(directory) / name)
            for name in sorted(files):
                path = safe_path(Path(directory) / name)
                # xapr contains exact private protection inputs; keep those recoverable.
                if folder != 'xapr' and (path.suffix.casefold() in EXCLUDED_SUFFIXES or name == '.env'):
                    continue
                if not path.is_file():
                    raise ValueError('Native input must be a regular file: ' + str(path))
                yield path.relative_to(root).as_posix(), path


def capture(root):
    return create_project_backup(root, 'XA Spy', file_selector=native_inputs)


def stable_inventory(root, snapshot):
    record = load_snapshot(snapshot)
    current = {name: file_hash(path) for name, path in selected_files(root, native_inputs)}
    if current != record['files']:
        raise ValueError('Native inputs changed after snapshot; build success was not recorded. Rebuild stable sources.')
    return record


def write_state(build, status, **values):
    if status not in {'in_progress', 'failed', 'success'}:
        raise ValueError('Unknown build receipt status')
    build = safe_path(build)
    build.mkdir(parents=True, exist_ok=True)
    record = {'schema': 'xa-spy.build/v1', 'status': status,
              'updated_utc': datetime.now(timezone.utc).isoformat(), **values}
    atomic_write(safe_path(build / 'build-receipt.json'),
                 (json.dumps(record, indent=2, sort_keys=True) + '\n').encode('utf-8'))
    return record


def complete(root, build, snapshot, configuration, outputs):
    record = stable_inventory(root, snapshot)
    hashes = {}
    build = safe_path(build)
    for output in outputs:
        path = safe_path(output)
        relative = path.relative_to(build).as_posix()
        if not path.is_file() or not path.stat().st_size:
            raise ValueError('Required native build output missing: ' + str(path))
        hashes[relative] = file_hash(path)
    # A second inventory check brackets output hashing and catches edits during it.
    stable_inventory(root, snapshot)
    return write_state(build, 'success', source_tree_sha256=record['tree_sha256'],
                       snapshot=snapshot.relative_to(root).as_posix(),
                       configuration=configuration, outputs=hashes)

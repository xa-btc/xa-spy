"""Private, incremental source history and verified recovery; never runs a build.

Updated 2026-10-27: incremental snapshots include a compact source-only change index.
Keep this entire store together when moving it; snapshots reference shared objects.
SETUP: Keep beside backup.py, source_changes.py and console_status.py in the selected
support package. No PLACEHOLDER is required. Run recovery with -m <package>.source_backup.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import time
from uuid import uuid4

from .console_status import print_status as print
from .source_changes import analyze_change, is_source


EXCLUDED_DIRS = frozenset({
    'docs', 'backups', '.archive', 'bin', 'obj', 'artifacts', '.git', '.vs', '.vscode',
    '.codex', '.claude', '.agents', '.windsurf', '__pycache__', 'dual_builds',
    'previous releases', 'plugin references', 'testresults', 'current functions',
    'function history', 'errors', 'build', 'build_protection', 'backup',
    '.venv', 'venv', 'node_modules', '.pytest_cache',
})
EXCLUDED_SUFFIXES = frozenset({
    '.db', '.db-wal', '.db-shm', '.sqlite', '.sqlite-wal', '.sqlite-shm',
    '.log', '.pyc', '.cache', '.user', '.suo',
})
DIGEST = re.compile(r'[0-9a-f]{64}')
SNAPSHOT_NAME = re.compile(r'\d{8}T\d{12}Z-[0-9a-f]{32}\.json')


def safe_path(path: Path) -> Path:
    """Reject links/reparse points in all existing ancestors, including broken links."""
    path = Path(os.path.abspath(path))
    for part in reversed((path, *path.parents)):
        try:
            info = part.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info, 'st_file_attributes', 0) & 0x400:
            raise ValueError(f'Source backup encountered a link/reparse point: {part}')
    return path


def require_active_project(root: Path) -> None:
    """Refuse workflow use of project copies stored as backups or archives."""
    root = safe_path(root)
    if any(parent.name.casefold() in {'.archive', 'backups'} for parent in (root, *root.parents)):
        raise ValueError('Run the workflow from the active project, not a backup or .archive copy')


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b''):
            digest.update(block)
    return digest.hexdigest()


def retry_hash(path: Path) -> str:
    """Keep bounded read retries for both changed and unchanged backup inputs."""
    for attempt in range(5):
        try:
            return file_hash(path)
        except PermissionError as error:
            if attempt == 4:
                raise PermissionError(error.errno, 'Backup read failed after 5 attempts; '
                                      f'build refused: {path}', str(path)) from error
            delay = 0.25 * (2 ** attempt)
            print(f'  [RETRY] Backup access denied for {path}; '
                  f'retrying in {delay:g}s ({attempt + 2}/5).', flush=True)
            time.sleep(delay)
    raise AssertionError('Backup hash retry loop did not return or raise')


def source_files(root: Path):
    """Preserve the former backup scope, including ignored private xapr inputs."""
    require_active_project(root)
    def walk_error(error):
        raise error

    for directory, dirs, files in os.walk(root, followlinks=False, onerror=walk_error):
        dirs[:] = sorted(name for name in dirs if name.casefold() not in EXCLUDED_DIRS
                         and not name.casefold().lstrip('.').startswith('github_release'))
        for name in dirs + files:
            safe_path(Path(directory) / name)
        for name in sorted(files):
            path = Path(directory) / name
            if path.suffix.lower() not in EXCLUDED_SUFFIXES:
                if not path.is_file():
                    raise ValueError(f'Backup input is not a regular file: {path}')
                yield path.relative_to(root).as_posix(), path


def tree_hash(files: dict) -> str:
    return hashlib.sha256(json.dumps(files, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def object_path(store: Path, digest: str) -> Path:
    if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
        raise ValueError('Invalid backup object digest')
    return safe_path(store / 'objects' / digest[:2] / digest[2:])


def validate_name(name: str) -> None:
    parts = PurePosixPath(name).parts
    if (not name or not parts or PurePosixPath(name).is_absolute()
            or PurePosixPath(name).as_posix() != name
            or any(part in ('.', '..') or part.endswith((' ', '.'))
                   or any(char in part for char in '\\:<>"|?*')
                   or any(ord(char) < 32 for char in part)
                   or part.split('.')[0].upper() in {'CON', 'PRN', 'AUX', 'NUL',
                                                       *(f'COM{i}' for i in range(1, 10)),
                                                       *(f'LPT{i}' for i in range(1, 10))}
                   for part in parts)):
        raise ValueError(f'Invalid backup file name: {name!r}')


def load_snapshot(snapshot: Path) -> dict:
    record = json.loads(safe_path(snapshot).read_text(encoding='utf-8'))
    if (not isinstance(record, dict) or record.get('schema_version') != 1
            or not isinstance(record.get('files'), dict)):
        raise ValueError('Invalid source backup snapshot')
    seen = set()
    for name, digest in record['files'].items():
        validate_name(name)
        if name.casefold() in seen:
            raise ValueError('Backup contains colliding file names')
        seen.add(name.casefold())
        if not isinstance(digest, str) or not DIGEST.fullmatch(digest):
            raise ValueError('Invalid backup object digest')
    if record.get('tree_sha256') != tree_hash(record['files']):
        raise ValueError('Source backup manifest verification failed')
    return record


def atomic_write(path: Path, data: bytes) -> None:
    safe_path(path)
    temporary = path.with_name('.' + path.name + '-' + uuid4().hex + '.tmp')
    try:
        with temporary.open('xb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        safe_path(path)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


@contextmanager
def backup_lock(store: Path):
    lock = safe_path(store / '.lock')
    try:
        stream = lock.open('x', encoding='utf-8')
    except FileExistsError as error:
        raise ValueError(f'Backup is locked: {lock}. If an earlier run stopped, confirm it '
                         'has exited before removing this lock file.') from error
    try:
        with stream:
            stream.write(f'pid={os.getpid()} utc={datetime.now(timezone.utc).isoformat()}\n')
        yield
    finally:
        lock.unlink()


def write_change_index(store: Path, snapshot: Path, record: dict, previous: dict) -> None:
    """Summarize immutable saved code bytes; never put a full diff in the backup."""
    lines = ['Source changes', f'Snapshot: {snapshot.name}',
             f'Previous: {record["parent"] or "none (initial baseline)"}',
             'Lines are 1-based: old = previous snapshot, new = this snapshot.',
             'Object paths are relative to this index. Function names are a navigation aid.', '']
    if record['parent'] is None:
        count = sum(is_source(name) for name in record['files'])
        lines.append(f'Baseline: {count} source-code files; no previous version to compare.')
    else:
        changes = [(status, name) for kind, status in
                   (('added', 'A'), ('modified', 'M'), ('deleted', 'D'))
                   for name in record['changes'][kind] if is_source(name)]
        changes.sort(key=lambda item: item[1])
        lines.append(f'{len(changes)} source-code files changed. Documentation and data files excluded.')
        # Large imports stay navigable without dumping an entire function inventory.
        for status, name in changes[:200]:
            contents, references = [], []
            for files in (previous, record['files']):
                digest = files.get(name)
                if digest is None:
                    contents.append(None)
                    references.append('-')
                    continue
                path = object_path(store, digest)
                if retry_hash(path) != digest:
                    raise ValueError(f'Change-index object verification failed: {path}')
                with path.open('rb') as stream:
                    contents.append(stream.read(2 * 1024 * 1024 + 1))
                references.append('../' + path.relative_to(store).as_posix())
            lines.append(f'{status} {name} | {analyze_change(name, *contents)}')
            lines.append(f'  old: {references[0]} | new: {references[1]}')
        if len(changes) > 200:
            lines.append(f'{len(changes) - 200} more source files not expanded; see manifest changes lists.')
    atomic_write(snapshot.with_suffix('.changes.txt'), ('\n'.join(lines) + '\n').encode('utf-8'))


def selected_files(root: Path, file_selector=None):
    """Validate a workflow's exact selection or use the default backup inventory."""
    seen = set()
    for name, path in (file_selector or source_files)(root):
        validate_name(name)
        if '.archive' in (part.casefold() for part in PurePosixPath(name).parts):
            raise ValueError('Archived files cannot be selected as current backup inputs')
        if name.casefold() in seen:
            raise ValueError('Backup input names collide')
        seen.add(name.casefold())
        path = safe_path(path)
        if path != root.joinpath(*PurePosixPath(name).parts) or not path.is_file():
            raise ValueError('Backup selection must name regular files inside the source root')
        yield name, path


def save_snapshot(root: Path, store: Path, copy_verified, *, file_selector=None) -> tuple[Path, dict]:
    """Write new contents before publishing a complete manifest and latest pointer."""
    root, store = safe_path(root), safe_path(store)
    require_active_project(root)
    store.mkdir(parents=True, exist_ok=True)
    snapshots = safe_path(store / 'snapshots')
    snapshots.mkdir(exist_ok=True)
    with backup_lock(store):
        latest = safe_path(store / 'LATEST')
        previous_path = None
        previous = {}
        if latest.exists():
            name = latest.read_text(encoding='utf-8').strip()
            if not SNAPSHOT_NAME.fullmatch(name):
                raise ValueError('Invalid latest source backup pointer')
            previous_path = snapshots / name
            previous = load_snapshot(previous_path)['files']
        inventory = {}
        verified = set()
        new_objects = new_bytes = 0
        for name, source in selected_files(root, file_selector):
            validate_name(name)
            digest = retry_hash(source)
            target = object_path(store, digest)
            if digest not in verified:
                if target.exists():
                    if not target.is_file() or retry_hash(target) != digest:
                        raise ValueError(f'Backup object verification failed: {target}')
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    temporary = target.with_name('.object-' + uuid4().hex + '.tmp')
                    try:
                        copied = copy_verified(source, temporary)
                        if copied != digest:
                            raise ValueError(f'Source changed during backup: {source}')
                        # copy2 can preserve a read-only source attribute. Objects are
                        # byte stores; Windows _commit requires a writable descriptor.
                        temporary.chmod(temporary.stat().st_mode | stat.S_IWRITE)
                        with temporary.open('r+b') as stream:
                            os.fsync(stream.fileno())
                        safe_path(target)
                        os.replace(temporary, target)
                        new_objects += 1
                        new_bytes += target.stat().st_size
                    finally:
                        temporary.unlink(missing_ok=True)
                verified.add(digest)
            inventory[name] = digest
        # Detect edits/additions/removals during capture; no partial success pointer.
        if inventory != {name: retry_hash(path) for name, path in selected_files(root, file_selector)}:
            raise ValueError('Source changed during backup; snapshot was not committed')
        added = sorted(set(inventory) - set(previous))
        removed = sorted(set(previous) - set(inventory))
        changed = sorted(name for name in inventory.keys() & previous.keys()
                         if inventory[name] != previous[name])
        stats = {'added': len(added), 'changed': len(changed), 'removed': len(removed),
                 'unchanged': len(inventory) - len(added) - len(changed),
                 'new_objects': new_objects, 'new_bytes': new_bytes}
        if previous_path is not None and inventory == previous:
            return previous_path, stats
        snapshot = snapshots / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
                                + '-' + uuid4().hex + '.json')
        record = {'schema_version': 1, 'created_utc': datetime.now(timezone.utc).isoformat(),
                  'parent': previous_path.name if previous_path else None,
                  'tree_sha256': tree_hash(inventory), 'files': inventory,
                  'change_index': snapshot.with_suffix('.changes.txt').name,
                  'changes': {'added': added, 'modified': changed, 'deleted': removed}}
        # Reuse the same validator as recovery before advertising a successful snapshot.
        atomic_write(snapshot, (json.dumps(record, indent=2, sort_keys=True) + '\n').encode())
        load_snapshot(snapshot)
        write_change_index(store, snapshot, record, previous)
        atomic_write(latest, (snapshot.name + '\n').encode())
        return snapshot, stats


def restore_snapshot(snapshot: Path, destination: Path) -> Path:
    """Restore to a new directory only; verify all objects before creating output."""
    snapshot, destination = safe_path(snapshot), safe_path(destination)
    if snapshot.parent.name != 'snapshots':
        raise ValueError('Select a JSON manifest in backups/source/snapshots')
    store = snapshot.parent.parent
    if destination.exists() or destination.is_relative_to(store):
        raise ValueError('Recovery requires a new destination outside the backup store')
    if not destination.parent.is_dir():
        raise ValueError('Recovery destination parent must already exist')
    record = load_snapshot(snapshot)
    for digest in set(record['files'].values()):
        path = object_path(store, digest)
        if file_hash(path) != digest:
            raise ValueError(f'Backup object verification failed: {path}')
    staging = destination.with_name('.' + destination.name + '.restore-' + uuid4().hex)
    staging.mkdir()
    try:
        for name, digest in record['files'].items():
            target = staging / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(object_path(store, digest), target)
            if file_hash(target) != digest:
                raise ValueError(f'Restored file verification failed: {name}')
        safe_path(destination)
        # Windows rename refuses an occupied destination; do not replace any existing tree.
        if destination.exists():
            raise ValueError('Recovery destination became occupied')
        staging.rename(destination)
    finally:
        if staging.exists():
            safe_path(staging)
            shutil.rmtree(staging)
    return destination


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, required=True,
                        help='Snapshot JSON under backups/source/snapshots')
    parser.add_argument('--destination', type=Path, required=True,
                        help='New, nonexistent recovery folder (never the active checkout)')
    args = parser.parse_args(argv)
    result = restore_snapshot(args.snapshot, args.destination)
    print(f'[OK] Verified source restored to {result}')
    print('Documentation is retained separately in backups/docs/.')
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

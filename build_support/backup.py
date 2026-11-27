"""
Incremental source snapshots, compact source change indexes and shared docs backup.

SETUP: Keep this file with source_backup.py, source_changes.py and console_status.py.
The selected support package is build_support/ or xapr/. Stage 1 imports
it; do not run it separately. Python 3.11+ is required for hashlib.file_digest.
No PLACEHOLDER replacement or project-specific configuration is required.
The caller supplies the project root and solution name. Optional docs/ is
backed up when present; absent docs/ requires no setting. Source snapshots
include configuration such as xapr/ while generated output is excluded.
Last Updated: 2026-10-27
Template v1.02 - store each distinct source content once; unchanged runs reuse a snapshot.
"""

from .console_status import print_status as print
from .source_backup import save_snapshot, safe_path, require_active_project
import hashlib
import json
import os
import shutil
import time
from datetime import datetime
from pathlib import Path
from uuid import uuid4

def sha256(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()

def copy_verified_backup_file(source: Path, destination: Path) -> str:
    """Retry temporary access denial without accepting changed or unverified bytes."""
    before = None
    attempts = 5
    for attempt in range(attempts):
        try:
            # Keep the first readable source hash even if copy/verification needs a retry.
            if before is None:
                before = sha256(source)
            shutil.copy2(source, destination)
            if sha256(destination) != before or sha256(source) != before:
                raise ValueError(f'Source changed or backup verification failed; build refused: {source}')
            return before
        except PermissionError as error:
            if attempt == attempts - 1:
                raise PermissionError(
                    error.errno,
                    f'Backup access failed after {attempts} attempts; build refused. '
                    f'Source: {source}; destination: {destination}. {error.strerror or error}',
                    error.filename or str(destination),
                ) from error
            delay = 0.25 * (2 ** attempt)
            print(f'  [RETRY] Backup access denied for {error.filename or source}; '
                  f'retrying in {delay:g}s ({attempt + 2}/{attempts}).', flush=True)
            time.sleep(delay)
    raise AssertionError('Backup retry loop did not return or raise')

def update_docs_backup(root: Path, backup_root: Path) -> None:
    """Copy new/changed documents to one plain folder; retain older missing files."""
    source_root = root / 'docs'
    target_root = backup_root / 'docs'
    def reject_link(path):
        safe_path(path)  # Includes Windows reparse points on Python 3.11.
    reject_link(backup_root)
    reject_link(source_root)
    reject_link(target_root)
    if not source_root.exists():
        return
    target_root.mkdir(exist_ok=True)
    updated = unchanged = 0
    def walk_error(error):
        raise error
    for directory, dirs, files in os.walk(source_root, followlinks=False, onerror=walk_error):
        dirs[:] = [name for name in dirs if name.casefold() not in {'backups', '.archive', '__pycache__', '.git', 'bin', 'obj'}]
        for name in dirs + files:
            reject_link(Path(directory) / name)
        relative = Path(directory).relative_to(source_root)
        destination_dir = target_root
        for part in relative.parts:
            destination_dir /= part
            reject_link(destination_dir)
            destination_dir.mkdir(exist_ok=True)
        for name in files:
            source = Path(directory) / name
            destination = destination_dir / name
            reject_link(destination)
            if destination.is_file() and sha256(source) == sha256(destination):
                unchanged += 1
                continue
            temporary = destination_dir / f'.docs-{uuid4().hex}.tmp'
            try:
                copy_verified_backup_file(source, temporary)
                reject_link(destination)
                os.replace(temporary, destination)
                updated += 1
            finally:
                temporary.unlink(missing_ok=True)
    print(f'  [OK] Docs backup: backups/docs/ ({updated} new/updated, {unchanged} unchanged).', flush=True)

def create_project_backup(root: Path, name: str = '', *, store: Path | None = None,
                          file_selector=None) -> Path:
    """Capture changed contents only; return the complete recoverable snapshot manifest."""
    root = safe_path(root).resolve(strict=True)
    require_active_project(root)
    store = safe_path(store or root / 'backups/source')
    backup_root = safe_path(store.parent)
    backup_root.mkdir(parents=True, exist_ok=True)
    update_docs_backup(root, backup_root)
    snapshot, stats = save_snapshot(root, store, copy_verified_backup_file,
                                    file_selector=file_selector)
    location = store.relative_to(root).as_posix() if store.is_relative_to(root) else str(store)
    print(f'  [OK] Source backup: {location}/ ({stats["added"]} new, '
          f'{stats["changed"]} updated, {stats["removed"]} deleted, '
          f'{stats["unchanged"]} unchanged).', flush=True)
    print(f'  [OK] Stored {stats["new_objects"]} new file contents '
          f'({stats["new_bytes"] / (1024 * 1024):.2f} MiB); snapshot: {snapshot.name}', flush=True)
    return snapshot

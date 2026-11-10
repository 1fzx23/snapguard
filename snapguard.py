#!/usr/bin/env python3
"""
SnapGuard — Directory snapshot, change detection & integrity guard.

A small, dependency-light CLI tool that creates immutable snapshots of a
directory tree, compares snapshots to detect added/removed/modified/renamed
files, verifies file integrity by re-hashing, and optionally watches for
real-time changes.

Core functionality uses only the Python standard library. If `watchdog`
is installed, the `watch` command will use the OS-native filesystem events;
otherwise it falls back to a polite polling mode.

Usage examples:
    python snapguard.py init .
    python snapguard.py snap --label "before-update"
    python snapguard.py list
    python snapguard.py diff latest
    python snapguard.py verify latest
    python snapguard.py watch --interval 2
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import os
import re
import shutil
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__version__ = "1.0.0"

DEFAULT_STORE = ".snapguard"
CHUNK_SIZE = 1024 * 1024  # 1 MiB read buffer for hashing


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass(frozen=True, slots=True)
class FileEntry:
    """Immutable record for a single file in a snapshot."""
    path: str          # relative POSIX-style path
    size: int
    mtime: float
    sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {"path": self.path, "size": self.size, "mtime": self.mtime, "sha256": self.sha256}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FileEntry":
        return cls(path=data["path"], size=int(data["size"]), mtime=float(data["mtime"]), sha256=data["sha256"])


@dataclass
class Snapshot:
    """A complete snapshot of a directory tree."""
    id: str                      # timestamp-based id, e.g. 20260831-181000-123
    created_at: str              # ISO-8601 UTC string
    label: str
    root: str                    # absolute path of the snapshotted directory
    entries: dict[str, FileEntry] = field(default_factory=dict)  # keyed by relative path
    format_version: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "created_at": self.created_at,
            "label": self.label,
            "root": self.root,
            "format_version": self.format_version,
            "entries": [e.to_dict() for e in self.entries.values()],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Snapshot":
        snap = cls(
            id=data["id"],
            created_at=data["created_at"],
            label=data.get("label", ""),
            root=data["root"],
            format_version=data.get("format_version", 1),
        )
        snap.entries = {e["path"]: FileEntry.from_dict(e) for e in data["entries"]}
        return snap


@dataclass
class ChangeReport:
    """Result of comparing a snapshot against the live tree."""
    added: list[FileEntry] = field(default_factory=list)
    removed: list[FileEntry] = field(default_factory=list)
    modified: list[tuple[FileEntry, FileEntry]] = field(default_factory=list)  # (old, new)
    renamed: list[tuple[FileEntry, FileEntry]] = field(default_factory=list)  # (old_path, new_entry)

    @property
    def total(self) -> int:
        return len(self.added) + len(self.removed) + len(self.modified) + len(self.renamed)

    def summary(self) -> str:
        parts = []
        if self.added:
            parts.append(f"+{len(self.added)} added")
        if self.removed:
            parts.append(f"-{len(self.removed)} removed")
        if self.modified:
            parts.append(f"~{len(self.modified)} modified")
        if self.renamed:
            parts.append(f"→{len(self.renamed)} renamed")
        return ", ".join(parts) if parts else "no changes"


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def _now_id() -> str:
    """Generate a sortable snapshot id from the current UTC time."""
    now = datetime.datetime.now(datetime.timezone.utc)
    return now.strftime("%Y%m%d-%H%M%S-") + f"{now.microsecond // 1000:03d}"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _posix_path(path: Path) -> str:
    """Return a POSIX-style relative path regardless of host OS."""
    return path.as_posix()


def _hash_file(path: Path) -> str:
    """Compute SHA-256 hex digest of a file with streaming reads."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()


def _find_store(root: Path) -> Path | None:
    """Locate the nearest SnapGuard store directory walking upward."""
    cur = root.resolve()
    while True:
        candidate = cur / DEFAULT_STORE
        if candidate.is_dir():
            return candidate
        parent = cur.parent
        if parent == cur:
            return None
        cur = parent


def _human_size(size: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if abs(size) < 1024:
            return f"{size:.1f} {unit}" if unit != "B" else f"{size} B"
        size /= 1024.0
    return f"{size:.1f} PiB"


def _short_hash(h: str) -> str:
    return h[:12]


# ---------------------------------------------------------------------------
# Snapshot core
# ---------------------------------------------------------------------------

def create_snapshot(root: Path, label: str = "", *, excludes: list[str] | None = None) -> Snapshot:
    """Walk `root` and build a Snapshot, skipping SnapGuard's own store."""
    snap = Snapshot(id=_now_id(), created_at=_now_iso(), label=label, root=str(root.resolve()))
    exclude_patterns = [re.compile(p) for p in (excludes or [])]

    for dirpath, dirnames, filenames in os.walk(root):
        dirpath_p = Path(dirpath).resolve()

        # Never descend into the SnapGuard store itself.
        if dirpath_p.name == DEFAULT_STORE:
            dirnames[:] = []
            continue

        # Apply exclude patterns to directories.
        dirnames[:] = [
            d for d in dirnames
            if not any(p.match(d) or p.match(f"{dirpath_p.name}/{d}") for p in exclude_patterns)
        ]

        for filename in filenames:
            file_path = dirpath_p / filename
            try:
                rel = _posix_path(file_path.relative_to(root))
            except ValueError:
                # Should not happen because os.walk starts from root, but stay safe.
                continue

            if any(p.match(rel) or p.match(filename) for p in exclude_patterns):
                continue

            stat = file_path.lstat()
            # Only regular files get hashed; skip symlinks and special files to avoid surprises.
            if not stat.st_mode & 0o100000:
                continue

            try:
                sha = _hash_file(file_path)
            except (OSError, PermissionError):
                # Report hash failures as empty so verification can catch them later.
                sha = ""

            snap.entries[rel] = FileEntry(
                path=rel,
                size=stat.st_size,
                mtime=stat.st_mtime,
                sha256=sha,
            )

    return snap


def save_snapshot(store: Path, snap: Snapshot) -> Path:
    """Persist a snapshot to disk and return its path."""
    snapshots_dir = store / "snapshots"
    snapshots_dir.mkdir(parents=True, exist_ok=True)
    path = snapshots_dir / f"{snap.id}.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(snap.to_dict(), f, indent=2, ensure_ascii=False)
        f.write("\n")
    return path


def load_snapshot(store: Path, snap_id: str) -> Snapshot:
    """Load a snapshot by id, accepting 'latest' as a magic alias."""
    if snap_id == "latest":
        snaps = list_snapshots(store)
        if not snaps:
            raise SnapGuardError("No snapshots found; create one with `snapguard snap`.")
        snap_id = snaps[-1].id

    path = store / "snapshots" / f"{snap_id}.json"
    if not path.exists():
        raise SnapGuardError(f"Snapshot not found: {snap_id}")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return Snapshot.from_dict(data)


def list_snapshots(store: Path) -> list[Snapshot]:
    """Return snapshots sorted chronologically."""
    snapshots_dir = store / "snapshots"
    if not snapshots_dir.exists():
        return []
    snaps: list[Snapshot] = []
    for p in snapshots_dir.glob("*.json"):
        try:
            with open(p, "r", encoding="utf-8") as f:
                snaps.append(Snapshot.from_dict(json.load(f)))
        except (json.JSONDecodeError, KeyError):
            # Ignore corrupt snapshot files silently.
            continue
    return sorted(snaps, key=lambda s: s.created_at)


# ---------------------------------------------------------------------------
# Diff & verify
# ---------------------------------------------------------------------------

def diff_snapshot(root: Path, snap: Snapshot) -> ChangeReport:
    """Compare the live tree against a stored snapshot and detect changes."""
    current = create_snapshot(root, "__diff__")
    report = ChangeReport()

    old_paths = set(snap.entries.keys())
    new_paths = set(current.entries.keys())

    added_paths = new_paths - old_paths
    removed_paths = old_paths - new_paths
    common_paths = old_paths & new_paths

    # Detect renames: a removed file whose hash now appears under a new path.
    removed_by_hash: dict[str, list[FileEntry]] = defaultdict(list)
    for rp in removed_paths:
        entry = snap.entries[rp]
        if entry.sha256:
            removed_by_hash[entry.sha256].append(entry)

    matched_new: set[str] = set()
    for np in sorted(added_paths):
        new_entry = current.entries[np]
        candidates = removed_by_hash.get(new_entry.sha256, [])
        if candidates:
            old_entry = candidates.pop(0)
            report.renamed.append((old_entry, new_entry))
            matched_new.add(np)
            removed_paths.discard(old_entry.path)

    # Remaining added paths that were not renames.
    for np in sorted(added_paths - matched_new):
        report.added.append(current.entries[np])

    # Remaining removed paths.
    for rp in sorted(removed_paths):
        report.removed.append(snap.entries[rp])

    # Common paths: compare hash first, then mtime/size as metadata hints.
    for cp in sorted(common_paths):
        old = snap.entries[cp]
        new = current.entries[cp]
        if old.sha256 != new.sha256:
            report.modified.append((old, new))
        elif old.size != new.size or abs(old.mtime - new.mtime) > 1e-9:
            # Same hash but metadata drift; treat as metadata change.
            report.modified.append((old, new))

    return report


def verify_snapshot(root: Path, snap: Snapshot) -> list[tuple[str, str, str | None]]:
    """
    Re-hash every file in the snapshot and report mismatches.
    Returns a list of (path, expected_hash, actual_hash | None) where None means missing.
    """
    mismatches: list[tuple[str, str, str | None]] = []
    for rel in sorted(snap.entries):
        entry = snap.entries[rel]
        file_path = root / rel
        if not file_path.exists():
            mismatches.append((rel, entry.sha256, None))
            continue
        try:
            actual = _hash_file(file_path)
        except (OSError, PermissionError):
            mismatches.append((rel, entry.sha256, "ERROR"))
            continue
        if actual != entry.sha256:
            mismatches.append((rel, entry.sha256, actual))
    return mismatches


# ---------------------------------------------------------------------------
# Watch
# ---------------------------------------------------------------------------

class SnapGuardError(Exception):
    """User-facing runtime error."""


def _snapshot_state(root: Path, excludes: list[str] | None = None) -> dict[str, FileEntry]:
    snap = create_snapshot(root, "__watch__", excludes=excludes)
    return snap.entries


def _watch_poll(root: Path, interval: float, excludes: list[str] | None = None) -> None:
    """Polling-based watch implementation using only the standard library."""
    print(f"[watch] polling every {interval}s (stdlib mode). Press Ctrl+C to stop.")
    baseline = _snapshot_state(root, excludes)
    while True:
        time.sleep(interval)
        current = _snapshot_state(root, excludes)
        # Build a minimal diff on the fly.
        old_paths = set(baseline)
        new_paths = set(current)
        changed = False
        for p in sorted(new_paths - old_paths):
            e = current[p]
            print(f"[+] {p}  ({_human_size(e.size)}  {_short_hash(e.sha256)})")
            changed = True
        for p in sorted(old_paths - new_paths):
            print(f"[-] {p}")
            changed = True
        for p in sorted(old_paths & new_paths):
            if baseline[p].sha256 != current[p].sha256 or baseline[p].size != current[p].size:
                e = current[p]
                print(f"[~] {p}  ({_human_size(e.size)}  {_short_hash(e.sha256)})")
                changed = True
        if changed:
            print("-" * 40)
        baseline = current


def _watch_native(root: Path, excludes: list[str] | None = None) -> None:
    """Use watchdog for native filesystem events when available."""
    from watchdog.observers import Observer  # type: ignore[import]
    from watchdog.events import FileSystemEventHandler  # type: ignore[import]

    exclude_patterns = excludes or []

    class Handler(FileSystemEventHandler):
        def on_any_event(self, event):  # type: ignore[override]
            # Ignore events inside the SnapGuard store.
            if DEFAULT_STORE in event.src_path.split(os.sep):
                return
            for pat in exclude_patterns:
                if re.search(pat, event.src_path):
                    return
            if event.event_type == "modified" and getattr(event, "is_directory", False):
                return
            print(f"[{event.event_type:8}] {event.src_path}")

    handler = Handler()
    observer = Observer()
    observer.schedule(handler, str(root), recursive=True)
    observer.start()
    print(f"[watch] native filesystem events mode. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()


def watch_directory(root: Path, interval: float, excludes: list[str] | None = None) -> None:
    """Watch a directory for changes, preferring native events if watchdog is installed."""
    try:
        _watch_native(root, excludes)
    except ImportError:
        _watch_poll(root, interval, excludes)


# ---------------------------------------------------------------------------
# CLI helpers
# ---------------------------------------------------------------------------

def _get_store(args: argparse.Namespace) -> Path:
    """Resolve the SnapGuard store from explicit path, -C, or by walking upward."""
    if args.store:
        return Path(args.store).resolve()
    root = Path(args.dir).resolve()
    if args.command == "init":
        init_dir = getattr(args, "init_dir", None) or args.dir
        return Path(init_dir).resolve() / DEFAULT_STORE
    store = _find_store(root)
    if store is None:
        raise SnapGuardError(
            f"No SnapGuard store found. Run `snapguard init` first, or use -C to specify one."
        )
    return store


def _print_table(rows: list[list[str]]) -> None:
    if not rows:
        return
    widths = [max(len(r[i]) for r in rows) + 2 for i in range(len(rows[0]))]
    for r in rows:
        line = "".join(cell.ljust(widths[i]) for i, cell in enumerate(r))
        print(line.rstrip())


# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

def cmd_init(args: argparse.Namespace) -> int:
    store = _get_store(args)
    store.mkdir(parents=True, exist_ok=True)
    (store / "snapshots").mkdir(exist_ok=True)
    config = {"version": __version__, "excludes": []}
    config_path = store / "config.json"
    if not config_path.exists():
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
            f.write("\n")
    print(f"Initialized SnapGuard store at {store}")
    return 0


def cmd_snap(args: argparse.Namespace) -> int:
    store = _get_store(args)
    root = store.parent
    config = _load_config(store)
    excludes = config.get("excludes", []) + (args.exclude or [])
    snap = create_snapshot(root, args.label or "", excludes=excludes)
    path = save_snapshot(store, snap)
    total_size = sum(e.size for e in snap.entries.values())
    print(f"Created snapshot {snap.id}")
    print(f"  files:    {len(snap.entries)}")
    print(f"  size:     {_human_size(total_size)}")
    print(f"  root:     {root}")
    print(f"  saved:    {path}")
    return 0


def cmd_list(args: argparse.Namespace) -> int:
    store = _get_store(args)
    snaps = list_snapshots(store)
    if not snaps:
        print("No snapshots yet.")
        return 0
    rows = [["ID", "LABEL", "FILES", "SIZE", "CREATED"]]
    for s in snaps:
        total = sum(e.size for e in s.entries.values())
        rows.append([s.id, s.label or "-", str(len(s.entries)), _human_size(total), s.created_at])
    _print_table(rows)
    return 0


def cmd_diff(args: argparse.Namespace) -> int:
    store = _get_store(args)
    root = store.parent
    snap = load_snapshot(store, args.snapshot)
    report = diff_snapshot(root, snap)
    print(f"Diff against snapshot {snap.id} ({snap.label or 'no label'})")
    print(f"Changes: {report.summary()}")
    if report.total == 0:
        return 0

    for old, new in report.renamed:
        print(f"→ {old.path}  →  {new.path}  ({_short_hash(new.sha256)})")
    for e in report.added:
        print(f"+ {e.path}  ({_human_size(e.size)}  {_short_hash(e.sha256)})")
    for e in report.removed:
        print(f"- {e.path}  ({_human_size(e.size)}  {_short_hash(e.sha256)})")
    for old, new in report.modified:
        print(f"~ {old.path}  ({_human_size(old.size)} → {_human_size(new.size)}  {_short_hash(old.sha256)} → {_short_hash(new.sha256)})")

    return 1 if report.total else 0


def cmd_verify(args: argparse.Namespace) -> int:
    store = _get_store(args)
    root = store.parent
    snap = load_snapshot(store, args.snapshot)
    mismatches = verify_snapshot(root, snap)
    print(f"Verifying {len(snap.entries)} files against snapshot {snap.id} ...")
    if not mismatches:
        print("All files verified OK.")
        return 0
    print(f"Found {len(mismatches)} mismatch(es):")
    rows = [["PATH", "EXPECTED", "ACTUAL"]]
    for path, expected, actual in mismatches:
        rows.append([path, _short_hash(expected), _short_hash(actual) if actual else "MISSING"])
    _print_table(rows)
    return 1


def cmd_watch(args: argparse.Namespace) -> int:
    store = _get_store(args)
    root = store.parent
    config = _load_config(store)
    excludes = config.get("excludes", []) + (args.exclude or [])
    try:
        watch_directory(root, args.interval, excludes)
    except KeyboardInterrupt:
        print("\n[watch] stopped.")
    return 0


def cmd_prune(args: argparse.Namespace) -> int:
    store = _get_store(args)
    if args.keep < 0:
        raise SnapGuardError(f"--keep must be >= 0, got {args.keep}.")
    snaps = list_snapshots(store)
    if args.keep >= len(snaps):
        print(f"Nothing to prune ({len(snaps)} snapshot(s), keep={args.keep}).")
        return 0
    to_delete = snaps[:-args.keep] if args.keep > 0 else snaps
    for s in to_delete:
        path = store / "snapshots" / f"{s.id}.json"
        path.unlink()
        print(f"Deleted {path.name}")
    print(f"Pruned {len(to_delete)} snapshot(s), {len(snaps) - len(to_delete)} remaining.")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    store = _get_store(args)
    root = store.parent
    snaps = list_snapshots(store)
    if not snaps:
        print("No snapshots. Run `snapguard snap` to create one.")
        return 0
    latest = snaps[-1]
    report = diff_snapshot(root, latest)
    print(f"Latest snapshot: {latest.id} ({latest.label or 'no label'})")
    print(f"  created: {latest.created_at}")
    print(f"  files:   {len(latest.entries)}")
    print(f"  changes: {report.summary()}")
    return 1 if report.total else 0


def _load_config(store: Path) -> dict[str, Any]:
    config_path = store / "config.json"
    if not config_path.exists():
        return {}
    try:
        with open(config_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError:
        return {}


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="snapguard",
        description="Directory snapshot, change detection & integrity guard.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  snapguard init .
  snapguard snap --label "before-upgrade"
  snapguard list
  snapguard diff latest
  snapguard verify latest
  snapguard watch --interval 2
  snapguard status
""",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("-C", "--dir", default=".", help="directory to operate on (default: current)")
    parser.add_argument("--store", default=None, help="path to the SnapGuard store (default: auto-detect)")

    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="initialize a SnapGuard store")
    p_init.add_argument("init_dir", nargs="?", default=".", help="directory to initialize (default: current)")
    p_init.set_defaults(func=cmd_init)

    p_snap = sub.add_parser("snap", help="create a new snapshot")
    p_snap.add_argument("--label", "-l", default="", help="optional human-readable label")
    p_snap.add_argument("--exclude", "-x", action="append", help="glob/regex pattern to exclude")
    p_snap.set_defaults(func=cmd_snap)

    p_list = sub.add_parser("list", help="list stored snapshots")
    p_list.set_defaults(func=cmd_list)

    p_diff = sub.add_parser("diff", help="compare live tree against a snapshot")
    p_diff.add_argument("snapshot", help="snapshot id or 'latest'")
    p_diff.set_defaults(func=cmd_diff)

    p_verify = sub.add_parser("verify", help="re-hash files and compare against a snapshot")
    p_verify.add_argument("snapshot", help="snapshot id or 'latest'")
    p_verify.set_defaults(func=cmd_verify)

    p_watch = sub.add_parser("watch", help="watch for changes in real time")
    p_watch.add_argument("--interval", "-i", type=float, default=2.0, help="polling interval in seconds (default: 2)")
    p_watch.add_argument("--exclude", "-x", action="append", help="additional exclude pattern")
    p_watch.set_defaults(func=cmd_watch)

    p_prune = sub.add_parser("prune", help="delete old snapshots, keeping the most recent N")
    p_prune.add_argument("--keep", "-k", type=int, default=10, help="number of snapshots to keep (default: 10)")
    p_prune.set_defaults(func=cmd_prune)

    p_status = sub.add_parser("status", help="show status against the latest snapshot")
    p_status.set_defaults(func=cmd_status)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except SnapGuardError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130


if __name__ == "__main__":
    sys.exit(main())

"""
Smoke tests for SnapGuard.

Run with:
    python -m unittest test_snapguard.py
"""
import argparse
import os
import tempfile
import unittest
from pathlib import Path

import snapguard as sg


class TestSnapGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def _write(self, rel_path: str, content: str) -> Path:
        path = self.root / rel_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")
        return path

    def test_create_snapshot_hashes_content(self):
        self._write("hello.txt", "hello world")
        snap = sg.create_snapshot(self.root, "test")
        self.assertIn("hello.txt", snap.entries)
        entry = snap.entries["hello.txt"]
        self.assertEqual(entry.size, 11)
        self.assertEqual(entry.sha256, "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9")

    def test_snapshot_ignores_snapguard_store(self):
        store = self.root / ".snapguard"
        store.mkdir()
        (store / "config.json").write_text("{}", encoding="utf-8")
        self._write("real.txt", "real")
        snap = sg.create_snapshot(self.root, "test")
        self.assertIn("real.txt", snap.entries)
        self.assertNotIn(".snapguard/config.json", snap.entries)

    def test_diff_detects_added_and_removed(self):
        self._write("keep.txt", "keep")
        snap = sg.create_snapshot(self.root, "base")
        self._write("new.txt", "new")
        os.remove(self.root / "keep.txt")
        report = sg.diff_snapshot(self.root, snap)
        self.assertEqual(len(report.added), 1)
        self.assertEqual(report.added[0].path, "new.txt")
        self.assertEqual(len(report.removed), 1)
        self.assertEqual(report.removed[0].path, "keep.txt")

    def test_diff_detects_rename(self):
        self._write("old.txt", "stable-content")
        snap = sg.create_snapshot(self.root, "base")
        os.remove(self.root / "old.txt")
        self._write("new.txt", "stable-content")
        report = sg.diff_snapshot(self.root, snap)
        self.assertEqual(len(report.renamed), 1)
        old_entry, new_entry = report.renamed[0]
        self.assertEqual(old_entry.path, "old.txt")
        self.assertEqual(new_entry.path, "new.txt")
        self.assertEqual(len(report.added), 0)
        self.assertEqual(len(report.removed), 0)

    def test_verify_detects_corruption(self):
        self._write("data.txt", " pristine ")
        snap = sg.create_snapshot(self.root, "base")
        (self.root / "data.txt").write_text(" tampered ", encoding="utf-8")
        mismatches = sg.verify_snapshot(self.root, snap)
        self.assertEqual(len(mismatches), 1)
        path, expected, actual = mismatches[0]
        self.assertEqual(path, "data.txt")
        self.assertNotEqual(expected, actual)

    def test_save_and_load_roundtrip(self):
        self._write("a.txt", "a")
        snap = sg.create_snapshot(self.root, "roundtrip")
        store = self.root / ".snapguard"
        store.mkdir()
        path = sg.save_snapshot(store, snap)
        loaded = sg.load_snapshot(store, snap.id)
        self.assertEqual(loaded.id, snap.id)
        self.assertEqual(len(loaded.entries), len(snap.entries))
        self.assertEqual(loaded.entries["a.txt"].sha256, snap.entries["a.txt"].sha256)

    def test_load_latest_alias(self):
        store = self.root / ".snapguard"
        store.mkdir()
        self._write("file.txt", "v1")
        s1 = sg.create_snapshot(self.root, "first")
        sg.save_snapshot(store, s1)
        self._write("file.txt", "v2")
        s2 = sg.create_snapshot(self.root, "second")
        sg.save_snapshot(store, s2)
        loaded = sg.load_snapshot(store, "latest")
        self.assertEqual(loaded.id, s2.id)


    def test_prune_rejects_negative_keep(self):
        store = self.root / ".snapguard"
        (store / "snapshots").mkdir(parents=True)
        self._write("file.txt", "v1")
        snap = sg.create_snapshot(self.root, "first")
        sg.save_snapshot(store, snap)
        args = argparse.Namespace(store=str(store), dir=str(self.root), command="prune", keep=-1)
        with self.assertRaises(sg.SnapGuardError):
            sg.cmd_prune(args)
        self.assertTrue((store / "snapshots" / (snap.id + ".json")).exists())

    def test_prune_negative_keep_cli_exit_code(self):
        store = self.root / ".snapguard"
        (store / "snapshots").mkdir(parents=True)
        self._write("file.txt", "v1")
        snap = sg.create_snapshot(self.root, "first")
        sg.save_snapshot(store, snap)
        rc = sg.main(["--store", str(store), "prune", "--keep", "-1"])
        self.assertEqual(rc, 2)
        self.assertTrue((store / "snapshots" / (snap.id + ".json")).exists())

if __name__ == "__main__":
    unittest.main()

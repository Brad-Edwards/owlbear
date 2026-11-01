"""Integrity and repeatability checks; fixtures contain no executable programs."""

import copy
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest


spec = importlib.util.spec_from_file_location(
    "artifact", Path(__file__).resolve().parents[1] / "scripts/research-artifact.py")
artifact = importlib.util.module_from_spec(spec)
spec.loader.exec_module(artifact)


class ResearchArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.files = {}
        for name in artifact.REQUIRED:
            data = b"fixture\n"
            if name.endswith((".o", ".ko", ".so", ".bin")) or name in {
                "daemon/owlbeard", "game/owlbear-game"
            }:
                data = bytearray(64)
                data[:6] = b"\x7fELF\x02\x01"
                machine = 247 if name.endswith(".bpf.o") else 183
                data[18:20] = machine.to_bytes(2, "little")
                data = bytes(data)
            self.files[name] = (data, 0o644)
        identity = {"version": "1.2.3", "source_commit": "a" * 40}
        identity["build_id"] = artifact.digest(artifact.encoded({"build": identity, "inputs": {}}))
        self.manifest = {
            "schema": artifact.SCHEMA, "build": identity, "inputs": {},
            "files": {name: {"sha256": artifact.digest(data), "size": len(data), "mode": mode}
                      for name, (data, mode) in self.files.items()},
        }

    def archive(self, name="artifact.tar.gz"):
        files = dict(self.files, **{"manifest.json": (artifact.encoded(self.manifest), 0o644)})
        path = self.root / name
        artifact.write_archive(path, "owlbear-fixture", files, 1234567890)
        return path

    def installation(self):
        root = self.root / "installed"
        for name, (data, mode) in self.files.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
            path.chmod(mode)
        (root / "manifest.json").write_bytes(artifact.encoded(self.manifest))
        return root

    def test_archive_and_installation_report_same_identity(self):
        self.assertEqual(artifact.verify(self.archive()), artifact.verify(self.installation()))

    def test_archive_bytes_independent_of_output_name_and_input_order(self):
        first = self.archive("first.tar.gz").read_bytes()
        self.files = dict(reversed(list(self.files.items())))
        self.assertEqual(first, self.archive("second.tar.gz").read_bytes())

    def test_changed_payload_is_rejected(self):
        self.files["signatures/default.sigs"] = (b"changed", 0o644)
        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            artifact.verify(self.archive())

    def test_changed_permissions_are_rejected(self):
        root = self.installation()
        (root / "daemon/owlbeard").chmod(0o755)
        with self.assertRaisesRegex(ValueError, "integrity mismatch"):
            artifact.verify(root)

    def test_missing_or_extra_files_are_rejected(self):
        for missing in (True, False):
            with self.subTest(missing=missing):
                files = copy.deepcopy(self.files)
                if missing:
                    del files["game/owlbear-game"]
                else:
                    files["unexpected"] = (b"extra", 0o644)
                with self.assertRaisesRegex(ValueError, "missing or unexpected"):
                    artifact.check_payload(self.manifest, files)

    def test_even_rehashed_incomplete_artifact_is_rejected(self):
        del self.files["kernel/owlbear.ko"]
        del self.manifest["files"]["kernel/owlbear.ko"]
        with self.assertRaisesRegex(ValueError, "incomplete"):
            artifact.verify(self.archive())

    def test_wrong_architecture_is_rejected_even_with_matching_hash(self):
        data = bytearray(self.files["daemon/owlbeard"][0])
        data[18:20] = (62).to_bytes(2, "little")  # EM_X86_64
        self.files["daemon/owlbeard"] = (bytes(data), 0o644)
        self.manifest["files"]["daemon/owlbeard"]["sha256"] = artifact.digest(data)
        with self.assertRaisesRegex(ValueError, "wrong ELF architecture"):
            artifact.verify(self.archive())

    def test_changed_build_inputs_are_rejected(self):
        self.manifest["inputs"]["compiler"] = "other compiler"
        with self.assertRaisesRegex(ValueError, "build identity"):
            artifact.verify(self.archive())

    def test_symlink_in_installation_is_rejected(self):
        root = self.installation()
        path = root / "daemon/owlbeard"
        path.unlink()
        path.symlink_to(root / "game/owlbear-game")
        with self.assertRaisesRegex(ValueError, "symlink"):
            artifact.verify(root)

    def test_unsafe_and_duplicate_archive_entries_are_rejected(self):
        for name, symlink, duplicate in (
            ("root/../escape", False, False), ("/absolute", False, False),
            ("root/link", True, False), ("root/file", False, True),
        ):
            with self.subTest(name=name, symlink=symlink, duplicate=duplicate):
                path = self.root / "unsafe.tar.gz"
                with tarfile.open(path, "w:gz") as output:
                    member = tarfile.TarInfo(name)
                    if symlink:
                        member.type = tarfile.SYMTYPE
                        member.linkname = "/outside"
                    else:
                        member.size = 1
                    output.addfile(member, io.BytesIO(b"x"))
                    if duplicate:
                        output.addfile(member, io.BytesIO(b"x"))
                with self.assertRaisesRegex(ValueError, "unsafe|duplicate"):
                    artifact.verify(path)


if __name__ == "__main__":
    unittest.main()

"""Qualification must distinguish syscall denial from unrelated failures."""
import errno
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("memory_checks", Path(__file__).parents[1] / "qualification/bigrae/check-memory.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class QualificationTests(unittest.TestCase):
    def test_only_explicit_permission_denial_proves_protection(self):
        results = {name: {"return": -1, "errno": errno.EPERM, "expected_bytes": 4}
                   for name in ("process_vm_readv", "process_vm_writev", "proc_mem", "ptrace")}
        self.assertTrue(module.classify(results, "protected"))
        for error in (errno.EFAULT, errno.ESRCH, errno.EACCES, 0):
            changed = {name: dict(value) for name, value in results.items()}
            changed["ptrace"]["errno"] = error
            self.assertFalse(module.classify(changed, "protected"))
        self.assertFalse(module.classify({}, "protected"))

    def test_baseline_requires_success_for_every_operation(self):
        results = {name: {"return": count, "errno": 0, "expected_bytes": count}
                   for name, count in (("process_vm_readv", 4), ("process_vm_writev", 4), ("proc_mem", 4), ("ptrace", 0))}
        self.assertTrue(module.classify(results, "baseline"))
        results["process_vm_readv"]["return"] = 2
        self.assertFalse(module.classify(results, "baseline"))
        results.pop("ptrace")
        self.assertFalse(module.classify(results, "baseline"))

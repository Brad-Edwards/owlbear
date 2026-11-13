"""Exercise complete workload discovery across real partial file writes."""
import importlib.util
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest

spec = importlib.util.spec_from_file_location("baseline", Path(__file__).parents[1] / "qualification/bigrae/baseline.py")
baseline = importlib.util.module_from_spec(spec)
spec.loader.exec_module(baseline)


class BaselineTests(unittest.TestCase):
    def test_partial_discovery_waits_for_the_complete_record(self):
        with tempfile.TemporaryDirectory() as tmp, subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"]) as process:
            info = Path(tmp) / "game.info"
            info.touch()
            def write():
                time.sleep(.03)
                info.write_text(f"{process.pid} 0x")
                time.sleep(.03)
                info.write_text(f"{process.pid} 0x1234\n")
            writer = threading.Thread(target=write)
            writer.start()
            try:
                self.assertEqual(baseline.wait_for_workload(process, info, timeout=1), 0x1234)
            finally:
                writer.join()
                process.terminate()

    def test_wrong_workload_identity_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp, subprocess.Popen([sys.executable, "-c", "import time; time.sleep(2)"]) as process:
            info = Path(tmp) / "game.info"
            info.write_text(f"{process.pid + 1} 0x1234\n")
            try:
                with self.assertRaises(RuntimeError):
                    baseline.wait_for_workload(process, info, timeout=1)
            finally:
                process.terminate()

# SPDX-License-Identifier: GPL-2.0-only
"""The game holds its run canary only in process memory."""
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
INFO = Path("/tmp/owlbear-game.info")


class GameCanary(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory()
        cls.binary = Path(cls.build.name) / "owlbear-game"
        subprocess.run(
            ["cc", "-std=c11", "-Wall", "-Wextra", "-Werror", "-Wpedantic", "-D_GNU_SOURCE",
             "-o", str(cls.binary), str(ROOT / "game/main.c"), "-lncurses", "-lm",
             *os.environ.get("OWL_GAME_LDFLAGS", "").split()],
            check=True,
        )

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def start(self, canary=None):
        """Start the game; give it ``canary`` through a pipe before it can report ready."""
        INFO.unlink(missing_ok=True)
        args, fds, write = ["--no-curses"], (), None
        if canary is not None:
            read, write = os.pipe()
            args, fds = [*args, "--canary-fd", str(read)], (read,)
        game = subprocess.Popen([str(self.binary), *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                pass_fds=fds)
        self.addCleanup(lambda: (game.kill(), game.communicate()))
        if canary is not None:
            os.close(fds[0])
            os.write(write, canary)
            os.close(write)
        for _ in range(50):
            if INFO.exists() and INFO.read_text().strip():
                return game
            time.sleep(0.1)
        self.fail("the game did not write its info file")

    def state(self):
        pid, address = INFO.read_text().split()
        with open(f"/proc/{pid}/mem", "rb") as memory:
            memory.seek(int(address, 16))
            # The state is a few hundred bytes; a longer read can cross into unmapped memory.
            return memory.read(256)

    def test_canary_is_in_memory_and_nowhere_else(self):
        canary = secrets.token_hex(16).encode()
        game = self.start(canary)
        self.assertIn(canary, self.state())
        self.assertNotIn(canary, INFO.read_bytes())
        game.kill()
        stdout, stderr = game.communicate()
        self.assertNotIn(canary, stdout + stderr)

    def test_missing_canary_fails_start(self):
        read, write = os.pipe()
        os.close(write)
        game = subprocess.run([str(self.binary), "--no-curses", "--canary-fd", str(read)],
                              pass_fds=(read,), capture_output=True, timeout=10)
        os.close(read)
        self.assertEqual(game.returncode, 1)

    def test_game_without_canary_keeps_running(self):
        self.start()
        self.assertEqual(self.state()[:4], (0x4F574C42).to_bytes(4, "little"))


if __name__ == "__main__":
    unittest.main()

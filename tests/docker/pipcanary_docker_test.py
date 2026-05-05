import os
import subprocess
import unittest


class PipCanaryIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.lock_file_path = "tests/docker/shared/requirements-locked.txt"
        if os.path.exists(self.lock_file_path):
            os.remove(self.lock_file_path)

    def run_script(self, script: str):
        subprocess.check_output(["sh", "-c", script])

    def test_run(self):
        self.run_script("cd tests/docker && make build && make run")
        self.assertTrue(os.path.exists(self.lock_file_path))

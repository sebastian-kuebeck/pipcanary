import os
import subprocess
import unittest


class PipCanaryIntegrationTest(unittest.TestCase):
    def run_script(self, script: str):
        script_file = os.path.join(os.path.dirname(__file__), script)
        subprocess.check_output(["sh", script_file])

    def test_run(self):
        self.run_script("pipcanary_test.sh")

    def test_run_and_recognize_attack(self):
        try:
            self.run_script("attack_test.sh")
            self.fail("Should have recognized illegal access")
        except subprocess.CalledProcessError as e:
            self.assertEqual(5, e.returncode)

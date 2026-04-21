import os
import subprocess
import unittest


class PipCanaryIntegrationTest(unittest.TestCase):
    def run_script(self, script: str):
        script_file = os.path.join(os.path.dirname(__file__), script)
        subprocess.check_output(["sh", script_file])

    def test_run(self):
        self.run_script("pipcanary_test.sh")

    def test_recognize_attack(self):
        try:
            self.run_script("attack_test.sh")
            self.fail("Should have recognized illegal access")
        except subprocess.CalledProcessError as e:
            self.assertEqual(5, e.returncode)

    def test_too_recently(self):
        try:
            self.run_script("pipcanary_too_recent.sh")
            self.fail("Should have recognized packages updated too recently")
        except subprocess.CalledProcessError as e:
            self.assertEqual(4, e.returncode)

    def test_existing_vulns(self):
        try:
            self.run_script("pipcanary_fail_test.sh")
            self.fail("Should have recognized existing vulnerabilities")
        except subprocess.CalledProcessError as e:
            self.assertEqual(4, e.returncode)

    def test_ignore_vuns(self):
        self.run_script("pipcanary_fail_ignored_test.sh")

    def test_toml(self):
        self.run_script("pipcanary_toml_test.sh")

    def test_no_sandbox(self):
        self.run_script("pipcanary_no_sandbox_test.sh")

    def test_dont_scan(self):
        self.run_script("pipcanary_fail_dont_scan_test.sh")

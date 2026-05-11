import os
import unittest

from datetime import datetime
from argparse import ArgumentParser

from pipcanary.parameters import PipCanaryParameters, LogLevel

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "test_data")


class TestPipCanaryArgParameters(unittest.TestCase):
    def setUp(self):
        self.parser = ArgumentParser(prog="test", description="Test")
        self.params = PipCanaryParameters([LogLevel()])
        self.params.add_arguments(self.parser)

    def test_fill(self):
        ns = self.parser.parse_args(["--log-level", "DEBUG"])
        self.params.fill(ns)
        self.assertEqual("DEBUG", self.params[LogLevel.name])

    def test_fill_default(self):
        ns = self.parser.parse_args([])
        self.params.fill(ns)
        self.assertEqual("INFO", self.params[LogLevel.name])


class TestPipCanaryConfigParameters(unittest.TestCase):
    def setUp(self):
        self.project_file = os.path.join(TEST_DATA_DIR, "pyproject-parameters.toml")
        self.requirements_file = os.path.join(TEST_DATA_DIR, "requirements.txt")

        self.parser = ArgumentParser(prog="test", description="Test")
        self.params = PipCanaryParameters()
        self.params.add_arguments(self.parser)

    def test_fill(self):
        ns = self.parser.parse_args(["-p", self.project_file])
        self.params.fill(ns)
        self.assertEqual("DEBUG", self.params.log_level)
        self.assertTrue(self.params.sandbox)

    def test_fill_override(self):
        ns = self.parser.parse_args(["-p", self.project_file, "--log-level", "ERROR"])
        self.params.fill(ns)
        self.assertEqual("ERROR", self.params.log_level)

    def test_requirements_from_config(self):
        ns = self.parser.parse_args(["-p", self.project_file])
        self.params.fill(ns)
        requirements = self.params.requirements()
        self.assertEqual(["virtualenv==21.2.0", "tomli==2.4.1"], requirements.list())

    def test_combined_requirements(self):
        ns = self.parser.parse_args(
            ["-p", self.project_file, "-r", self.requirements_file]
        )
        self.params.fill(ns)
        requirements = self.params.requirements()

        expected = [
            "botocore<=1.42.81",
            "boto3<=1.42.81",
            "click<=8.3.1",
            "Werkzeug<=3.1.7",
            "charset-normalizer~=3.4.6",
            "requests",
            "flask",
            "pyyaml",
            "numpy",
            "virtualenv==21.2.0",
            "tomli==2.4.1",
        ]
        self.assertEqual(expected, requirements.list())

    def test_ignore_vulns(self):
        ns = self.parser.parse_args(
            ["-p", self.project_file, "--ignore-vuln", "CVE-2026-4539"]
        )
        self.params.fill(ns)
        self.assertEqual("DEBUG", self.params[LogLevel.name])
        selection = self.params.auditSelection()
        self.assertEqual(
            {"GHSA-5239-wwwm-4pmq", "CVE-2026-4539"}, selection.ignore_vulns
        )

    def test_dont_scan(self):
        ns = self.parser.parse_args(["-p", self.project_file, "--do-not-scan", "tomli"])
        self.params.fill(ns)
        self.assertEqual({"virtualenv", "tomli"}, set(self.params.do_not_scan))

    def test_allow_upload_time(self):
        ns = self.parser.parse_args(
            [
                "-r",
                self.requirements_file,
                "--allow-upload-time",
                "pip<=2026-04-26T21:00:05",
            ]
        )
        self.params.fill(ns)
        selection = self.params.auditSelection()
        self.assertEqual(
            {"pip": datetime.fromisoformat("2026-04-26T21:00:05")},
            selection.allowed_upload_times,
        )

    def test_no_sandbox(self):
        ns = self.parser.parse_args(["-p", self.project_file, "--no-sandbox"])
        self.params.fill(ns)
        self.assertFalse(self.params.sandbox)

    def test_locked_requirements_file(self):
        locked_requirements_file = "requirements-locked.txt"
        ns = self.parser.parse_args(
            ["-p", self.project_file, "-l", locked_requirements_file]
        )
        self.params.fill(ns)
        self.assertEqual(locked_requirements_file, self.params.locked_requirements_file)

    def test_trace_file(self):
        trace_file = "trace.txt"
        ns = self.parser.parse_args(
            ["-p", self.project_file, "--trace-file", trace_file]
        )
        self.params.fill(ns)
        self.assertEqual(trace_file, self.params.trace_file)

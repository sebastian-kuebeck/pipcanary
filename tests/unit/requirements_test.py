import os
import unittest

from pipcanary.requirements import Requirements, RequirementsError

TEST_DATA_DIR = os.path.join(os.path.dirname(__file__), "test_data")


class RequirementsTest(unittest.TestCase):
    def setUp(self):
        self.requirements_file = os.path.join(TEST_DATA_DIR, "requirements.txt")
        self.static_project_file = os.path.join(TEST_DATA_DIR, "pyproject-static.toml")
        self.dynamic_project_file = os.path.join(
            TEST_DATA_DIR, "pyproject-dynamic.toml"
        )
        self.requirements_file_with_options = os.path.join(
            TEST_DATA_DIR, "requirements-with-options.txt"
        )

    def test_parse_requirements(self):
        lines = [
            "# remark",
            "boto3<=1.42.81",
            "click<=\\ ",
            "8.3.1",
            "Werkzeug\\",
            "<=3.1.7\\",
        ]
        self.assertEqual(
            [
                "boto3<=1.42.81",
                "click<=8.3.1",
                "Werkzeug<=3.1.7",
            ],
            Requirements.parse_requirements(lines),
        )

    def test_from_requirements_file(self):
        requirements = Requirements.from_requirements_file(self.requirements_file)
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
        ]
        self.assertEqual(expected, requirements.list())

    def test_from_requirements_file_with_options(self):
        try:
            Requirements.from_requirements_file(self.requirements_file_with_options)
            self.fail()
        except RequirementsError as e:
            self.assertEqual(
                f"Failed to load requirements file {self.requirements_file_with_options}: Error in line 11: options are not supported.",
                str(e),
            )

    def test_from_project_file(self):
        requirements = Requirements.from_project_file(self.static_project_file)
        expected = ["virtualenv==21.2.0", "tomli==2.4.1", "PyQt5", "rich", "click"]
        self.assertEqual(expected, requirements.list())

    def test_reject_dynamic_project_file(self):
        try:
            Requirements.from_project_file(self.dynamic_project_file)
            self.fail("Should not accept dynamic requirements")
        except RequirementsError:
            pass

    def test_skip_packages(self):
        requirements = Requirements.from_requirements_file(self.requirements_file)
        reduced_requirements = requirements.skip_packages(
            ["botocore", "numpy", "charset-normalizer"]
        )
        expected = [
            "boto3<=1.42.81",
            "click<=8.3.1",
            "Werkzeug<=3.1.7",
            "requests",
            "flask",
            "pyyaml",
        ]
        self.assertEqual(expected, reduced_requirements.list())

    def test_write_to_temporary_file(self):
        requirements = Requirements.from_requirements_file(self.requirements_file)
        requirements_reduced = requirements.skip_packages(
            ["botocore", "numpy", "charset-normalizer"]
        )
        temp_file = requirements_reduced.write_to_temporary_file()
        try:
            requirements_loaded = Requirements.from_requirements_file(temp_file)
        finally:
            os.remove(temp_file)

        expected = [
            "boto3<=1.42.81",
            "click<=8.3.1",
            "Werkzeug<=3.1.7",
            "requests",
            "flask",
            "pyyaml",
        ]
        self.assertEqual(expected, requirements_loaded._requirements)

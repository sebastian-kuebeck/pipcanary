import os
import unittest

from pipcanary.requirements import Requirements


class RequirementsTest(unittest.TestCase):
    def setUp(self):
        self.requirements_file = os.path.join(
            os.path.dirname(__file__), "requirements.txt"
        )
        self.project_file = os.path.join(os.path.dirname(__file__), "pyproject.toml")

    def test_from_requirements_file(self):
        requirements = Requirements.from_requirements_file(self.requirements_file)
        expected = [
            "botocore<=1.42.81",
            "boto3<=1.42.81",
            "click<=8.3.1",
            "Werkzeug<=3.1.7",
            "charset-normalizer<=3.4.6",
            "requests",
            "flask",
            "pyyaml",
            "numpy",
        ]
        self.assertEqual(expected, requirements.requirements)

    def test_from_project_file(self):
        requirements = Requirements.from_project_file(self.project_file)
        expected = ["virtualenv==21.2.0", "tomli==2.4.1"]
        self.assertEqual(expected, requirements.requirements)

    def test_skip_packages(self):
        requirements = Requirements.from_requirements_file(self.requirements_file)
        requirements.skip_packages(["botocore", "numpy"])
        expected = [
            "boto3<=1.42.81",
            "click<=8.3.1",
            "Werkzeug<=3.1.7",
            "charset-normalizer<=3.4.6",
            "requests",
            "flask",
            "pyyaml",
        ]
        self.assertEqual(expected, requirements.requirements)

    def test_write_to_temporary_file(self):
        requirements = Requirements.from_requirements_file(self.requirements_file)
        requirements.skip_packages(["botocore", "numpy"])
        temp_file = requirements.write_to_temporary_file()
        try:
            requirements_loaded = Requirements.from_requirements_file(temp_file)
        finally:
            os.remove(temp_file)

        expected = [
            "boto3<=1.42.81",
            "click<=8.3.1",
            "Werkzeug<=3.1.7",
            "charset-normalizer<=3.4.6",
            "requests",
            "flask",
            "pyyaml",
        ]
        self.assertEqual(expected, requirements_loaded.requirements)

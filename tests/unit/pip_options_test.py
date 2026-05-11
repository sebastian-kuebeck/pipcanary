import unittest

from pipcanary.package_auditor import (
    PipOptions,
)


class TestPipOptions(unittest.TestCase):
    def test_encode_to_shell(self):
        options = PipOptions(
            index_url="http://localhost:3141/root/pypi/+simple/",
            extra_index_url="http://localhost:3141/root/pypi/+test/",
        )
        self.assertEqual(
            "--index-url http://localhost:3141/root/pypi/+simple/ --extra-index-url http://localhost:3141/root/pypi/+test/",
            options.encode_for_shell(),
        )

    def test_encode_to_shell_with_additional_args(self):
        options = PipOptions(
            index_url="http://localhost:3141/root/pypi/+simple/",
            additional_args="--uploaded-prior-to P3D",
        )
        self.assertEqual(
            "--uploaded-prior-to P3D --index-url http://localhost:3141/root/pypi/+simple/",
            options.encode_for_shell(),
        )

    def test_pip_environment(self):
        self.options = PipOptions(
            index_url="http://localhost:3141/root/pypi/+simple/",
            extra_index_url="http://localhost:3141/root/pypi/+test/",
        )
        self.assertEqual(
            {
                "PIP_INDEX_URL": "http://localhost:3141/root/pypi/+simple/",
                "PIP_EXTRA_INDEX_URL": "http://localhost:3141/root/pypi/+test/",
            },
            self.options.pip_environment(),
        )

import unittest
import logging
from eyeon.cli import CommandLine


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.cli1 = CommandLine(
            f"-o ./outputs  -g file.log -v {logging.DEBUG} observe -l LLNL demo.ipynb ".split()
        )

        self.cli2 = CommandLine(
            f"--output-dir ./outputs --log-file file.log --log-level {logging.DEBUG} parse tests -t 2 ".split()  # noqa: E501
        )

        self.cli3 = CommandLine(
            "checksum notepad++.exe -a sha1 28a2a37cf2e9550a699b138dddba4b8067c8e1b1".split()
        )

    def testObserveArgs(self) -> None:
        self.assertEqual(self.cli1.args.filename, "demo.ipynb")
        self.assertEqual(self.cli1.args.output_dir, "./outputs")
        self.assertEqual(self.cli1.args.log_level, logging.DEBUG)
        self.assertEqual(self.cli1.args.log_file, "file.log")
        self.assertEqual(self.cli1.args.location, "LLNL")
        self.assertEqual(self.cli1.args.func, self.cli1.observe)

    def testParseArgs(self) -> None:
        self.assertEqual(self.cli2.args.dir, "tests")
        self.assertEqual(self.cli2.args.output_dir, "./outputs")
        self.assertEqual(self.cli2.args.log_file, "file.log")
        self.assertEqual(self.cli2.args.log_level, logging.DEBUG)
        self.assertEqual(self.cli2.args.threads, 2)
        self.assertEqual(self.cli2.args.func, self.cli2.parse)

    def testChecksumArgs(self):
        self.assertEqual(self.cli3.args.file, "notepad++.exe")
        self.assertEqual(self.cli3.args.algorithm, "sha1")
        self.assertEqual(self.cli3.args.cksum, "28a2a37cf2e9550a699b138dddba4b8067c8e1b1")
        self.assertEqual(self.cli3.args.func, self.cli3.checksum)
        


if __name__ == "__main__":
    unittest.main()

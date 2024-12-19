import unittest
import logging
from eyeon.cli import CommandLine


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.cli1 = CommandLine(
            f"observe -o ./outputs  -g file.log -v {logging.DEBUG} -l LLNL demo.ipynb ".split()
        )

        self.cli2 = CommandLine(
            f"parse --output-dir ./outputs --log-file file.log --log-level {logging.DEBUG} tests -t 2 ".split()  # noqa: E501
        )

        self.cli3 = CommandLine(
            "checksum Wintap.exe -a sha1 1585373cc8ab4f22ce6e553be54eacf835d63a95".split()
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
        self.assertEqual(self.cli3.args.file, "Wintap.exe")
        self.assertEqual(self.cli3.args.algorithm, "sha1")
        self.assertEqual(self.cli3.args.cksum, "1585373cc8ab4f22ce6e553be54eacf835d63a95")
        self.assertEqual(self.cli3.args.func, self.cli3.checksum)


if __name__ == "__main__":
    unittest.main()

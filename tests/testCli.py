import unittest

from eyeon.cli import CommandLine
from unittest.mock import patch


class CliTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.cli1 = CommandLine(
            "observe -o ./outputs  -g file.log -v DEBUG -l LLNL demo.ipynb ".split()
        )

        self.cli2 = CommandLine(
            "parse --output-dir ./outputs --log-file file.log --log-level DEBUG tests -t 2 ".split()  # noqa: E501
        )

        self.cli3 = CommandLine(
            "checksum Wintap.exe -a sha1 1585373cc8ab4f22ce6e553be54eacf835d63a95".split()
        )

        self.cli4 = CommandLine(
            "observe Wintap.exe -c 1585373cc8ab4f22ce6e553be54eacf835d63a95 -a sha1".split()
        )

    def testObserveArgs(self) -> None:
        self.assertEqual(self.cli1.args.filename, "demo.ipynb")
        self.assertEqual(self.cli1.args.output_dir, "./outputs")
        self.assertEqual(self.cli1.args.log_level, "DEBUG")
        self.assertEqual(self.cli1.args.log_file, "file.log")
        self.assertEqual(self.cli1.args.location, "LLNL")
        self.assertEqual(self.cli1.args.func, self.cli1.observe)

    def testParseArgs(self) -> None:
        self.assertEqual(self.cli2.args.dir, "tests")
        self.assertEqual(self.cli2.args.output_dir, "./outputs")
        self.assertEqual(self.cli2.args.log_file, "file.log")
        self.assertEqual(self.cli2.args.log_level, "DEBUG")
        self.assertEqual(self.cli2.args.threads, 2)
        self.assertEqual(self.cli2.args.func, self.cli2.parse)

    def testChecksumArgs(self):
        self.assertEqual(self.cli3.args.file, "Wintap.exe")
        self.assertEqual(self.cli3.args.algorithm, "sha1")
        self.assertEqual(self.cli3.args.cksum, "1585373cc8ab4f22ce6e553be54eacf835d63a95")
        self.assertEqual(self.cli3.args.func, self.cli3.checksum)

    def testObserveChecksumArgs(self):
        self.assertEqual(self.cli4.args.filename, "Wintap.exe")
        self.assertEqual(self.cli4.args.checksum, "1585373cc8ab4f22ce6e553be54eacf835d63a95")
        self.assertEqual(self.cli4.args.algorithm, "sha1")

    def testObserveMissingArgs(self):
        with self.assertRaises(SystemExit):
            CommandLine([])


class CliTestObserve(unittest.TestCase):
    def setUp(self):
        # patch observe and checksum functions
        self.observe_patch = patch("eyeon.observe.Observe")
        self.checksum_patch = patch("eyeon.checksum.Checksum")

        self.observe_mock = self.observe_patch.start()
        self.checksum_mock = self.checksum_patch.start()

    def tearDown(self):
        self.addCleanup(self.observe_patch.stop)
        self.addCleanup(self.checksum_patch.stop)

    def testObserve_no_checksum(self):
        args = ["observe", "Wintap.exe"]
        cli = CommandLine(args)

        print(cli.args)

        cli.observe(cli.args)
        self.observe_mock.assert_called_once_with("Wintap.exe", "ERROR", None)
        self.checksum_mock.assert_not_called()

    def testObserve_checksum(self):
        args = ["observe", "Wintap.exe", "-c", "abc123"]
        cli = CommandLine(args)

        cli.observe(cli.args)
        self.observe_mock.assert_called_once_with("Wintap.exe", "ERROR", None)
        self.checksum_mock.assert_called_once_with("Wintap.exe", "md5", "abc123")

    def testObserve_checksum_alg(self):
        args = ["observe", "Wintap.exe", "-c", "abc123", "-a", "sha1"]
        cli = CommandLine(args)

        cli.observe(cli.args)
        self.observe_mock.assert_called_once_with("Wintap.exe", "ERROR", None)
        self.checksum_mock.assert_called_once_with("Wintap.exe", "sha1", "abc123")

    def testObserve_optional_args(self):
        args = [
            "observe",
            "Wintap.exe",
            "-o",
            "./output",
            "-g",
            "mylog.log",
            "-v",
            "DEBUG",
        ]
        cli = CommandLine(args)

        cli.observe(cli.args)
        self.observe_mock.assert_called_once_with("Wintap.exe", "DEBUG", "mylog.log")
        self.checksum_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()

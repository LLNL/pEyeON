"""
CLI interface for EyeON tools.
"""

import argparse

import eyeon.observe
import eyeon.parse
import eyeon.checksum
import logging


class CommandLine:
    """
    Command Line object to interact with eyeon tools.
    """

    def __init__(self, testargs: str = None) -> None:
        parser = argparse.ArgumentParser(
            prog="eyeon",
            description="Eye on Operational techNology, an update tracker for OT devices",
        )

        shared_args = argparse.ArgumentParser(add_help=False)
        shared_args.add_argument(
            "-o",
            "--output-dir",
            help="Path to results directory. Defaults to $pwd. Can set on $EYEON_OUTPUT.",
        )

        shared_args.add_argument(
            "-g", "--log-file", help="Output file for log. If none, prints to console."
        )
        shared_args.add_argument(
            "-v",
            "--log-level",
            default=logging.ERROR,
            type=int,
            help="Set the log level. Defaults to ERROR.",
        )

        # parent parser to add shared arg to both observe and parse
        db_parser = argparse.ArgumentParser(add_help=False)
        db_parser.add_argument(
            "-d", "--database", help="Specify a filepath to save result to duckdb database"
        )

        # Create subparser
        subparsers = parser.add_subparsers(required=True, help="sub-command help")

        # Create parser for observe command
        observe_parser = subparsers.add_parser(
            "observe", help="observe help", parents=[db_parser, shared_args]
        )
        observe_parser.add_argument("filename", help="Name of file to scan")
        observe_parser.add_argument(
            "-l",
            "--location",
            help="Site location where scan/install happens. Can set on $SITE to auto-read.",
        )
        observe_parser.set_defaults(func=self.observe)

        # Create parser for parse command
        parse_parser = subparsers.add_parser(
            "parse", help="parse help", parents=[db_parser, shared_args]
        )
        parse_parser.add_argument("dir", help="Name of directory to scan")
        parse_parser.add_argument(
            "--threads",
            "-t",
            help="Number of threads for multiprocessing. Default 1.",
            default=1,
            type=int,
        )
        parse_parser.set_defaults(func=self.parse)

        # Create parser for checksum command
        checksum_parser = subparsers.add_parser("checksum", help="checksum help")
        checksum_parser.add_argument("file", help="file you want to checksum")
        checksum_parser.add_argument("cksum", help="expected checksum (md5, sha1, sha256) of file")
        checksum_parser.add_argument(
            "-a",
            "--algorithm",
            choices=["md5", "sha1", "sha256"],
            default="md5",
            help="Specify the hash algorithm (default: md5)",
        )
        checksum_parser.set_defaults(func=self.checksum)

        # new
        if testargs:
            self.args = parser.parse_args(testargs)
        else:
            self.args = parser.parse_args()

        # self.args = parser.parse_args()
        # args.func(args)

    def observe(self, args) -> None:
        """
        Parser function.
        """

        obs = eyeon.observe.Observe(args.filename, args.log_level, args.log_file)

        if (outdir := args.output_dir) is None:
            outdir = "."

        obs.write_json(outdir)

        if args.database:
            obs.write_database(args.database, outdir)

    def parse(self, args) -> None:
        """
        Call to eyeon parser. Runs `observe` on files in path.
        """

        p = eyeon.parse.Parse(args.dir, args.log_level, args.log_file)
        if (outdir := args.output_dir) is None:
            outdir = "./results"

        p(result_path=outdir, threads=args.threads)

        if args.database:
            p.write_database(args.database, outdir)

    def checksum(self, args) -> None:
        "verify checksum against provided value"

        eyeon.checksum.Checksum(args.file, args.algorithm, args.cksum)


def main():
    """
    Call to run CLI parser.
    """
    cli = CommandLine()
    cli.args.func(cli.args)

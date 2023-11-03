"""
CLI interface for EyeON tools.
"""


import argparse

import eyeon.observe
import eyeon.parse
import logging


class CommandLine:
    """
    Command Line object to interact with eyeon tools.
    """

    def __init__(self) -> None:
        parser = argparse.ArgumentParser(
            prog="eyeon",
            description="Eye on Operational techNology, an update tracker for OT devices",
        )
        parser.add_argument(
            "-o",
            "--output-dir",
            help="Path to results directory. Defaults to $pwd. Can set on $EYEON_OUTPUT.",
        )
        parser.add_argument(
            "-g", "--log-file", help="Output file for log. If none, prints to console."
        )
        parser.add_argument(
            "-v", "--log-level", default=logging.ERROR, help="Set the log level. Defaults to ERROR."
        )

        # Create subparser
        subparsers = parser.add_subparsers(required=True, help="sub-command help")

        # Create parser for observe command
        observe_parser = subparsers.add_parser("observe", help="observe help")
        observe_parser.add_argument("filename", help="Name of file to scan")
        observe_parser.add_argument(
            "-l",
            "--location",
            help="Site location where scan/install happens. Can set on $SITE to auto-read.",
        )
        observe_parser.set_defaults(func=self.observe)

        # Create parser for parse command
        parse_parser = subparsers.add_parser("parse", help="parse help")
        parse_parser.add_argument("dir", help="Name of directory to scan")
        parse_parser.add_argument(
            "--threads",
            "-t",
            help="Number of threads for multiprocessing. Default 1.",
            default=1,
            type=int,
        )
        parse_parser.set_defaults(func=self.parse)
        self.args = parser.parse_args()
        # args.func(args)

    def observe(self, args) -> None:
        """
        Parser function.
        """

        obs = eyeon.observe.Observe(args.filename, args.log_level, args.log_file)

        if args.output_dir:
            obs.write_json(args.output_dir)
        else:
            obs.write_json()

    def parse(self, args) -> None:
        """
        Call to eyeon parser. Runs `observe` on files in path.
        """

        p = eyeon.parse.Parse(args.dir, args.log_level, args.log_file)
        p(result_path=args.output_dir, threads=args.threads)


def main():
    """
    Call to run CLI parser.
    """
    cli = CommandLine()
    cli.args.func(cli.args)

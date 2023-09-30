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
        self.parser = argparse.ArgumentParser(
            prog="eyeon",
            description="Eye on Operational techNology, an update tracker for OT devices",
        )
        self.parser.add_argument(
            "-o",
            "--output-dir",
            help="Path to results directory. Defaults to $pwd. Can set on $EYEON_OUTPUT.",
        )
        self.parser.add_argument(
            "-g", "--log-file", help="Output file for log. If none, prints to console."
        )
        self.parser.add_argument(
            "-v", "--log-level", default=logging.ERROR, help="Set the log level. Defaults to ERROR."
        )
        self.parser.add_argument(
            "function", choices=["observe", "parse"], help="Observe one file or Parse a directory."
        )
        args, sub_args = self.parser.parse_known_args()
        if args.function == "observe":
            self.observe()
        elif args.function == "parse":
            self.parse()

    def observe(self) -> None:
        """
        Parser function.
        """

        self.parser.add_argument("filename", help="Name of file to scan")
        self.parser.add_argument("-m", "--manufacturer", help="Software vendor.")
        self.parser.add_argument(
            "-l",
            "--location",
            help="Site location where scan/install happens. Can set on $SITE to auto-read.",
        )

        args = self.parser.parse_args()
        obs = eyeon.observe.Observe(args.filename, args.log_level, args.log_file)

        if args.output_dir:
            obs.write_json(args.output_dir)
        else:
            obs.write_json()

    def parse(self) -> None:
        """
        Call to eyeon parser. Runs `observe` on files in path.
        """
        self.parser.add_argument("dir", help="Name of directory to scan")
        self.parser.add_argument(
            "--threads",
            "-t",
            help="Number of threads for multiprocessing. Default 1.",
            default=1,
            type=int,
        )
        args = self.parser.parse_args()

        p = eyeon.parse.Parse(args.dir, args.log_level, args.log_file)
        p(result_path=args.output_dir, threads=args.threads)


def main():
    """
    Call to run CLI parser.
    """
    CommandLine()

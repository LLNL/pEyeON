"""
CLI interface for EyeON tools.
"""


import argparse

import eyeon.observe
import logging


class CommandLine:
    """
    Command Line object to interact with eyeon tools.
    """

    def __init__(self) -> None:
        pass

    def observe(self) -> None:
        """
        Parser function.
        """
        parser = argparse.ArgumentParser(
            prog="eyeon",
            description="Eye on Operational techNology, an update tracker for OT devices",
        )
        parser.add_argument("filename", help="Name of file to scan")
        parser.add_argument(
            "-o",
            "--output-dir",
            help="Path to results directory. Defaults to $pwd. Can set on $EYEON_OUTPUT.",
        )
        parser.add_argument("-m", "--manufacturer", help="Software vendor.")
        parser.add_argument(
            "-l",
            "--location",
            help="Site location where scan/install happens. Can set on $SITE to auto-read.",
        )
        parser.add_argument(
            "-g", "--log-file", help="Output file for log. If none, prints to console."
        )
        parser.add_argument(
            "-v", "--log-level", default=logging.ERROR, help="Set the log level. Defaults to ERROR."
        )

        args = parser.parse_args()
        obs = eyeon.observe.Observe(args.filename, args.log_level, args.log_file)

        if args.output_dir:
            obs.write_json(args.output_dir)
        else:
            obs.write_json()

    def parse(self) -> None:
        """
        Call to eyeon parser. Runs `observe` on files in path.
        """
        pass


def main():
    """
    Call to run CLI parser.
    """
    CommandLine().observe()

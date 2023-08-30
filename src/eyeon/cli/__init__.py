"""
CLI interface for EyeON tools.
"""


import argparse

import eyeon.observe


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

        args = parser.parse_args()
        obs = eyeon.observe.Observe(args.filename)

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

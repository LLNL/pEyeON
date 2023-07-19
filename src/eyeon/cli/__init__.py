import argparse
import observe
class CommandLine:
    def __init__(self) -> None:
        pass

    def run(self) -> None:
        parser = argparse.ArgumentParser(
            prog="eyeon",
            description="Eye on Operational techNology, an update tracker for OT devices",
        )
        parser.add_argument("filename", help="Name of file to scan")
        parser.add_argument("-o", "--output-dir", help="Path to results directory. Defaults to $pwd.")

        args = parser.parse_args()
        obs = observe.Observe(args.filename)
        obs.write_json(args.get())



def main():
    CommandLine().run()
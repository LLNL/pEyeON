from dataclasses import dataclass
import datetime
import hashlib
import json
import magic
import os
import pefile
import pprint
from unblob import models
import tempfile
# TODO: import tika

@dataclass
class Observe:
    # required fields
    bytecount: int
    filename: str
    magic: str
    md5: str
    modtime: str
    observation_ts: str
    sha1: str
    sha256: str
    permissions: int  # needs to be in octal for reading

    # optional fields
    compiler: str = None
    host: list = None
    imphash: str = None

    def __init__(self, file) -> None:
        stat = os.stat(file)
        self.bytecount = stat.st_size
        self.filename = os.path.basename(file)  # TODO: split into absolute path maybe?
        try:
            self.set_imphash(file)
        except pefile.PEFormatError:
            self.imphash = "N/A"
        self.magic = magic.from_file(file)
        self.modtime = datetime.datetime.utcfromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
        self.observation_ts = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        self.permissions = oct(stat.st_mode)

        self.md5 = Observe.create_hash(file, "md5")
        self.sha1 = Observe.create_hash(file, "sha1")
        self.sha256 = Observe.create_hash(file, "sha256")

    @staticmethod
    def create_hash(file, hash):
        hashers = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
        }
        with open(file, 'rb') as f:
            h = hashers[hash]()
            h.update(f.read())
            return h.hexdigest()

    def set_magic(self, file) -> None:
        self.magic = magic.from_file(file)

    def set_imphash(self, file) -> None:
        pef = pefile.PE(file)
        self.imphash = pef.get_imphash()

    def write_json(self, outfile=None) -> None:
        if not outfile:
            outfile = f"{self.filename}.{self.md5}.json"
        with open(outfile, 'w') as f:
            json.dump(vars(self), f, indent=2)

    def __str__(self) -> str:
        return pprint.pformat(vars(self), indent=2)

    def extract(self) -> None:
        # TODO: add the system heirarchy stuff here
        with tempfile.TemporaryDirectory() as td:
            extr = models.Extractor().extract(self.filename, td)


def main() -> None:
    obs = Observe("/usr/bin/ls")
    print(obs)


if __name__ == "__main__":
    main()
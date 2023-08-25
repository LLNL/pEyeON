# from dataclasses import dataclass, field
import datetime
import hashlib
import json
try:
    import magic
except ImportError:
    print("Is libmagic1 installed on host machine?")
import os
import pefile
import pprint
# from unblob import models
import tempfile
import subprocess
from glob import glob
# TODO: import tika
import lief


def decore() -> None:
    ''' for some reason detect-it-easy generates these big core dumps
    they will fill up the disk if we don't clean them up
    '''
    for rm in glob("core.*"):
        try:
            os.remove(rm)
        except FileNotFoundError:
            pass


class Observe:
    """
    Class to create an Observation of a file.
    Parameters:
        file (str): Path to file to be scanned.

    Required Attributes:
        bytecount (int): sizeof file
        filename (str): File name
        magic (str): Magic byte descriptor
        md5 (str): ``md5sum`` of file
        modtime (str): Datetime string of last modified time
        observation_ts (str): Datetime string of time of scan
        sha1 (str): ``sha1sum`` of file
        sha256 (str): ``sha256sum`` of file
        permissions (str): Octet string of file permission value

    Optional Attributes:
        compiler (str): String describing compiler, compiler version, flags, etc.
        host (str): csv string containing intended install locations
        imphash (str): Import hash. Only valid for Windows binaries.
        # die (str): Detect-It-Easy output.
        # {signature: [cert1, ...]}
        pe_info (dict): Descriptors of PE information, including signatures and certificates.
    """

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

        self.set_pe_info(file)

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

    def set_die(self, file) -> None:
        try:
            dp = os.environ["DIEPATH"]
            self.die = subprocess.run(
                [os.path.join(dp, "diec.sh"), file],
                capture_output=True,
                timeout=10
            ).stdout.decode("utf-8")
        except KeyError:
            print("No $DIEPATH set. See README.md for more information.")
        except Exception as E:  # no file diec
            print(E)

    def set_pe_info(self, file) -> None:
        if lief.is_pe(file):
            pe = lief.parse(file)
            if len(pe.signatures) > 1:
                print("file has multiple signatures")
            for sig in pe.signatures:
                # signinfo = sig.SignerInfo  # this thing is documented but has no constructor defined
                self.signatures[sig.content_info.digest.hex()] = {
                    # "certs": [{
                    #     "version": c.version,
                    #     "serial_number": c.serial_number,
                    #     "issuer": c.issuer_name,
                    #     "subject": c.subject,
                    #     "valid_from": c.valid_from,
                    #     "valid_to": c.valid_to,
                    #     "algorithm": c.signature_algorithm,  # OID format...
                    # } for c in sig.certificates],
                    "certs": [c.__str__() for c in sig.certificates],
                    "signers": sig.signers,
                    "digest_algorithm": sig.digest_algorithm,
                    "verification": sig.check().__str__()
                    # "sections": [s.__str__() for s in pe.sections]
                    # **signinfo,
                }
                



    def write_json(self, outfile=None) -> None:
        if not outfile:
            outfile = f"{self.filename}.{self.md5}.json"
        with open(outfile, 'w') as f:
            json.dump(vars(self), f, indent=2)

    def __str__(self) -> str:
        return pprint.pformat(vars(self), indent=2)

    # def extract(self) -> None:
    #     # TODO: add the system heirarchy stuff here
    #     with tempfile.TemporaryDirectory() as td:
    #         extr = models.Extractor().extract(self.filename, td)



def main() -> None:
    obs = Observe("/usr/bin/ls")
    print(obs)


if __name__ == "__main__":
    main()
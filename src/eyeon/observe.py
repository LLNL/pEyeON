"""
eyeon.observe.Observe makes an observation of a file.
An observation will output a json file containing unique identifying information
  such as hashes, modify date, certificate info, etc.
See the Observe class doc for full details.
"""
import datetime
import hashlib
import json
import os
import pprint
import subprocess

import lief
import logging
from setup_log import logger  # noqa: F401

log = logging.getLogger("eyeon.observe")
# from glob import glob

# import tempfile
# from unblob import models

# def decore() -> None:
#     """for some reason detect-it-easy generates these big core dumps
#     they will fill up the disk if we don't clean them up
#     """
#     for rm in glob("core.*"):
#         try:
#             os.remove(rm)
#         except FileNotFoundError:
#             pass


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
        signatures (dict): Descriptors of signature information,
            including signatures and certificates.
        ssdeep: Fuzzy hash used by VirusTotal to match similar binaries.
    """

    def __init__(self, file: str, log_level: int, log_file: str = None) -> None:
        if log_file:
            self.log = logging.basicConfig(log_file, level=log_level)

        stat = os.stat(file)
        self.bytecount = stat.st_size
        self.filename = os.path.basename(file)  # TODO: split into absolute path maybe?
        self.signatures = {}
        if lief.is_pe(file):
            self.set_imphash(file)
            self.set_signatures(file)
        elif lief.is_elf(file):
            self.set_telfhash(file)
        else:
            self.imphash = "N/A"
            self.signatures = {"valid": "N/A"}
        self.magic = self.set_magic(file)
        self.modtime = datetime.datetime.utcfromtimestamp(stat.st_mtime).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        self.observation_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.permissions = oct(stat.st_mode)

        self.md5 = Observe.create_hash(file, "md5")
        self.sha1 = Observe.create_hash(file, "sha1")
        self.sha256 = Observe.create_hash(file, "sha256")
        self.set_ssdeep(file)

    @staticmethod
    def create_hash(file, hash):
        """
        Generator for hash functions.
        """
        hashers = {
            "md5": hashlib.md5,
            "sha1": hashlib.sha1,
            "sha256": hashlib.sha256,
        }
        with open(file, "rb") as f:
            h = hashers[hash]()
            h.update(f.read())
            return h.hexdigest()

    def set_magic(self, file: str) -> None:
        """
        Reads magic bytes at beginning of file.
        """
        try:
            import magic
        except ImportError:
            self.log.warning("libmagic1 or python-magic is not installed.")
        self.magic = magic.from_file(file)

    def set_imphash(self, file: str) -> None:
        """
        Sets import hash for PE files.
        See
         https://www.mandiant.com/resources/blog/tracking-malware-import-hashing.
        """
        import pefile

        pef = pefile.PE(file)
        self.imphash = pef.get_imphash()

    def set_die(self, file: str) -> None:
        """
        Sets Detect-It-Easy info. WIP
        """
        try:
            dp = os.environ["DIEPATH"]
            self.die = subprocess.run(
                [os.path.join(dp, "diec.sh"), file], capture_output=True, timeout=10
            ).stdout.decode("utf-8")
        except KeyError:
            self.log.warning("No $DIEPATH set. See README.md for more information.")
        except FileNotFoundError:
            self.log.warning("Please install Detect-It-Easy.")
        except Exception as E:
            self.log.error(E)

    def set_signatures(self, file: str) -> None:
        """
        Runs LIEF signature validation and collects certificate chain.
        """
        pe = lief.parse(file)
        if len(pe.signatures) > 1:
            self.log.info("file has multiple signatures")
        self.signatures["valid"] = str(pe.verify_signature())
        self.signatures["signatures"] = {}
        self.authentihash = pe.signatures[0].content_info.digest.hex()
        for sig in pe.signatures:
            # signinfo = sig.SignerInfo
            # this thing is documented but has no constructor defined
            self.signatures["signatures"][sig.content_info.digest.hex()] = {
                """
                 "certs": [{
                    "version": c.version,
                    "serial_number": c.serial_number,
                    "issuer": c.issuer_name,
                    "subject": c.subject,
                    "valid_from": c.valid_from,
                    "valid_to": c.valid_to,
                    "algorithm": c.signature_algorithm,  # OID format...
                 } for c in sig.certificates],
                """
                "certs": [str(c) for c in sig.certificates],
                "signers": str(sig.signers[0]),
                "digest_algorithm": str(sig.digest_algorithm),
                "verification": str(sig.check())
                # "sections": [s.__str__() for s in pe.sections]
                # **signinfo,
            }

    def set_telfhash(self, file: str) -> None:
        """
        Sets telfhash for ELF files.
        See https://github.com/trendmicro/telfhash.
        """
        try:
            import telfhash
        except ModuleNotFoundError:
            self.log.warning("tlsh and telfhash are not installed.")
            return
        self.imphash = telfhash.telfhash(file)[0]["telfhash"]

    def set_ssdeep(self, file: str) -> None:
        """
        Computes fuzzy hashing using ssdeep.
        See https://ssdeep-project.github.io/ssdeep/index.html.
        """
        try:
            out = subprocess.run(["ssdeep", "-b", file], stdout=subprocess.PIPE).stdout.decode(
                "utf-8"
            )
        except FileNotFoundError:
            self.log.warning("ssdeep is not installed.")
            return
        out = out.split("\n")[1]  # header/hash/emptystring
        out = out.split(",")[0]  # hash/filename
        self.ssdeep = out

    def write_json(self, outdir: str = ".") -> None:
        """
        Writes observation to json file.
        :param outdir: output directory prefix. Defaults to local directory.
        """

        outfile = f"{os.path.join(outdir, self.filename)}.{self.md5}.json"
        with open(outfile, "w") as f:
            json.dump(vars(self), f, indent=2)

    def __str__(self) -> str:
        return pprint.pformat(vars(self), indent=2)

    # def extract(self) -> None:
    #     # TODO: add the system heirarchy stuff here
    #     with tempfile.TemporaryDirectory() as td:
    #         extr = models.Extractor().extract(self.filename, td)

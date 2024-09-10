"""
eyeon.observe.Observe makes an observation of a file.
An observation will output a json file containing unique identifying information
such as hashes, modify date, certificate info, etc.
See the Observe class doc for full details.
"""
import hashlib
import json
import os
import pprint
import subprocess
import eyeon.config
from pathlib import Path

import lief
import logging
from .setup_log import logger  # noqa: F401

import eyeon.file

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
    -----------
        file (str): Path to file to be scanned.

    Required Attributes:
    ----------------------
        bytecount : int
            size of file
        filename : str
            File name
        magic : str
            Magic byte descriptor
        md5 : str
            ``md5sum`` of file
        modtime : str
            Datetime string of last modified time
        observation_ts : str
            Datetime string of time of scan
        permissions : str
            Octet string of file permission value
        sha1 : str
            ``sha1sum`` of file
        sha256 : str
            ``sha256sum`` of file
        ssdeep : str
            Fuzzy hash used by VirusTotal to match similar binaries.
        config : dict
            toml configuration file elements

    Optional Attributes:
    -----------------------
        compiler : str
            String describing compiler, compiler version, flags, etc.
        host : str
            csv string containing intended install locations
        imphash : str
            Either Import hash for Windows binaries or telfhash for ELF Linux binaries.
        # die : str
            #Detect-It-Easy output.
        signatures : dict
            Descriptors of signature information, including signatures and certificates. Only
            valid for Windows
        metadata : dict
            Windows File Properties -- OS, Architecture, File Info, etc.
    """

    def __init__(self, file: str, log_level: int = logging.ERROR, log_file: str = None) -> None:
        if log_file:
            fh = logging.FileHandler(log_file)
            fh.setFormatter(
                logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
            )
            logging.getLogger().handlers.clear()  # remove console log
            log.addHandler(fh)
        logging.getLogger().setLevel(log_level)

        #Check file type
        if lief.is_pe(file):
            self.vars=eyeon.file.PE_File(file)
        elif lief.is_elf(file):
            self.vars=eyeon.file.ELF_File(file)
        else:
            self.vars=eyeon.file.File(file)

        #Look for config
        configfile = self.find_config()
        if configfile:
            self.vars.defaults = eyeon.config.ConfigRead(configfile)
        else:
            log.info("toml config not found")
            self.vars.defaults = {}
        log.debug("end of init")

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
            log.warning("No $DIEPATH set. See README.md for more information.")
        except FileNotFoundError:
            log.warning("Please install Detect-It-Easy.")
        except Exception as E:
            log.error(E)

    def find_config(self, dir: str = "."):
        """
        Looks for the toml config file starting in the current directory the tool is run from
        """
        for dirpath, _, filenames in os.walk(dir):
            for file in filenames:
                if file.endswith(".toml") and not file.startswith("pyproject"):
                    return os.path.join(dirpath, file)
        return None

    def _safe_serialize(self, obj) -> str:
        """
        Certs are byte objects, not json.
        This function gives a default value to unserializable data.
        Returns json encoded string where the non-serializable bits are
        a string saying not serializable.

        Parameters:
        -----------
            obj : dict
                Object to serialize.

        """

        def default(o):
            return f"<<non-serializable: {type(o).__qualname__}>>"

        return json.dumps(obj, default=default)

    def write_json(self, outdir: str = ".") -> None:
        """
        Writes observation to json file.

        Parameters:
        -----------
            outdir : str
                Output directory prefix. Defaults to local directory.
        """
        os.makedirs(outdir, exist_ok=True)
        vs = vars(self.vars)
        if "certs" in vs:
            Path(os.path.join(outdir, "certs")).mkdir(parents=True, exist_ok=True)
            for c, b in self.vars.certs.items():
                with open(f"{os.path.join(outdir, 'certs', c)}.crt", "wb") as cert_out:
                    cert_out.write(b)
        outfile = f"{os.path.join(outdir, self.vars.filename)}.{self.vars.md5}.json"
        vs = {k: v for k, v in vs.items() if k != "certs"}
        with open(outfile, "w") as f:
            f.write(self._safe_serialize(vs))

    def __str__(self) -> str:
        return pprint.pformat(vars(self), indent=2)

    # def extract(self) -> None:
    #     # TODO: add the system heirarchy stuff here
    #     with tempfile.TemporaryDirectory() as td:
    #         extr = models.Extractor().extract(self.filename, td)

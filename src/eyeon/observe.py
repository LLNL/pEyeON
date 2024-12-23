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
import eyeon.config
import re
import duckdb
from importlib.resources import files
from pathlib import Path
from uuid import uuid4

import lief
import logging
from .setup_log import logger  # noqa: F401

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
            Import hash for Windows binaries
        telfhash : str
            Telfhash for ELF Linux binaries
        detect_it_easy : str
            Detect-It-Easy output.
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
        self.uuid = str(uuid4())
        stat = os.stat(file)
        self.bytecount = stat.st_size
        self.filename = os.path.basename(file)  # TODO: split into absolute path maybe?
        self.signatures = []
        self.set_detect_it_easy(file)
        if lief.is_pe(file):
            self.set_imphash(file)
            self.certs = {}
            self.set_signatures(file)
            self.set_issuer_sha256()
            self.set_windows_metadata(file)
        elif lief.is_elf(file):
            self.set_telfhash(file)
            self.set_elf_metadata(file)
        elif lief.is_macho(file):
            self.set_macho_metadata(file)
        else:
            self.imphash = "N/A"
        self.set_magic(file)
        self.modtime = datetime.datetime.fromtimestamp(
            stat.st_mtime, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        self.observation_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.permissions = oct(stat.st_mode)

        self.md5 = Observe.create_hash(file, "md5")
        self.sha1 = Observe.create_hash(file, "sha1")
        self.sha256 = Observe.create_hash(file, "sha256")
        self.set_ssdeep(file)
        configfile = self.find_config()
        if configfile:
            self.defaults = eyeon.config.ConfigRead(configfile)
        else:
            log.info("toml config not found")
            self.defaults = {}
        log.debug("end of init")

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
            log.warning("libmagic1 or python-magic is not installed.")
        self.magic = magic.from_file(file)

    def set_imphash(self, file: str) -> None:
        """
        Sets import hash for PE files.
        See https://www.mandiant.com/resources/blog/tracking-malware-import-hashing.
        """
        import pefile

        pef = pefile.PE(file)
        self.imphash = pef.get_imphash()

    def set_detect_it_easy(self, file: str) -> None:
        """
        Sets Detect-It-Easy info.
        """
        try:
            dp = "/usr/bin"
            self.detect_it_easy = subprocess.run(
                [os.path.join(dp, "diec"), file], capture_output=True, timeout=30
            ).stdout.decode("utf-8")
        except KeyError:
            log.warning("No $DIEPATH set. See README.md for more information.")
        except FileNotFoundError:
            log.warning("Please install Detect-It-Easy.")
        except Exception as E:
            log.error(E)

    # @staticmethod
    def _cert_parser(self, cert: lief.PE.x509) -> dict:
        """lief certs are messy. convert to json data"""
        crt = str(cert).split("\n")
        cert_d = {}
        for line in crt:
            if line:  # catch empty string
                try:
                    k, v = re.split("\s+: ", line)  # noqa: W605
                except ValueError:  # not enough values to unpack
                    k = re.split("\s+: ", line)[0]  # noqa: W605
                    v = ""
                except Exception as e:
                    print(line)
                    raise (e)
                k = "_".join(k.split())  # replace space with underscore
                cert_d[k] = v
            cert_d["sha256"] = self.hashit(cert)
        return cert_d

    def set_signatures(self, file: str) -> None:
        """
        Runs LIEF signature validation and collects certificate chain.
        """

        def verif_flags(flag: lief.PE.Signature.VERIFICATION_FLAGS) -> str:
            """
            Map flags to strings
            """
            if flag == 0:
                return "OK"

            VERIFICATION_FLAGS = {
                1: "INVALID_SIGNER",
                2: "UNSUPPORTED_ALGORITHM",
                4: "INCONSISTENT_DIGEST_ALGORITHM",
                8: "CERT_NOT_FOUND",
                16: "CORRUPTED_CONTENT_INFO",
                32: "CORRUPTED_AUTH_DATA",
                64: "MISSING_PKCS9_MESSAGE_DIGEST",
                128: "BAD_DIGEST",
                256: "BAD_SIGNATURE",
                512: "NO_SIGNATURE",
                1024: "CERT_EXPIRED",
                2048: "CERT_FUTURE",
            }
            vf = ""

            for k, v in VERIFICATION_FLAGS.items():
                if flag.value & k:
                    if len(vf):
                        vf += " | "
                    vf += v

            return vf

        pe = lief.parse(file)
        if len(pe.signatures) > 1:
            log.info("file has multiple signatures")
        self.signatures = []
        if not pe.signatures:
            log.info(f"file {file} has no signatures.")
            return

        # perform authentihash computation
        self.authentihash = pe.authentihash(pe.signatures[0].digest_algorithm).hex()

        # verifies signature digest vs the hashed code to validate code integrity
        self.authenticode_integrity = verif_flags(pe.verify_signature())

        # signinfo = sig.SignerInfo
        # this thing is documented but has no constructor defined
        self.signatures = [
            {
                "certs": [self._cert_parser(c) for c in sig.certificates],
                "signers": str(sig.signers[0]),
                "digest_algorithm": str(sig.digest_algorithm),
                "verification": verif_flags(sig.check()),  # gives us more info than a bool on fail
                "sha1": sig.content_info.digest.hex(),
                # "sections": [s.__str__() for s in pe.sections]
                # **signinfo,
            }
            for sig in pe.signatures
        ]

    def set_issuer_sha256(self) -> None:
        """
        Parses the certificates to build issuer_sha256 chain
        The match between issuer and subject name is case insensitive,
         as per RFC 5280 §4.1.2.4 section 7.1
        """
        subject_sha = {}  # dictionary that maps subject to sha256
        for sig in self.signatures:
            for cert in sig["certs"]:  # set mappings
                subject_sha[cert["subject_name"].casefold()] = cert["sha256"]

        for sig in self.signatures:
            for cert in sig["certs"]:  # parse mappings, set issuer sha based on issuer name
                if cert["issuer_name"].casefold() in subject_sha:
                    cert["issuer_sha256"] = subject_sha[cert["issuer_name"].casefold()]

    # @staticmethod
    def hashit(self, c: lief.PE.x509):
        hc = hashlib.sha256()
        hc.update(c.raw)
        hc = hc.hexdigest()
        self.certs[hc] = c.raw
        return hc

    def set_telfhash(self, file: str) -> None:
        """
        Sets telfhash for ELF files.
        See https://github.com/trendmicro/telfhash.
        """
        try:
            import telfhash
        except ModuleNotFoundError:
            log.warning("tlsh and telfhash are not installed.")
            return
        self.telfhash = telfhash.telfhash(file)[0]["telfhash"]

    def set_ssdeep(self, file: str) -> None:
        """
        Computes fuzzy hashing using ssdeep.
        See https://ssdeep-project.github.io/ssdeep/index.html.
        """
        try:
            out = subprocess.run(
                ["ssdeep", "-b", file], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
            ).stdout.decode("utf-8")
        except FileNotFoundError:
            log.warning("ssdeep is not installed.")
            return
        out = out.split("\n")[1]  # header/hash/emptystring
        out = out.split(",")[0]  # hash/filename
        self.ssdeep = out

    def find_config(self, dir: str = "."):
        """
        Looks for the toml config file starting in the current directory the tool is run from
        """
        for dirpath, _, filenames in os.walk(dir):
            for file in filenames:
                if file.endswith(".toml") and not file.startswith("pyproject"):
                    return os.path.join(dirpath, file)
        return None


    def set_windows_metadata(self, file: str) -> None:
        """Finds the metadata from surfactant"""
        from surfactant.infoextractors.pe_file import extract_pe_info

        try:
            self.metadata = extract_pe_info(file)
        except Exception as e:
            print(file, e)
            self.metadata = {}

    def set_elf_metadata(self, file: str) -> None:
        """Finds the metadata from surfactant"""
        from surfactant.infoextractors.elf_file import extract_elf_info

        try:
            test_metadata = extract_elf_info(file)
            counter = 0
            # fix elfnote section
            og_elfnote = test_metadata["elfNote"]
            new_elfnote_dict = dict()

            # iterate through each elfnote dictionary
            for elfnote_dict in og_elfnote:
                # get type
                type_key_value = elfnote_dict["type"]
                # want to create this only if type_key_value has not been seen before
                if type_key_value in new_elfnote_dict:
                    type_key_list = new_elfnote_dict[type_key_value]
                else:
                    type_key_list = []
                new_dict = dict()
                for key in elfnote_dict:
                    if not key == "type":
                        # add to dict
                        new_dict[key] = elfnote_dict[key]
                type_key_list.append(new_dict)
                # add the type_key into the elfNote dict
                new_elfnote_dict[type_key_value] = type_key_list
            new_elfnote = [new_elfnote_dict]
            test_metadata["elfNote"] = new_elfnote
            self.metadata = test_metadata

        except Exception as e:
            print(file, e)
            self.metadata = {}

    def set_macho_metadata(self, file: str) -> None:
        """Finds the metadata from surfactant"""
        from surfactant.infoextractors.mach_o_file import extract_mach_o_info

        try:
            self.metadata = extract_mach_o_info(file)
        except Exception as e:
            print(file, e)
            self.metadata = {}

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
        vs = vars(self)
        if "certs" in vs:
            Path(os.path.join(outdir, "certs")).mkdir(parents=True, exist_ok=True)
            for c, b in self.certs.items():
                with open(f"{os.path.join(outdir, 'certs', c)}.crt", "wb") as cert_out:
                    cert_out.write(b)
        outfile = f"{os.path.join(outdir, self.filename)}.{self.md5}.json"
        vs = {k: v for k, v in vs.items() if k != "certs"}
        with open(outfile, "w") as f:
            f.write(self._safe_serialize(vs))

    def write_database(self, database: str, outdir: str = ".") -> None:
        """
        Creates or loads json file into duckdb database

        Parameters:
        -----------
            database : str
                Path to duckdb database file.
            outdir : str
                Output directory prefix. Defaults to current working directory.
        """
        observation_json = f"{os.path.join(outdir, self.filename)}.{self.md5}.json"
        if os.path.exists(observation_json):
            try:
                if not os.path.exists(database):  # create the table if database is new
                    # create table and views from sql
                    db_path = os.path.dirname(database)
                    if db_path != "":
                        os.makedirs(db_path, exist_ok=True)
                    con = duckdb.connect(database)  # creates or connects
                    con.sql(files("database").joinpath("eyeon-ddl.sql").read_text())
                else:
                    con = duckdb.connect(database)  # creates or connects
                # add the file to the observations table, making it match template
                # observations with missing keys will get null vals as placeholder to match sql
                con.sql(
                    f"""
                insert into observations by name
                select * from
                read_json_auto(['{observation_json}',
                                '{files('database').joinpath('observations.json')}'],
                                union_by_name=true, auto_detect=true)
                where filename is not null;
                """
                )
                con.close()
            except duckdb.IOException as ioe:
                con = None
                s = f":exclamation: Failed to attach to db {database}: {ioe}"
                print(s)
        else:
            raise FileNotFoundError

    def __str__(self) -> str:
        return pprint.pformat(vars(self), indent=2)

    # def extract(self) -> None:
    #     # TODO: add the system heirarchy stuff here
    #     with tempfile.TemporaryDirectory() as td:
    #         extr = models.Extractor().extract(self.filename, td)

import lief
import os
import hashlib
import datetime
import re
import subprocess

from uuid import uuid4

class File:
    '''
    Create base observations for each file
    '''
    def __init__(self, file:str) -> None:
        #want to have all the attributes for any type of file defined here
        # self.file = file
        self.filename = os.path.basename(file)
        # self.file_type="unknown"
        self.uuid = str(uuid4())
        self.bytecount = self.get_byte_count(file)
        self.signatures = []
        self.imphash = "N/A"
        self.md5=self.create_hash(file, "md5")
        self.sha1=self.create_hash(file, "sha1")
        self.sha256=self.create_hash(file, "sha256")
        self.get_file_time(file)
        self.set_magic(file)
        self.set_ssdeep(file)
    
    def get_byte_count(self, file):
        stat = os.stat(file)
        return stat.st_size
    
    def get_file_time(self, file):
        stat = os.stat(file)
        self.modtime = datetime.datetime.fromtimestamp(
            stat.st_mtime, tz=datetime.timezone.utc
        ).strftime("%Y-%m-%d %H:%M:%S")
        self.observation_ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.permissions = oct(stat.st_mode)

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
            print("libmagic1 or python-magic is not installed.")
        self.magic = magic.from_file(file)    

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
            print("ssdeep is not installed.")
            return
        out = out.split("\n")[1]  # header/hash/emptystring
        out = out.split(",")[0]  # hash/filename
        self.ssdeep = out    


class PE_File(File):
    '''
    Create base observations for PE file
    '''
    def __init__(self, file: str) -> None:
        #PE specific stuff
        self.certs = {}
        self.set_windows_metadata(file)
        # print(self.metadata)

        super().__init__(file)
        # print(self.uuid)
        # print(self.bytecount)
        # print(self.md5)
        # print(self.modtime)
        # print(self.permissions)
        self.set_imphash(file)
        # print(self.imphash)
        self.set_signatures(file)
        # print(self.signatures)
        self.set_issuer_sha256()

    def set_imphash(self, file: str) -> None:
        """
        Sets import hash for PE files.
        See https://www.mandiant.com/resources/blog/tracking-malware-import-hashing.
        """
        import pefile

        pef = pefile.PE(file)
        self.imphash = pef.get_imphash()

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
    
    def hashit(self, c: lief.PE.x509):
        hc = hashlib.sha256()
        hc.update(c.raw)
        hc = hc.hexdigest()
        self.certs[hc] = c.raw
        return hc

    def set_signatures(self, file: str) -> None:
        """
        Runs LIEF signature validation and collects certificate chain.
        """
        pe = lief.parse(file)
        if len(pe.signatures) > 1:
            print("file has multiple signatures")
        self.signatures = []
        if not pe.signatures:
            print(f"file {file} has no signatures.")
            return

        # perform authentihash computation
        self.authentihash = pe.authentihash(pe.signatures[0].digest_algorithm).hex()

        # verifies signature digest vs the hashed code to validate code integrity
        self.authenticode_integrity = str(pe.verify_signature())

        # signinfo = sig.SignerInfo
        # this thing is documented but has no constructor defined
        self.signatures = [
            {
                "certs": [self._cert_parser(c) for c in sig.certificates],
                "signers": str(sig.signers[0]),
                "digest_algorithm": str(sig.digest_algorithm),
                "verification": str(sig.check()),  # gives us more info than a bool on fail
                "sha1": sig.content_info.digest.hex()
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

    def set_windows_metadata(self, file: str) -> None:
        """Finds the metadata from surfactant"""
        from surfactant.infoextractors.pe_file import extract_pe_info

        try:
            self.metadata = extract_pe_info(file)
        except Exception as e:
            print(file, e)
            self.metadata = {}

class ELF_File(File):
    '''
    Create base observations for ELF file
    '''
    def __init__(self, file: str) -> None:
        #ELF specific attrs here
        super().__init__(file)
        self.set_telfhash(file)
        print(self.uuid)
        print(self.bytecount)
        print(self.md5)

    def set_telfhash(self, file: str) -> None:
        """
        Sets telfhash for ELF files.
        See https://github.com/trendmicro/telfhash.
        """
        try:
            import telfhash
        except ModuleNotFoundError:
            print("tlsh and telfhash are not installed.")
            return
        self.imphash = telfhash.telfhash(file)[0]["telfhash"]
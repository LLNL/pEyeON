from dataclasses import dataclass
import datetime
import hashlib
import magic
import os
import pefile


@dataclass
class Observation:
    # required fields
    bytecount: int
    filename: str
    magic: str
    md5: str
    modtime: datetime.datetime
    observation_ts: datetime.datetime
    sha1: str
    sha256: str
    permissions: int  # needs to be in octal for reading

    # optional fields
    compiler: str
    host: list
    imphash: str

    def __init__(self, file) -> None:
        stat = os.stat(file)
        self.modtime = stat.st_mtime
        self.observation_ts = datetime.datetime.now()
        self.permissions = stat.st_mode
        with open(file, 'rb') as f:
            self.set_magic(f)
            self.set_md5(f)
            self.set_sha1(f)
            self.set_sha256(f)
            self.set_imphash(f)

    def set_magic(self, file) -> None:
        self.magic = magic.from_file(file)

    def set_md5(self, file) -> None:
        md5 = hashlib.md5()
        md5.update()

    def set_sha1(self, file) -> None:
        pass

    def set_sha256(self, file) -> None:
        pass

    def set_imphash(self, file) -> None:
        pef = pefile.PE(file)
        self.imphash = pef.get_imphash()

    def write_json(self) -> None:
        pass




    

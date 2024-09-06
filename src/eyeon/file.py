import lief
import os
import hashlib
import datetime

from uuid import uuid4

class File:
    '''
    Create base observations for each file
    '''
    def __init__(self, file:str) -> None:
        #want to have all the attributes for any type of file defined here
        self.file = file
        self.filename = os.path.basename(file)
        self.file_type="unknown"
        self.uuid = str(uuid4())
        self.bytecount = self.get_byte_count()
        self.signatures = []
        self.imphash = "N/A"
        self.md5=self.create_hash(file, "md5")
        self.sha1=self.create_hash(file, "sha1")
        self.sha256=self.create_hash(file, "sha256")
        self.get_file_time()
    
    def get_byte_count(self):
        stat = os.stat(self.file)
        return stat.st_size
    
    def get_file_time(self):
        stat = os.stat(self.file)
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


class PE_File(File):
    '''
    Create base observations for PE file
    '''
    def __init__(self, file: str) -> None:
        #PE specific attrs here
        super().__init__(file)
        print(self.uuid)
        print(self.bytecount)
        print(self.md5)
        print(self.modtime)
        print(self.permissions)

class ELF_File(File):
    '''
    Create base observations for ELF file
    '''
    def __init__(self, file: str) -> None:
        #ELF specific attrs here
        super().__init__(file)
        print(self.uuid)
        print(self.bytecount)
        print(self.md5)
import unittest
import datetime as dt
import os
import json
import jsonschema
import logging
import lief
import sys
from io import StringIO

from eyeon import parse
from eyeon import observe

# this is a superclass that runs common assertions for each
#   of the 2 different certificate corruptions below
class BadSignaturesTestCase(unittest.TestCase):

    @classmethod
    def corrupt(cls, skip, binpath, badbinpath):
        # change some of the data in notepad++.exe to break signature
        writelen = 500 # overwrite some of the bytes

        # open one for read and one for write
        binary = open(binpath, "rb")
        corrupted = open(badbinpath, "wb")

        # get the first chunk and write to corrupted file
        chunk1 = binary.read(skip)
        corrupted.write(chunk1)
        corrupted.write(bytes([0x33] * writelen)) # overwrite some bytes

        # write rest of file
        binary.seek(skip+writelen)
        corrupted.write(binary.read())

        binary.close()
        corrupted.close()

        if not os.path.exists(badbinpath):
            assert False, f"Failed to create {badbinpath}"


    def scan(self, badbinpath):
        # scan the corrupted notepad++.exe
        self.OBS = observe.Observe(
                badbinpath,
                log_level=logging.INFO,
                log_file="testBadSignatures.log"
                )


    def varsExe(self, md5, sha1, sha256, filename, magic, bytecount) -> None:
        # verify hashes and see if verification broke properly
        self.assertEqual(self.OBS.bytecount, bytecount)
        self.assertEqual(self.OBS.filename, filename)
        self.assertEqual(self.OBS.md5, md5)
        self.assertEqual(self.OBS.sha1, sha1)
        self.assertEqual(self.OBS.sha256, sha256)
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.magic, magic)

        # signature failure check
        self.assertEqual(self.OBS.signatures[0]["verification"], False)

    def configJson(self) -> None:
        vs = vars(self.OBS)
        obs_json = json.loads(self.OBS._safe_serialize(vs))
        assert "defaults" in obs_json, "defaults not in json"

    def validateSchema(self) -> None:
        with open("../schema/observation.schema.json") as schem:
            schema = json.loads(schem.read())

        with open("../schema/meta.schema.json") as schem:
            meta = json.loads(schem.read())

        print(jsonschema.validate(instance=schema, schema=meta))

    @classmethod
    def tearDownClass(cls):
        os.remove("./testBadSignatures.log")


class NotepadFirstCertCorrupt(BadSignaturesTestCase):

    def setUp(self):
        # path for reading original, and path for writing exe with broken cert
        self.binpath = "./binaries/x86/notepad++/notepad++.exe"
        self.badbinpath = "./binaries/x86/notepad++/notepad++_corrupted.exe" 

        # corrupt the first cert, write bad binary, and scan
        self.corrupt(0x00615FC0, self.binpath, self.badbinpath) # location of first cert
        self.scan(self.badbinpath)

    def testSuper(self):
        md5 = "09ec21d51a66e06788179336589488a1"
        sha1 = "b3f4d9d18ccb23705992109a871bf0541a9d20d6"
        sha256 = "4e434a9fb8bfbb15a5fac7a33c882ec91a05427b35c55e17fd82e030548b4b3f"
        magic = "PE32 executable (GUI) Intel 80386, for MS Windows"
        bytecount = 6390616
        filename = self.badbinpath.rsplit('/', maxsplit=1)[-1]
        self.varsExe(md5, sha1, sha256, filename,  magic, bytecount)
        self.configJson()
        self.validateSchema()

    def tearDown(self):
        os.remove(self.badbinpath)


class NotepadSecondCertCorrupt(BadSignaturesTestCase):
    def setUp(self):
        self.binpath = "./binaries/x86/notepad++/notepad++.exe"
        self.badbinpath = "./binaries/x86/notepad++/notepad++_corrupted.exe"
        self.corrupt(0x006162A0, self.binpath, self.badbinpath) # location of second cert
        self.scan(self.badbinpath)

    def testSuper(self):
        md5 = "ae8c330902a79edf97526ba2fbe452a0"
        sha1 = "cae1d9471f7413f9219ddcf6fd9c986e81a95f75"
        sha256 = "2f11aaa964206882823348915b08b8106f95ce17bb5491fede7932466f85c31c"
        magic = "PE32 executable (GUI) Intel 80386, for MS Windows"
        bytecount = 6390616
        filename = self.badbinpath.rsplit('/', maxsplit=1)[-1]
        self.varsExe(md5, sha1, sha256, filename, magic, bytecount)
        self.configJson()
        self.validateSchema()

    def tearDown(self):
        os.remove(self.badbinpath)


class CurlFirstCertCorrupt(BadSignaturesTestCase):
    def setUp(self):
        self.binpath = "./binaries/arm/curl-8.8.0_1-win64arm-mingw.exe"
        self.badbinpath = "./binaries/arm/curl-8.8.0_1-win64arm-mingw_corrupted.exe"
        self.corrupt(0x00315BB0, self.binpath, self.badbinpath) # location of first cert
        self.scan(self.badbinpath)

    def testSuper(self):
        md5 = "33ab10b10a9270c61dfb9df2e1e71413"
        sha1 = "68c4acb734d0cfdde2b75020e5fd1a64e91553b2"
        sha256 = "34985fc11dc4875c0d7f6b03be601225e99b527202e34ec3ceef6cd270b30c3c"
        magic = "PE32+ executable (console) Aarch64, for MS Windows"
        bytecount = 3237992
        filename = self.badbinpath.rsplit('/', maxsplit=1)[-1]
        self.varsExe(md5, sha1, sha256, filename, magic, bytecount)
        self.configJson()
        self.validateSchema()

    def tearDown(self):
        os.remove(self.badbinpath)

if __name__ == "__main__":
    unittest.main()

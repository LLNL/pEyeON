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
    def corrupt(cls, skip):
        # change some of the data in notepad++.exe to break signature
        writelen = 500 # overwrite some of the bytes

        # open one for read and one for write
        notepad = open("./notepad++/notepad++/notepad++.exe", "rb")
        corrupted = open("./notepad++/notepad++/notepad++_corrupted.exe", "wb")

        # get the first chunk and write to corrupted file
        chunk1 = notepad.read(skip)
        corrupted.write(chunk1)
        corrupted.write(bytes([0x33] * writelen)) # overwrite some bytes

        # write rest of file
        notepad.seek(skip+writelen)
        corrupted.write(notepad.read())

        notepad.close()
        corrupted.close()

        if not os.path.exists("./notepad++/notepad++/notepad++_corrupted.exe"):
            assert False, "Failed to create notepad++_corrupted.exe"


    def scan(self):
        # scan the corrupted notepad++.exe
        self.OBS = observe.Observe(
                "./notepad++/notepad++/notepad++_corrupted.exe",
                log_level=logging.INFO,
                log_file="testBadSignatures.log"
                )


    def varsExe(self, md5, sha1, sha256) -> None:
        # verify hashes and see if verification broke properly
        self.assertEqual(self.OBS.bytecount, 6390616)
        self.assertEqual(self.OBS.filename, 'notepad++_corrupted.exe')
        self.assertEqual(self.OBS.md5, md5)
        self.assertEqual(self.OBS.sha1, sha1)
        self.assertEqual(self.OBS.sha256, sha256)
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(
            self.OBS.magic,
            "PE32 executable (GUI) Intel 80386, for MS Windows",
        )

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
        os.remove("./notepad++/notepad++/notepad++_corrupted.exe")
        os.remove("./testBadSignatures.log")


class FirstCertCorrupt(BadSignaturesTestCase):
    def setUp(self):
        self.corrupt(0x00615FC0) # location of first cert
        self.scan()

    def testSuper(self):
        md5 = "09ec21d51a66e06788179336589488a1"
        sha1 = "b3f4d9d18ccb23705992109a871bf0541a9d20d6"
        sha256 = "4e434a9fb8bfbb15a5fac7a33c882ec91a05427b35c55e17fd82e030548b4b3f"
        self.varsExe(md5, sha1, sha256)
        self.configJson()
        self.validateSchema()

class SecondCertCorrupt(BadSignaturesTestCase):
    def setUp(self):
        self.corrupt(0x006162A0) # location of second cert
        self.scan()

    def testSuper(self):
        md5 = "ae8c330902a79edf97526ba2fbe452a0"
        sha1 = "cae1d9471f7413f9219ddcf6fd9c986e81a95f75"
        sha256 = "2f11aaa964206882823348915b08b8106f95ce17bb5491fede7932466f85c31c"
        self.varsExe(md5, sha1, sha256)
        self.configJson()
        self.validateSchema()


    


if __name__ == "__main__":
    unittest.main()

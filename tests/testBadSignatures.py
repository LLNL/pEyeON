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


class BadSignatures(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        # change some of the data in notepad++.exe to break signature
        skip = 0x00615FC0 # skip to where one of the certs is
        writelen = 1000 # overwrite some of the bytes

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


    @classmethod
    def setUp(self):
        # get STDOUT to a check that it prints "Can't find certificate" string
        capture = StringIO()
        sys.stdout = capture

        # scan the corrupted notepad++.exe
        self.OBS = observe.Observe(
                "./notepad++/notepad++/notepad++_corrupted.exe",
                log_level=logging.INFO,
                log_file="testBadSignatures.log"
                )

        # reset STDOUT
        sys.stdout = sys.__stdout__

        self.assertIn(
                "Can't find certificate for which the issuer is ",
                 capture.getvalue(),
                "Failed: Did not print 'Can't find certificate for bad issuer message'")

        capture.close()


    def testVarsExe(self) -> None:
        # mostly same check, with new hashes
        self.assertEqual(self.OBS.bytecount, 6390616)
        self.assertEqual(self.OBS.filename,'notepad++_corrupted.exe')
        self.assertEqual(self.OBS.md5, "65d1231662c5b27659a6244f514de629")
        self.assertEqual(self.OBS.sha1, "e130eab78f70c456d9baf8512411e0df3368174f")
        self.assertEqual(
                self.OBS.sha256, "2501f29b609b2b54678c2529f813a07f2f4593ad7c10d535e0a47e924f8ecf15"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(
            self.OBS.magic,
            "PE32 executable (GUI) Intel 80386, for MS Windows",
        )
        self.assertEqual(
            self.OBS.ssdeep,
            "98304:kq6vzyzgvZe2fwa5T3CWxeKNn5pRD4RnzY/moFJ:V6vzhUfa5fnws5",
        )

        # signature failure check
        self.assertEqual(self.OBS.signatures[0]["verification"], False)

    @classmethod
    def tearDownClass(cls):
        os.remove("./notepad++/notepad++/notepad++_corrupted.exe")
        os.remove("./testBadSignatures.log")


if __name__ == "__main__":
    unittest.main()

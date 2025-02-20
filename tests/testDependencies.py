import os
import unittest
import logging
from glob import glob
import datetime as dt
import subprocess
import telfhash

import json

from eyeon import observe

import jsonschema

# class TestLIEF(unittest.TestCase):
#     @classmethod
#     def setUp(self) -> None:
#         self.OBS = observe.Observe("./binaries/a_out_files/big_m68020.aout")

#     def testIsPE(self) -> None:
#         self.assertEqual(self.OBS.bytecount, 4)
#         self.assertEqual(self.OBS.filename, "big_m68020.aout")
#         self.assertEqual(self.OBS.md5, "e8d3808a4e311a4262563f3cb3a31c3e")
#         self.assertEqual(self.OBS.sha1, "fbf8688fbe1976b6f324b0028c4b97137ae9139d")
#         self.assertEqual(
#             self.OBS.sha256, "9e125f97e5f180717096c57fa2fdf06e71cea3e48bc33392318643306b113da4"
#         )
#         try:
#             dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
#         except ValueError:
#             self.fail()
#         self.assertIsInstance(self.OBS.observation_ts, str)
#         self.assertEqual(self.OBS.permissions, "0o100644")

#     def testisElf(self) -> None:
#         pass
    
#     def testIsMacho(self) -> None:
#         pass

#     def testCertParser(self) -> None:
#         pass

#     def testSignatureValidation(self) -> None:
#         pass

#     @classmethod
#     def tearDownClass(self) -> None:
#         try:
#             for j in glob("*.json"):
#                 os.remove(j)
#         except FileNotFoundError:
#             pass


class TestTelfhash(unittest.TestCase):
    def setUp(self) -> None:
        self.ELF_file = "./tests/binaries/ELF_shared_obj_test_no1/bin/hello_world"

    def testTelfhash(self) -> None:
        self.OBS = observe.Observe("./binaries/ELF_shared_obj_test_no1/bin/hello_world")
        telfhash2 = telfhash.telfhash(self.ELF_file)[0]["telfhash"]
        self.assertEqual(self.OBS.telfhash, telfhash2)

class TestPythonMagic(unittest.TestCase):
    def setUp(self) -> None:
        self.test_files = [
            "./binaries/a_out_files/big_m68020.aout",
            "../Photo/EyeON_Mascot.png",
            "./binaries/README.md",
            "./empty.txt"
        ]

    def testMagic(self) -> None:
        try:
            for test_file in self.test_files:
                with self.subTest(file=test_file):
                    fileMagic = subprocess.run(
                        ["file", test_file], 
                        capture_output=True, 
                        text=True
                )
                    fileMagicOutput = fileMagic.stdout.split(":", 1) [-1].strip()
                    
                    self.OBS = observe.Observe(test_file)
                    self.assertEqual(self.OBS.magic, fileMagicOutput)
        except ImportError as e:
            logger.warning("Missing dependency: Make sure python-magic is installed")
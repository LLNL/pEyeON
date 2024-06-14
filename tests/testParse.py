import unittest
import os
import shutil
import json
import jsonschema
import logging
import time

from eyeon import parse


class ParseTestCase(unittest.TestCase):

    def checkOutputs(self) -> None:  # these files + paths should be created by parse
        self.assertTrue(os.path.exists("./results"))
        self.assertTrue(os.path.exists("./results/certs"))
        self.assertTrue(os.path.exists
                        ("./results/notepad++.exe.0ec33611cb6594903ff88d47c78dcdab.json"))

    def certExtracted(self) -> None:
        self.assertTrue(os.path.exists("./results/certs/46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b.crt"))  # noqa: E501
        self.assertTrue(os.path.exists("./results/certs/866b46dc0876c0b9c85afe6569e49352a021c255c8e7680df6ac1fdbad677033.crt"))  # noqa: E501

    def validateJson(self) -> None:
        with open("./results/notepad++.exe.0ec33611cb6594903ff88d47c78dcdab.json") as schem:
            schema = json.loads(schem.read())
        self.assertEqual(schema['bytecount'], 6390616)
        self.assertEqual(schema['filename'], 'notepad++.exe')
        self.assertEqual(schema['md5'], "0ec33611cb6594903ff88d47c78dcdab")
        self.assertEqual(schema['sha1'], "28a2a37cf2e9550a699b138dddba4b8067c8e1b1")
        self.assertEqual(
            schema['sha256'], "ccb4ff6b20689d948233807a67d9de9666229625aa6682466ef01917b01ccd3b"
        )


class SinglethreadTest(ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./binaries/x86/notepad++/",
                               logging.WARNING,
                               "./testParse.log")
        self.PRS()  # run scan

    def testCommon(self):
        self.checkOutputs()
        self.certExtracted()
        self.validateJson()

    def testLogCreated(self):
        self.assertTrue(os.path.exists("./testParse.log"))

    @classmethod
    def tearDownClass(self) -> None:
        os.remove("./testParse.log")


class TwoThreadTestCase(ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./binaries/x86/notepad++")
        self.PRS(threads=2)
        time.sleep(1)  # these multithreaded tests create a race condition

    def testCommon(self):
        self.checkOutputs()
        self.certExtracted()
        self.validateJson()


class ThreeThreadTestCase(ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./binaries/x86/notepad++")
        self.PRS(threads=3)
        time.sleep(1)

    def testCommon(self):
        self.checkOutputs()
        self.certExtracted()
        self.validateJson()


if __name__ == "__main__":
    unittest.main()

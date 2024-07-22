import unittest
import os
import shutil
import json
import logging

from eyeon import parse


class X86ParseTestCase(unittest.TestCase):

    def checkOutputs(self) -> None:  # these files + paths should be created by parse
        self.assertTrue(os.path.isdir("./testresults"))
        self.assertTrue(os.path.isdir("./testresults/certs"))
        self.assertTrue(os.path.isfile(
            "./testresults/notepad++.exe.0ec33611cb6594903ff88d47c78dcdab.json"))
        self.assertTrue(os.path.isfile(
            "./testresults/7z_win32.exe.8515170956d36ef9da3082a7c22e8213.json"))

    def certExtracted(self) -> None:
        self.assertTrue(os.path.isfile("./testresults/certs/46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b.crt"))  # noqa: E501
        self.assertTrue(os.path.isfile("./testresults/certs/866b46dc0876c0b9c85afe6569e49352a021c255c8e7680df6ac1fdbad677033.crt"))  # noqa: E501

    def validateNotepadJson(self) -> None:
        with open("./testresults/notepad++.exe.0ec33611cb6594903ff88d47c78dcdab.json") as schem:
            schema = json.loads(schem.read())
        self.assertEqual(schema['bytecount'], 6390616)
        self.assertEqual(schema['filename'], "notepad++.exe")
        self.assertEqual(schema['md5'], "0ec33611cb6594903ff88d47c78dcdab")
        self.assertEqual(schema['sha1'], "28a2a37cf2e9550a699b138dddba4b8067c8e1b1")
        self.assertEqual(
            schema['sha256'], "ccb4ff6b20689d948233807a67d9de9666229625aa6682466ef01917b01ccd3b"
        )
        self.assertEqual(schema['authenticode_integrity'], "OK")
        self.assertEqual(schema['signatures'][0]["verification"], "OK")
        self.assertEqual(schema['authentihash'], schema['signatures'][0]["sha1"])

        self.assertNotIn(  # check that the first cert has no issuer in the chain
            "issuer_sha256",
            schema['signatures'][0]["certs"][0]
        )
        self.assertEqual(  # check that the second cert has the first issuer's sha
            schema['signatures'][0]["certs"][1]["issuer_sha256"],
            "46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b"
        )

    def validate7zipJson(self) -> None:
        with open("./testresults/7z_win32.exe.8515170956d36ef9da3082a7c22e8213.json") as schem:
            schema = json.loads(schem.read())
        self.assertEqual(schema['bytecount'], 1330263)
        self.assertEqual(schema['filename'], "7z_win32.exe")
        self.assertEqual(schema['md5'], "8515170956d36ef9da3082a7c22e8213")
        self.assertEqual(schema['sha1'], "66c835bdf217d1ceb2d73f7b8b27d7ccca212b38")
        self.assertEqual(
            schema['sha256'], "1ea62e6b152e4b7dbadf45289e04bf4ea7431c7928a9b3c6ba5e4c06fe368085"
        )
        self.assertFalse(schema['signatures'])  # 7zip has no signatures

    @classmethod
    def tearDownClass(self) -> None:
        shutil.rmtree("./testresults")


class X86SinglethreadTestCase(X86ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./binaries/x86/",
                               logging.WARNING,
                               "./testParse.log")
        self.PRS(result_path="testresults")  # run scan

    def testCommon(self):
        self.checkOutputs()
        self.certExtracted()
        self.validateNotepadJson()
        self.validate7zipJson()

    def testLogCreated(self):
        self.assertTrue(os.path.isfile("./testParse.log"))

    @classmethod
    def tearDownClass(self) -> None:
        shutil.rmtree("./testresults")
        os.remove("./testParse.log")


class X86TwoThreadTestCase(X86ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./binaries/x86/")
        self.PRS(result_path="testresults", threads=2)

    def testCommon(self):
        self.checkOutputs()
        self.certExtracted()
        self.validateNotepadJson()
        self.validate7zipJson()


class X86ThreeThreadTestCase(X86ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./binaries/x86/")
        self.PRS(result_path="testresults", threads=3)

    def testCommon(self):
        self.checkOutputs()
        self.certExtracted()
        self.validateNotepadJson()
        self.validate7zipJson()


if __name__ == "__main__":
    unittest.main()

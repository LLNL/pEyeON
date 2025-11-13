import unittest
import os
import shutil
import json
import logging

from eyeon import parse


class X86ParseTestCase(unittest.TestCase):
    def checkOutputs(self) -> None:  # these files + paths should be created by parse
        self.assertTrue(os.path.isdir("./tests/testresults"))
        self.assertTrue(os.path.isdir("./tests/testresults/certs"))
        self.assertTrue(
            os.path.isfile("./tests/testresults/Wintap.exe.2950c0020a37b132718f5a832bc5cabd.json")
        )
        self.assertTrue(
            os.path.isfile(
                "./tests/testresults/WintapSetup.msi.f06087338f3b3e301d841c29429a1c99.json"
            )
        )

    def certExtracted(self) -> None:
        self.assertTrue(
            os.path.isfile(
                "./tests/testresults/certs/552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988.crt"  # noqa: E501
            )
        )
        self.assertTrue(
            os.path.isfile(
                "./tests/testresults/certs/33846b545a49c9be4903c60e01713c1bd4e4ef31ea65cd95d69e62794f30b941.crt"  # noqa: E501
            )
        )  # noqa: E501

    def validateWintapExeJson(self) -> None:
        with open("./tests/testresults/Wintap.exe.2950c0020a37b132718f5a832bc5cabd.json") as schem:
            schema = json.loads(schem.read())
        self.assertEqual(schema["bytecount"], 201080)
        self.assertEqual(schema["filename"], "Wintap.exe")
        self.assertEqual(schema["md5"], "2950c0020a37b132718f5a832bc5cabd")
        self.assertEqual(schema["sha1"], "1585373cc8ab4f22ce6e553be54eacf835d63a95")
        self.assertEqual(
            schema["sha256"], "bdd73b73b50350a55e27f64f022db0f62dd28a0f1d123f3468d3f0958c5fcc39"
        )
        self.assertEqual(schema["authenticode_integrity"], "OK")
        self.assertEqual(schema["signatures"][0]["verification"], "OK")
        self.assertEqual(schema["authentihash"], schema["signatures"][0]["sha1"])

        self.assertNotIn(  # check that the first cert has no issuer in the chain
            "issuer_sha256", schema["signatures"][0]["certs"][0]
        )
        self.assertEqual(  # check that the second cert has the first issuer's sha
            schema["signatures"][0]["certs"][1]["issuer_sha256"],
            "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988",
        )

    def validateWintapSetupMsiJson(self) -> None:
        with open(
            "./tests/testresults/WintapSetup.msi.f06087338f3b3e301d841c29429a1c99.json"
        ) as schem:
            schema = json.loads(schem.read())
        self.assertEqual(schema["bytecount"], 13679616)
        self.assertEqual(schema["filename"], "WintapSetup.msi")
        self.assertEqual(schema["md5"], "f06087338f3b3e301d841c29429a1c99")
        self.assertEqual(schema["sha1"], "ffb3f6b7d55dfbd293a922e2bfa7ba0110d2ff9c")
        self.assertEqual(
            schema["sha256"], "7bc438c474f01502c7f6e2447b7c525888c86c25c4d0703495c20fe22a71ddc0"
        )
        self.assertFalse(schema["signatures"])  # WintapSetup.msi has no signatures

    @classmethod
    def tearDownClass(self) -> None:
        shutil.rmtree("./tests/testresults")


class X86SinglethreadTestCase(X86ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./tests/binaries", logging.WARNING, "./tests/testParse.log")
        self.PRS(result_path="tests/testresults")  # run scan

    def testCommon(self):
        self.checkOutputs()
        self.certExtracted()
        self.validateWintapExeJson()
        self.validateWintapSetupMsiJson()

    def testLogCreated(self):
        self.assertTrue(os.path.isfile("./tests/testParse.log"))

    @classmethod
    def tearDownClass(self) -> None:
        shutil.rmtree("./tests/testresults")
        os.remove("./tests/testParse.log")


class X86TwoThreadTestCase(X86ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./tests/binaries")
        self.PRS(result_path="tests/testresults", threads=2)

    def testCommon(self):
        self.checkOutputs()
        self.certExtracted()
        self.validateWintapExeJson()
        self.validateWintapSetupMsiJson()


class X86ThreeThreadTestCase(X86ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./tests/binaries")
        self.PRS(result_path="tests/testresults", threads=3)

    def testCommon(self):
        self.checkOutputs()
        self.certExtracted()
        self.validateWintapExeJson()
        self.validateWintapSetupMsiJson()


if __name__ == "__main__":
    unittest.main()

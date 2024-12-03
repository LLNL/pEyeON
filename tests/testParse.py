import unittest
import os
import shutil
import json
import logging

from eyeon import parse


class X86ParseTestCase(unittest.TestCase):
    def checkOutputs(self) -> None:  # these files + paths should be created by parse
        self.assertTrue(os.path.isdir("./results"))
        self.assertTrue(os.path.isdir("./results/certs"))
        self.assertTrue(
            os.path.isfile("./results/hello_world.exe.c1550ecc547c89b2f24599c990a29184.json")
        )
        self.assertTrue(
            os.path.isfile("./results/testlib.dll.17b7ca694f2e1e307127c7b653ed294f.json")
        )

    # def certExtracted(self) -> None:
    #     self.assertTrue(
    #         os.path.isfile(
    #             "./testresults/certs/46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b.crt"  # noqa: E501
    #         )
    #     )
    #     self.assertTrue(
    #         os.path.isfile(
    #             "./testresults/certs/866b46dc0876c0b9c85afe6569e49352a021c255c8e7680df6ac1fdbad677033.crt"  # noqa: E501
    #         )
    #     )  # noqa: E501

    def validateHelloWorldJson(self) -> None:
        with open("./results/hello_world.exe.c1550ecc547c89b2f24599c990a29184.json") as schem:
            schema = json.loads(schem.read())
        self.assertEqual(schema["bytecount"], 58880)
        self.assertEqual(schema["filename"], "hello_world.exe")
        self.assertEqual(schema["md5"], "c1550ecc547c89b2f24599c990a29184")
        self.assertEqual(schema["sha1"], "e4e8ecba8d39ba23cf6f13498021049d62c3659c")
        self.assertEqual(
            schema["sha256"], "de22b757eaa0ba2b79378722e8057d3052edc87caf543b17d8267bd2713162a8"
        )
        # self.assertEqual(schema["authenticode_integrity"], "OK")
        # self.assertEqual(schema["signatures"][0]["verification"], "OK")
        # self.assertEqual(schema["authentihash"], schema["signatures"][0]["sha1"])

        # self.assertNotIn(  # check that the first cert has no issuer in the chain
        #     "issuer_sha256", schema["signatures"][0]["certs"][0]
        # )
        # self.assertEqual(  # check that the second cert has the first issuer's sha
        #     schema["signatures"][0]["certs"][1]["issuer_sha256"],
        #     "46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b",
        # )

    def validateTestLibDllJson(self) -> None:
        with open("./results/testlib.dll.17b7ca694f2e1e307127c7b653ed294f.json") as schem:
            schema = json.loads(schem.read())
        self.assertEqual(schema["bytecount"], 53248)
        self.assertEqual(schema["filename"], "testlib.dll")
        self.assertEqual(schema["md5"], "17b7ca694f2e1e307127c7b653ed294f")
        self.assertEqual(schema["sha1"], "77a6248d4bb7f7a58e0868d17057c62d92c9f1c1")
        self.assertEqual(
            schema["sha256"], "42cc4d90b3348853ce4decc2c8c1142ff26623c53a058630be5bdd2f8d848c00"
        )
        self.assertFalse(schema["signatures"])  # testLib.dll has no signatures

    @classmethod
    def tearDownClass(self) -> None:
        shutil.rmtree("./testresults")


class X86SinglethreadTestCase(X86ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./binaries/Windows_dll_test_no1", logging.WARNING, "./testParse.log")
        self.PRS(result_path="testresults")  # run scan

    def testCommon(self):
        self.checkOutputs()
        # self.certExtracted()
        self.validateHelloWorldJson()
        self.validateTestLibDllJson()

    def testLogCreated(self):
        self.assertTrue(os.path.isfile("./testParse.log"))

    @classmethod
    def tearDownClass(self) -> None:
        shutil.rmtree("./testresults")
        os.remove("./testParse.log")


class X86TwoThreadTestCase(X86ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./binaries/Windows_dll_test_no1")
        self.PRS(result_path="testresults", threads=2)

    def testCommon(self):
        self.checkOutputs()
        # self.certExtracted()
        self.validateHelloWorldJson()
        self.validateTestLibDllJson()


class X86ThreeThreadTestCase(X86ParseTestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.PRS = parse.Parse("./binaries/Windows_dll_test_no1")
        self.PRS(result_path="testresults", threads=3)

    def testCommon(self):
        self.checkOutputs()
        # self.certExtracted()
        self.validateHelloWorldJson()
        self.validateTestLibDllJson()


if __name__ == "__main__":
    unittest.main()

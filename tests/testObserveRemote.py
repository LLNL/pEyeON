# import tempfile
import os
import unittest
import logging
from glob import glob
import datetime as dt

import json

from eyeon import observe

import jsonschema


class ObservationTestCase(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/a_out_files/big_m68020.aout")

    def testVarsExe(self) -> None:
        self.assertEqual(self.OBS.bytecount, 4)
        self.assertEqual(self.OBS.filename, "big_m68020.aout")
        self.assertEqual(self.OBS.md5, "e8d3808a4e311a4262563f3cb3a31c3e")
        self.assertEqual(self.OBS.sha1, "fbf8688fbe1976b6f324b0028c4b97137ae9139d")
        self.assertEqual(
            self.OBS.sha256, "9e125f97e5f180717096c57fa2fdf06e71cea3e48bc33392318643306b113da4"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")
        # This is not a PE file so there is no signatures
        # self.assertEqual(self.OBS.authenticode_integrity, "OK")
        # self.assertEqual(self.OBS.signatures[0]["verification"], "OK")
        # self.assertEqual(self.OBS.authentihash, self.OBS.signatures[0]["sha1"])

        # self.assertNotIn(  # check that the first cert has no issuer in the chain
        #     "issuer_sha256", self.OBS.signatures[0]["certs"][0]
        # )
        # self.assertEqual(  # check that the second cert has the first issuer's sha
        #     self.OBS.signatures[0]["certs"][1]["issuer_sha256"],
        #     "46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b",
        # )

    # def testValidateJson(self) -> None:
    #     with open("../schema/observation.schema.json") as schem:
    #         schema = json.loads(schem.read())
    #     vs = vars(self.OBS)
    #     obs_json = json.loads(self.OBS._safe_serialize(vs))
    #     print(jsonschema.validate(instance=obs_json, schema=schema))

    def testConfigJson(self) -> None:
        vs = vars(self.OBS)
        obs_json = json.loads(self.OBS._safe_serialize(vs))
        assert "defaults" in obs_json, "defaults not in json"

    @classmethod
    def tearDownClass(self) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass


class ObservationTestCase2(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/coff_files/intel_80386_coff")

    def testVarsElf(self) -> None:
        self.assertEqual(self.OBS.bytecount, 2)
        self.assertEqual(self.OBS.filename, "intel_80386_coff")
        self.assertEqual(self.OBS.md5, "3e44d3b6dd839ce18f1b298bac5ce63f")
        self.assertEqual(self.OBS.sha1, "aad24871701ab7c50fec7f4f2afb7096e5292854")
        self.assertEqual(
            self.OBS.sha256, "ed22c79e7ff516da5fb6310f6137bfe3b9724e9902c14ca624bfe0873f8f2d0c"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")
        self.assertEqual(len(self.OBS.signatures), 0)  # ls is unsigned, should have no signatures

    def testValidateJson(self) -> None:
        with open("../schema/observation.schema.json") as schem:
            schema = json.loads(schem.read())
        obs_json = json.loads(json.dumps(vars(self.OBS)))
        print(jsonschema.validate(instance=obs_json, schema=schema))

    def testValidateSchema(self) -> None:
        with open("../schema/observation.schema.json") as schem:
            schema = json.loads(schem.read())

        with open("../schema/meta.schema.json") as schem:
            meta = json.loads(schem.read())

        print(jsonschema.validate(instance=schema, schema=meta))

    @classmethod
    def tearDownClass(self) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass


class ObservationTestCase3(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/ELF_shared_obj_test_no1/bin/hello_world")

    def testVarsExe(self) -> None:
        self.assertEqual(self.OBS.bytecount, 16424)
        self.assertEqual(self.OBS.filename, "hello_world")
        self.assertEqual(self.OBS.md5, "d2a52fd35b9bec826c814f26cba50b4d")
        self.assertEqual(self.OBS.sha1, "558931bab308cb5d7adb275f7f6a94757286fc63")
        self.assertEqual(
            self.OBS.sha256, "f776715b7a01c4d4efc6be326b3e82ce546efd182c39040a7a9159f6dbe13398"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        # Unsigned
        # self.assertEqual(self.OBS.authenticode_integrity, "OK")
        # self.assertEqual(self.OBS.signatures[0]["verification"], "OK")
        # self.assertEqual(self.OBS.authentihash, self.OBS.signatures[0]["sha1"])
        # self.assertEqual(
        #     self.OBS.signatures[0]["certs"][0]["issuer_sha256"],
        #     "07821038ae6d90f2ea3bff5b6169ba0fb0b3b5cef57db18e7d48313da99e4a36",
        # )
        # self.assertEqual(
        #     self.OBS.signatures[0]["certs"][1]["issuer_sha256"],
        #     "07821038ae6d90f2ea3bff5b6169ba0fb0b3b5cef57db18e7d48313da99e4a36",
        # )

    def testConfigJson(self) -> None:
        vs = vars(self.OBS)
        obs_json = json.loads(self.OBS._safe_serialize(vs))
        assert "defaults" in obs_json, "defaults not in json"

    @classmethod
    def tearDownClass(self) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass
        # self.OBS.write_json()
        # unittest.mock?


class ObservationTestCase4(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/java_class_no1/HelloWorld.class")

    def testVarsExe(self) -> None:
        self.assertEqual(self.OBS.bytecount, 1091)
        self.assertEqual(self.OBS.filename, "HelloWorld.class")
        self.assertEqual(self.OBS.md5, "eed620dc71014e2bbe9171867d4a36da")
        self.assertEqual(self.OBS.sha1, "326afcefa84a51113d49d623cf8902b7a07b4e98")
        self.assertEqual(
            self.OBS.sha256, "990f9f530a833d2ab6ef1580235832a1849de3080efc69cc17cf6575e5a1c469"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)


# This is a Mac-O with 0 signatures, so we can test some of the logging functions
class ObservationTestCase5(unittest.TestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.OBS = observe.Observe(
            "./binaries/mach_o_dylib_test_no1/bin/hello_world", log_level=logging.INFO, log_file="./observe.log"
        )

    # def testLog(self):  # check log is created and correct info logged
    #     self.assertTrue(os.path.exists("./observe.log"))
    #     with open("./observe.log", "r") as f:
    #         log = f.read()

    #     messages = []
    #     for line in log.split("\n", maxsplit=3):
    #         # check log formatting is correct for each line
    #         if line:
    #             components = line.split(" - ")  # seperator defined in observe
    #             print(components)

    #             # order should be a datetime, then name, then loglevel
    #             try:
    #                 dt.datetime.strptime(components[0], "%Y-%m-%d %H:%M:%S,%f")
    #             except ValueError:
    #                 self.fail()
    #             self.assertEqual(components[1], "eyeon.observe")
    #             self.assertIn(components[2], ["INFO", "WARNING"])
    #             messages.append(components[3])

    #     # check message correctly logged
    #     self.assertIn("file ./binaries/mach_o_dylib_test_no1/bin/hello_world has no signatures.", messages)

    def testToString(self):
        try:
            str(self.OBS)
        except Exception as e:
            self.fail(f"Observe.__str__ raised exception {e} unexpectedly!")

    @classmethod
    def tearDownClass(self):
        os.remove("./observe.log")


class TestFilePermissions(unittest.TestCase):
    def test_nonreadable_file(self):
        # Check to see if permission error is raised
        self.assertRaises(PermissionError, observe.Observe, "/etc/shadow")


class TestFolderPermissions(unittest.TestCase):
    def test_nonreadable_folder(self):
        self.assertRaises(PermissionError, observe.Observe, "/root")


if __name__ == "__main__":
    unittest.main()

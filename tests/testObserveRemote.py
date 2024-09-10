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
        self.OBS = observe.Observe("./binaries/x86/notepad++/notepad++.exe")

    def testVarsExe(self) -> None:
        self.assertEqual(self.OBS.vars.bytecount, 6390616)
        self.assertEqual(self.OBS.vars.filename, "notepad++.exe")
        self.assertEqual(self.OBS.vars.md5, "0ec33611cb6594903ff88d47c78dcdab")
        self.assertEqual(self.OBS.vars.sha1, "28a2a37cf2e9550a699b138dddba4b8067c8e1b1")
        self.assertEqual(
            self.OBS.vars.sha256, "ccb4ff6b20689d948233807a67d9de9666229625aa6682466ef01917b01ccd3b"
        )
        try:
            dt.datetime.strptime(self.OBS.vars.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.vars.observation_ts, str)
        self.assertEqual(self.OBS.vars.permissions, "0o100644")
        self.assertEqual(self.OBS.vars.authenticode_integrity, "OK")
        self.assertEqual(self.OBS.vars.signatures[0]["verification"], "OK")
        self.assertEqual(self.OBS.vars.authentihash, self.OBS.vars.signatures[0]["sha1"])

        self.assertNotIn(  # check that the first cert has no issuer in the chain
            "issuer_sha256", self.OBS.vars.signatures[0]["certs"][0]
        )
        self.assertEqual(  # check that the second cert has the first issuer's sha
            self.OBS.vars.signatures[0]["certs"][1]["issuer_sha256"],
            "46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b",
        )

    # def testValidateJson(self) -> None:
    #     with open("../schema/observation.schema.json") as schem:
    #         schema = json.loads(schem.read())
    #     vs = vars(self.OBS)
    #     obs_json = json.loads(self.OBS.vars._safe_serialize(vs))
    #     print(jsonschema.validate(instance=obs_json, schema=schema))

    def testConfigJson(self) -> None:
        vs = vars(self.OBS.vars)
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
        self.OBS = observe.Observe("./binaries/elf/ls")

    def testVarsElf(self) -> None:
        self.assertEqual(self.OBS.vars.bytecount, 138208)
        self.assertEqual(self.OBS.vars.filename, "ls")
        self.assertEqual(self.OBS.vars.md5, "586256cbd58140ec8c3b2c910cf80c27")
        self.assertEqual(self.OBS.vars.sha1, "8b24bc69bd1e97d5d9932448d0f8badaaeb2dd38")
        self.assertEqual(
            self.OBS.vars.sha256, "8696974df4fc39af88ee23e307139afc533064f976da82172de823c3ad66f444"
        )
        try:
            dt.datetime.strptime(self.OBS.vars.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.vars.observation_ts, str)
        self.assertEqual(self.OBS.vars.permissions, "0o100755")
        self.assertEqual(len(self.OBS.vars.signatures), 0)  # ls is unsigned, should have no signatures

    def testValidateJson(self) -> None:
        with open("../schema/observation.schema.json") as schem:
            schema = json.loads(schem.read())
        obs_json = json.loads(json.dumps(vars(self.OBS.vars)))
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


class ObservationTestCaseArm(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/arm/curl-8.8.0_1-win64arm-mingw.exe")

    def testVarsExe(self) -> None:
        self.assertEqual(self.OBS.vars.bytecount, 3237992)
        self.assertEqual(self.OBS.vars.filename, "curl-8.8.0_1-win64arm-mingw.exe")
        self.assertEqual(self.OBS.vars.md5, "c4062346970bfe1e99dac115aca41845")
        self.assertEqual(self.OBS.vars.sha1, "e0a60241ae6c4450da3547b76eb0d35d6876f80e")
        self.assertEqual(
            self.OBS.vars.sha256, "678400429ccbfd5935f9253754203b824500469f79d30bc6a27674d2840551c7"
        )
        try:
            dt.datetime.strptime(self.OBS.vars.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.vars.observation_ts, str)
        self.assertEqual(self.OBS.vars.authenticode_integrity, "OK")
        self.assertEqual(self.OBS.vars.signatures[0]["verification"], "OK")
        self.assertEqual(self.OBS.vars.authentihash, self.OBS.vars.signatures[0]["sha1"])
        self.assertEqual(
            self.OBS.vars.signatures[0]["certs"][0]["issuer_sha256"],
            "07821038ae6d90f2ea3bff5b6169ba0fb0b3b5cef57db18e7d48313da99e4a36",
        )
        self.assertEqual(
            self.OBS.vars.signatures[0]["certs"][1]["issuer_sha256"],
            "07821038ae6d90f2ea3bff5b6169ba0fb0b3b5cef57db18e7d48313da99e4a36",
        )

    def testConfigJson(self) -> None:
        vs = vars(self.OBS.vars)
        obs_json = json.loads(self.OBS._safe_serialize(vs))
        assert "defaults" in obs_json, "defaults not in json"

    @classmethod
    def tearDownClass(self) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass
        # self.OBS.vars.write_json()
        # unittest.mock?


class ObservationTestCasePowerPC(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/powerpc/rustup-init")

    def testVarsExe(self) -> None:
        self.assertEqual(self.OBS.vars.bytecount, 14585464)
        self.assertEqual(self.OBS.vars.filename, "rustup-init")
        self.assertEqual(self.OBS.vars.md5, "3e7704532c1cafb02244fc7e4308ec3d")
        self.assertEqual(self.OBS.vars.sha1, "05324fd5db3da42bc53794614738643942d12d54")
        self.assertEqual(
            self.OBS.vars.sha256, "ad4463793c6d545b8f86fff8dd24e80ced9573eb20b9849fd9bd47818e2e4598"
        )
        try:
            dt.datetime.strptime(self.OBS.vars.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.vars.observation_ts, str)


# 7zip is a PE with 0 signatures, so we can test some of the logging functions
class ObservationTestCase7zip(unittest.TestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.OBS = observe.Observe(
            "./binaries/x86/7z_win32.exe", log_level=logging.INFO, log_file="./observe.log"
        )

    def testLog(self):  # check log is created and correct info logged
        self.assertTrue(os.path.exists("./observe.log"))
        with open("./observe.log", "r") as f:
            log = f.read()

        messages = []
        for line in log.split("\n", maxsplit=3):
            # check log formatting is correct for each line
            print(line)
            if line:
                components = line.split(" - ")  # seperator defined in observe
                # order should be a datetime, then name, then loglevel
                try:
                    dt.datetime.strptime(components[0], "%Y-%m-%d %H:%M:%S,%f")
                except ValueError:
                    self.fail()
                self.assertEqual(components[1], "eyeon.observe")
                self.assertIn(components[2], ["INFO", "WARNING"])
                messages.append(components[3])
                 
        # check message correctly logged
        # This moved to file.py
        # self.assertIn("file ./binaries/x86/7z_win32.exe has no signatures.", messages)

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

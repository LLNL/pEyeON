# import tempfile
import os
import logging
import unittest
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
        self.assertEqual(self.OBS.bytecount, 6390616)
        self.assertEqual(self.OBS.filename, "notepad++.exe")
        self.assertEqual(self.OBS.md5, "0ec33611cb6594903ff88d47c78dcdab")
        self.assertEqual(self.OBS.sha1, "28a2a37cf2e9550a699b138dddba4b8067c8e1b1")
        self.assertEqual(
            self.OBS.sha256, "ccb4ff6b20689d948233807a67d9de9666229625aa6682466ef01917b01ccd3b"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")
        self.assertEqual(
            self.OBS.magic,
            "PE32 executable (GUI) Intel 80386, for MS Windows",  # noqa: E501
        )
        self.assertEqual(
            self.OBS.ssdeep,
            "98304:kq6vzyzgvZe2fwa5T3CWxeKNn5pRD4RnzY/moFJ:V6vzhUfa5fnws5",  # noqa: E501
        )
        self.assertNotIn(  # check that the first cert has no issuer in the chain
            "issuer_sha256", self.OBS.signatures[0]["certs"][0]
        )
        self.assertEqual(  # check that the second cert has the first issuer's sha
            self.OBS.signatures[0]["certs"][1]["issuer_sha256"],
            "46011ede1c147eb2bc731a539b7c047b7ee93e48b9d3c3ba710ce132bbdfac6b",
        )

        self.assertEqual(self.OBS.authenticode_integrity, "OK")
        self.assertEqual(self.OBS.signatures[0]["verification"], "OK")
        self.assertEqual(self.OBS.authentihash, self.OBS.signatures[0]["sha1"])

    def testConfigJson(self) -> None:
        vs = vars(self.OBS)
        obs_json = json.loads(self.OBS._safe_serialize(vs))
        assert "defaults" in obs_json, "defaults not in json"

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass
        # self.OBS.write_json()
        # unittest.mock?


class ObservationTestCase2(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/elf/ls")

    def testVarsElf(self) -> None:
        self.assertEqual(self.OBS.bytecount, 138208)
        self.assertEqual(self.OBS.filename, "ls")
        self.assertEqual(self.OBS.md5, "586256cbd58140ec8c3b2c910cf80c27")
        self.assertEqual(self.OBS.sha1, "8b24bc69bd1e97d5d9932448d0f8badaaeb2dd38")
        self.assertEqual(
            self.OBS.sha256, "8696974df4fc39af88ee23e307139afc533064f976da82172de823c3ad66f444"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100755")
        self.assertEqual(
            self.OBS.magic,
            "ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=897f49cafa98c11d63e619e7e40352f855249c13, for GNU/Linux 3.2.0, stripped",  # noqa: E501
        )
        self.assertEqual(
            self.OBS.ssdeep,
            "1536:1QMY7SpeylTgzfbPlxjBG3PMyFESaZrOwWXKMk3NJvvsC7W+oVfuokwcLxIvOG0H:1Qp7SQDPlxjBiRhwukI+d5wLOne+",  # noqa: E501
        )
        self.assertFalse(len(self.OBS.signatures))  # ls is unsigned, should have no signatures

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
    def tearDownClass(cls) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass


with open("../schema/observation.schema.json") as schem:
    schema = json.loads(schem.read())


class ObservationTestCase3(unittest.TestCase):
    def test_json_valid_required_properties(self) -> None:
        valid_data = {
            "filename": "notepad++.exe",
            "bytecount": 6390616,
            "magic": "PE32 executable (GUI) Intel 80386, for MS Windows, 5 sections",  # noqa: E501
            "md5": "0ec33611cb6594903ff88d47c78dcdab",
            "observation_ts": "2024-05-28 15:55:15",
            "sha1": "28a2a37cf2e9550a699b138dddba4b8067c8e1b1",
            "sha256": "ccb4ff6b20689d948233807a67d9de9666229625aa6682466ef01917b01ccd3b",
            "uuid": "a7b5ecd6-676a-40f1-bba6-8a3654007c1f",
        }
        assert jsonschema.validate(instance=valid_data, schema=schema) is None

    def test_json_invalid_required_properties(self) -> None:
        valid_data = {
            "invalid": "invalid",
            "filename": "notepad++.exe",
            "bytecount": 6390616,
            "magic": "PE32 executable (GUI) Intel 80386, for MS Windows, 5 sections",  # noqa: E501
            "md5": "0ec33611cb6594903ff88d47c78dcdab",
            "observation_ts": "2024-05-28 15:55:15",
            "sha1": "28a2a37cf2e9550a699b138dddba4b8067c8e1b1",
            "sha256": "ccb4ff6b20689d948233807a67d9de9666229625aa6682466ef01917b01ccd3b",
            "uuid": "a7b5ecd6-676a-40f1-bba6-8a3654007c1f",
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            assert jsonschema.validate(instance=valid_data, schema=schema) is None

    def test_type_mismatch(self) -> None:
        invalid_type_data = {
            "filename": 37,
            "bytecount": 6390616,
            "magic": "PE32 executable (GUI) Intel 80386, for MS Windows, 5 sections",  # noqa: E501
            "md5": "0ec33611cb6594903ff88d47c78dcdab",
            "observation_ts": "2024-05-28 15:55:15",
            "sha1": "28a2a37cf2e9550a699b138dddba4b8067c8e1b1",
            "sha256": "ccb4ff6b20689d948233807a67d9de9666229625aa6682466ef01917b01ccd3b",
            "uuid": "a7b5ecd6-676a-40f1-bba6-8a3654007c1f",
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            assert jsonschema.validate(instance=invalid_type_data, schema=schema) is None

    def test_missing_required_fields(self) -> None:
        missing_data = {
            "filename": 37,
            "bytecount": 6390616,
            "md5": "0ec33611cb6594903ff88d47c78dcdab",
            "observation_ts": "2024-05-28 15:55:15",
            "sha1": "28a2a37cf2e9550a699b138dddba4b8067c8e1b1",
            "sha256": "ccb4ff6b20689d948233807a67d9de9666229625aa6682466ef01917b01ccd3b",
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            assert jsonschema.validate(instance=missing_data, schema=schema) is None

    def test_additional_properties(self) -> None:
        additional_data = {
            "OS_version": "Sonoma",
            "filename": "notepad++.exe",
            "bytecount": 72690816,
            "magic": "PE32 executable (GUI) Intel 80386, for MS Windows, 5 sections",  # noqa: E501
            "md5": "0ec33611cb6594903ff88d47c78dcdab",
            "observation_ts": "2024-05-28 15:55:15",
            "sha1": "28a2a37cf2e9550a699b138dddba4b8067c8e1b1",
            "sha256": "ccb4ff6b20689d948233807a67d9de9666229625aa6682466ef01917b01ccd3b",
            "uuid": "a7b5ecd6-676a-40f1-bba6-8a3654007c1f",
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            assert jsonschema.validate(instance=additional_data, schema=schema) is None


class ObservationTestCaseArm(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/arm/curl-8.8.0_1-win64arm-mingw.exe")

    def testVarsExe(self) -> None:
        self.assertEqual(self.OBS.bytecount, 3237992)
        self.assertEqual(self.OBS.filename, "curl-8.8.0_1-win64arm-mingw.exe")
        self.assertEqual(self.OBS.md5, "c4062346970bfe1e99dac115aca41845")
        self.assertEqual(self.OBS.sha1, "e0a60241ae6c4450da3547b76eb0d35d6876f80e")
        self.assertEqual(
            self.OBS.sha256, "678400429ccbfd5935f9253754203b824500469f79d30bc6a27674d2840551c7"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")
        self.assertEqual(
            self.OBS.ssdeep,
            "24576:ZwNqyhCkb9KkPhiN3Uo84/rwAejGQePOqw+1UMXW8NossRK9fvYGHNucilZOAI7K:ZVwnbJLAGjGdP31UMXIh4gGH9ily7b8d",  # noqa: E501
        )
        self.assertEqual(self.OBS.authenticode_integrity, "OK")
        self.assertEqual(self.OBS.signatures[0]["verification"], "OK")
        self.assertEqual(self.OBS.authentihash, self.OBS.signatures[0]["sha1"])
        self.assertEqual(
            self.OBS.signatures[0]["certs"][0]["issuer_sha256"],
            "07821038ae6d90f2ea3bff5b6169ba0fb0b3b5cef57db18e7d48313da99e4a36",
        )
        self.assertEqual(
            self.OBS.signatures[0]["certs"][1]["issuer_sha256"],
            "07821038ae6d90f2ea3bff5b6169ba0fb0b3b5cef57db18e7d48313da99e4a36",
        )

    def testConfigJson(self) -> None:
        vs = vars(self.OBS)
        obs_json = json.loads(self.OBS._safe_serialize(vs))
        assert "defaults" in obs_json, "defaults not in json"

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass
        # self.OBS.write_json()
        # unittest.mock?


class ObservationTestCasePowerPC(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/powerpc/rustup-init")

    def testVarsExe(self) -> None:
        self.assertEqual(self.OBS.bytecount, 14585464)
        self.assertEqual(self.OBS.filename, "rustup-init")
        self.assertEqual(self.OBS.md5, "3e7704532c1cafb02244fc7e4308ec3d")
        self.assertEqual(self.OBS.sha1, "05324fd5db3da42bc53794614738643942d12d54")
        self.assertEqual(
            self.OBS.sha256, "ad4463793c6d545b8f86fff8dd24e80ced9573eb20b9849fd9bd47818e2e4598"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")
        self.assertEqual(
            self.OBS.ssdeep,
            "196608:j45VWK0byrgGFes2xTMRgWx3XHUuHzsOyHShHK9Xp440Cfo:j4Gb+BhRpkuYOyyBy440Cfo",  # noqa: E501
        )
        self.assertFalse(len(self.OBS.signatures))

    def testConfigJson(self) -> None:
        vs = vars(self.OBS)
        obs_json = json.loads(self.OBS._safe_serialize(vs))
        assert "defaults" in obs_json, "defaults not in json"

    @classmethod
    def tearDownClass(cls) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass
        # self.OBS.write_json()
        # unittest.mock?


# 7zip is a PE with 0 signatures, so we can test some of the logging functions
class ObservationTestCase7zip(unittest.TestCase):
    @classmethod
    def setUpClass(self) -> None:
        # remove config temporarily to test log
        os.rename("test_config.toml", "test_config.txt")

        self.OBS = observe.Observe(
            "./binaries/x86/7z_win32.exe", log_level=logging.INFO, log_file="./observe.log"
        )

    def testLog(self):  # check log is created and correct info logged
        self.assertTrue(os.path.isfile("./observe.log"))
        with open("./observe.log", "r") as f:
            log = f.read()

        messages = []
        for line in log.split("\n"):
            # check log formatting is correct for each line
            if line:
                components = line.split(" - ", maxsplit=3)  # seperator defined in observe

                # order should be a datetime, then name, then loglevel
                try:
                    dt.datetime.strptime(components[0], "%Y-%m-%d %H:%M:%S,%f")
                except ValueError:
                    self.fail()
                self.assertEqual(components[1], "eyeon.observe")
                self.assertEqual(components[2], "INFO")
                messages.append(components[3])

        # check both messages are in log
        self.assertIn("file ./binaries/x86/7z_win32.exe has no signatures.", messages)
        self.assertIn("toml config not found", messages)

    def testDefaults(self):  # defaults should be empty when no config
        self.assertEqual(self.OBS.defaults, {})

    def testToString(self):
        try:
            str(self.OBS)
        except Exception as e:
            self.fail(f"Observe.__str__ raised exception {e} unexpectedly!")

    @classmethod
    def tearDownClass(self):
        os.rename("test_config.txt", "test_config.toml")
        os.remove("./observe.log")


class TestFilePermissions(unittest.TestCase):
    def test_nonreadable_file(self):
        # Check to see if permission error is raised
        self.assertRaises(PermissionError, observe.Observe, "/etc/shadow")


class TestFolderPermissions(unittest.TestCase):
    def test_nonreadable_folder(self):
        self.assertRaises(PermissionError, observe.Observe, "/root")


# class TestDiffArchitecture(unittest.TestCase):
#     def test_i386_ls(self):
#         # Check to see if permission error is raised
#         self.assertRaises(PermissionError, observe.Observe, "ls/i386-ls")


if __name__ == "__main__":
    unittest.main()

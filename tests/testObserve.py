# import tempfile
import os
import unittest
from glob import glob
import datetime as dt

import json

from eyeon import observe

import jsonschema


class ObservationTestCase(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./notepad++/notepad++/notepad++.exe")

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

    def testWriteJson(self) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass
        # self.OBS.write_json()
        # unittest.mock?

    def testValidateJson(self) -> None:
        with open("../schema/observation.schema.json") as schem:
            schema = json.loads(schem.read())
        vs = vars(self.OBS)
        obs_json = json.loads(self.OBS._safe_serialize(vs))
        print(jsonschema.validate(instance=obs_json, schema=schema))

    def testConfigJson(self) -> None:
        vs = vars(self.OBS)
        obs_json = json.loads(self.OBS._safe_serialize(vs))
        assert "defaults" in obs_json, "defaults not in json"


class ObservationTestCase2(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./ls")

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

    def testWriteJson(self) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass

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


if __name__ == "__main__":
    unittest.main()

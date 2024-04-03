# import tempfile
import os
import unittest
from glob import glob
import datetime as dt

# import StringIO
import json

from eyeon import observe

import jsonschema


# class ObservationTestCase(unittest.TestCase):
#     @classmethod
#     def setUp(self) -> None:
#         self.OBS = observe.Observe("./Obsidian.1.1.9.exe")

#     def testVarsExe(self) -> None:
#         self.assertEqual(self.OBS.bytecount, 72690816)
#         self.assertEqual(self.OBS.filename, "Obsidian.1.1.9.exe")
#         self.assertEqual(self.OBS.md5, "52880858a43613dc8b2011f7f1c84ec8")
#         self.assertEqual(self.OBS.sha1, "3c45505db042068f22caee4fbb5fef0a102100bb")
#         self.assertEqual(
#             self.OBS.sha256, "8759af1eb38bd975c52dcf31f4ce185b3adcef0baf1a4677b51065ea9eb1e7d4"
#         )
#         try:
#             dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
#         except ValueError:
#             self.fail()
#         self.assertIsInstance(self.OBS.observation_ts, str)
#         self.assertEqual(self.OBS.permissions, "0o100755")
#         self.assertEqual(
#             self.OBS.magic,
#             "PE32 executable (GUI) Intel 80386, for MS Windows, Nullsoft Installer self-extracting archive",  # noqa: E501
#         )
#         self.assertEqual(
#             self.OBS.ssdeep,
#             "1572864:ZVBOHCnuy3zotWQbHr3DRYt3bVTBmoURPljZKT8RnmY:TnDPQjvytRQouimh",  # noqa: E501
#         )

#     def testWriteJson(self) -> None:
#         try:
#             for j in glob("*.json"):
#                 os.remove(j)
#         except FileNotFoundError:
#             pass
#         # self.OBS.write_json()
#         # unittest.mock?

#     def testValidateJson(self) -> None:
#         with open("../schema/observation.schema.json") as schem:
#             schema = json.loads(schem.read())
#         vs = vars(self.OBS)
#         obs_json = json.loads(self.OBS._safe_serialize(vs))
#         print(jsonschema.validate(instance=obs_json, schema=schema))


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


if __name__ == "__main__":
    unittest.main()

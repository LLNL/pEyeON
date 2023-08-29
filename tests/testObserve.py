# import datetime
# import json

# import tempfile
import os
import unittest
from glob import glob

from eyeon import observe

# import jsonschema


class ObservationTestCase(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./Obsidian.1.1.9.exe")

    # def tearDown(self) -> None:
    #     return super().tearDown()

    def testVarsExe(self) -> None:
        self.assertEqual(self.OBS.bytecount, 72690816)
        self.assertEqual(self.OBS.filename, "Obsidian.1.1.9.exe")
        # self.assertEqual(self.OBS.magic, )
        self.assertEqual(self.OBS.md5, "52880858a43613dc8b2011f7f1c84ec8")
        self.assertEqual(self.OBS.sha1, "3c45505db042068f22caee4fbb5fef0a102100bb")
        self.assertEqual(
            self.OBS.sha256, "8759af1eb38bd975c52dcf31f4ce185b3adcef0baf1a4677b51065ea9eb1e7d4"
        )
        # self.assertEqual(self.OBS.modtime, "2023-08-29 16:51:31")  # fails in CI/CD bc of write
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100755")

    def testWriteJson(self) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass

    def testValidateJson(self) -> None:
        pass


class ObservationTestCase2(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./ls")

    # def tearDown(self) -> None:
    #     return super().tearDown()

    def testVarsElf(self) -> None:
        self.assertEqual(self.OBS.bytecount, 138208)
        self.assertEqual(self.OBS.filename, "ls")
        # self.assertEqual(self.OBS.magic, )
        self.assertEqual(self.OBS.md5, "586256cbd58140ec8c3b2c910cf80c27")
        self.assertEqual(self.OBS.sha1, "8b24bc69bd1e97d5d9932448d0f8badaaeb2dd38")
        self.assertEqual(
            self.OBS.sha256, "8696974df4fc39af88ee23e307139afc533064f976da82172de823c3ad66f444"
        )
        # self.assertEqual(self.OBS.modtime, "2023-08-29 16:51:31")  # fails in CI/CD bc of write
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100755")
        self.assertEqual(
            self.ssdeep,
            "1536:1QMY7SpeylTgzfbPlxjBG3PMyFESaZrOwWXKMk3NJvvsC7W+oVfuokwcLxIvOG0H:1Qp7SQDPlxjBiRhwukI+d5wLOne+",
        )

    def testWriteJson(self) -> None:
        try:
            for j in glob("*.json"):
                os.remove(j)
        except FileNotFoundError:
            pass

    def testValidateJson(self) -> None:
        pass


if __name__ == "__main__":
    unittest.main()

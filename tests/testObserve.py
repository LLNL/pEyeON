import unittest
import json
import jsonschema
# import tempfile
import os
from glob import glob
import datetime
from eyeon import observe


class ObservationTestCase(unittest.TestCase):

    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./Obsidian.1.1.9.exe")
        
    
    # def tearDown(self) -> None:
    #     return super().tearDown()
    
    def testVars(self) -> None:
        self.assertEqual(self.OBS.bytecount, 72690816)
        self.assertEqual(self.OBS.filename, "Obsidian.1.1.9.exe")
        # self.assertEqual(self.OBS.magic, )
        self.assertEqual(self.OBS.md5, "52880858a43613dc8b2011f7f1c84ec8")
        self.assertEqual(self.OBS.sha1, "3c45505db042068f22caee4fbb5fef0a102100bb")
        self.assertEqual(self.OBS.sha256, "8759af1eb38bd975c52dcf31f4ce185b3adcef0baf1a4677b51065ea9eb1e7d4")
        self.assertEqual(self.OBS.modtime, "2023-08-23 16:45:58")
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, '0o100755')

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
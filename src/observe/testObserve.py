import unittest
import json
import jsonschema
import tempfile
import observe


class ObservationTestCase(unittest.TestCase):

    @classmethod
    def setUp(self) -> observe.Observe:
        return super().setUp()
        
    
    # def tearDown(self) -> None:
    #     return super().tearDown()
    
    def runTestVars(self) -> None:
        pass

    def runTestWriteJson(self) -> None:
        pass

    def runTestValidateJson(self) -> None:
        pass


if __name__ == "__main__":
    unittest.main()
import os
import json
import unittest
import jsonschema
import shutil
import duckdb
from glob import glob
from eyeon import observe
from eyeon import parse


class GeneralDatabaseTestCase(unittest.TestCase):
    def writeObserve(self):
        self.OBS.write_json()
        self.OBS.write_database(self.database_output)

    def writeParse(self):
        self.PRS.write_database(self.database_output, self.original_output)

    def checkDatabaseCreated(self) -> None:
        self.assertTrue(os.path.isfile(self.database_output))

    def checkDatabaseContents(self) -> None:
        # Read in the json, compare to raw_pf table contents
        con = duckdb.connect(self.database_output)
        table = con.execute("select * from raw_pf").fetchall()

        # convert table to list of dictionaries
        columns = [desc[0] for desc in con.description]
        db_data = [dict(zip(columns, row)) for row in table]

        json_data = []
        if os.path.isdir(self.original_output):
            for jsonfile in glob(os.path.join(self.original_output, "*.json")):
                with open(jsonfile, 'r') as f:
                    json_data.append(json.load(f))
        else:
            with open(self.original_output) as f:
                json_data.append(json.load(f))

        # for each json file that was output, compare its contents to the database
        json_data = sorted(json_data, key = lambda x: x["filename"])
        db_data = sorted(db_data, key = lambda x: x["filename"])
        json_structs = []
        db_structs = []
        for json_dict, db_dict in zip(json_data,db_data):
            for key in ["signatures", "metadata"]:
                if key in json_dict:
                    json_structs.append(json_dict.pop(key))
                    db_structs.append(db_dict.pop(key))

            for key in json_dict:
                if isinstance(json_dict[key], str):
                    # normalize inconsistencies with uuid/hashes from db import
                    db_dict[key] = str(db_dict[key]).replace("-", '')
                    json_dict[key] = json_dict[key].replace("-", '')
                self.assertEqual(json_dict[key], db_dict[key], msg=f"Comparison failed for key {key}" )

        # look at signatures + metadata seperately
        # because these are nested structs, and the db has null values for missing entries
        for json_struct, db_struct in zip(json_structs, db_structs):
            # TODO: figure out how to compare this mess
            pass


    @classmethod
    def tearDownClass(self):  # remove outputs
        os.remove(self.database_output)
        if os.path.isdir(self.original_output):
            shutil.rmtree(self.original_output)
        else:
            os.remove(self.original_output)


class NotepadObserveTestCase(GeneralDatabaseTestCase):
    @classmethod
    def setUpClass(self):
        self.original_output = "notepad++.exe.0ec33611cb6594903ff88d47c78dcdab.json"
        self.database_output = "test_database"
        self.OBS = observe.Observe("./binaries/x86/notepad++/notepad++.exe")

    def testCommon(self):
        self.writeObserve()
        self.checkDatabaseCreated()
        self.checkDatabaseContents()

class LsObserveTestCase(GeneralDatabaseTestCase):
    @classmethod
    def setUpClass(self):
        self.original_output = "ls.586256cbd58140ec8c3b2c910cf80c27.json"
        self.database_output = "test_database"
        self.OBS = observe.Observe("./binaries/elf/ls")

    def testCommon(self):
        self.writeObserve()
        self.checkDatabaseCreated()
        self.checkDatabaseContents()


class X86ParseDatabaseTestCase(GeneralDatabaseTestCase):
    @classmethod
    def setUpClass(self):
        self.original_output = "./testresults"
        self.database_output = "test_database"
        self.PRS = parse.Parse("./binaries/x86/")
        self.PRS(result_path=self.original_output)

    def testCommon(self):
        self.writeParse()
        self.checkDatabaseCreated()
        self.checkDatabaseContents()


class TestErrorHandling(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.database = "test_database"
        self.parse_path = "./binaries/x86/notepad++/"
        self.observe_path = "./binaries/x86/notepad++/notepad++.exe"
        self.PRS = parse.Parse(self.parse_path)
        self.OBS = observe.Observe(self.observe_path)

    def testBadPathParse(self):
        with self.assertRaises(FileNotFoundError):
            self.PRS.write_database(self.database, "badpath")

    def testBadPathObserve(self):
        with self.assertRaises(FileNotFoundError):
            self.OBS.write_database(self.database, "badpath")

    def testNoDatabaseParse(self):
        with self.assertRaises(FileNotFoundError):
            self.PRS.write_database("", self.parse_path)

    def testNoDatabaseObserve(self):
        with self.assertRaises(FileNotFoundError):
            self.OBS.write_database("", self.observe_path)

if __name__ == "__main__":
    unittest.main()

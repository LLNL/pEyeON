import os
import json
import unittest

# import jsonschema
import shutil
import duckdb
from glob import glob
from eyeon import observe
from eyeon import parse
import collections


class GeneralDatabaseTestCase(unittest.TestCase):
    def writeObserve(self):
        self.OBS.write_json()
        self.OBS.write_database(self.database_output)

    def writeParse(self):
        self.PRS.write_database(self.database_output, self.original_output)

    def checkDatabaseCreated(self) -> None:
        self.assertTrue(os.path.isfile(self.database_output))

    def dict_compare(self, d01, d02):
        d1 = collections.OrderedDict(sorted(d01.items()))
        d2 = collections.OrderedDict(sorted(d02.items()))

        for i1, i2 in zip(d1.items(), d2.items()):
            self.assertEqual(i1[0], i2[0])  # compare keys
            # here we test to see if the data in the db is the same as data in the object
            # self.assertEqual(i1[1], i2[1])  # this breaks when there is an empty field. TODO
            # something like {"field": {"foo": None}} != {"field": {}}

    def validateDatabaseContents(self) -> None:
        # Read in the json, compare to observations table contents
        con = duckdb.connect(self.database_output)
        table = con.execute("select * from observations").fetchall()

        # convert table to list of dictionaries
        columns = [desc[0] for desc in con.description]
        db_data = [dict(zip(columns, row)) for row in table]

        json_data = []
        if os.path.isdir(self.original_output):
            for jsonfile in glob(os.path.join(self.original_output, "*.json")):
                with open(jsonfile, "r") as f:
                    json_data.append(json.load(f))
        else:
            with open(self.original_output) as f:
                json_data.append(json.load(f))

        # for each json file that was output, compare its contents to the database
        json_data = sorted(json_data, key=lambda x: x["filename"])
        db_data = sorted(db_data, key=lambda x: x["filename"])
        json_sigs = []
        db_sigs = []
        for json_dict, db_dict in zip(json_data, db_data):
            if "signatures" in json_dict:
                json_sigs.append(json_dict.pop("signatures"))
                db_sigs.append(db_dict.pop("signatures"))

            if "metadata" in json_dict:
                self.dict_compare(json_dict.pop("metadata"), json.loads((db_dict.pop("metadata"))))

            for key in json_dict:
                if isinstance(json_dict[key], str):
                    # normalize inconsistencies with uuid/hashes from db import
                    db_dict[key] = str(db_dict[key]).replace("-", "")
                    json_dict[key] = json_dict[key].replace("-", "")
                self.assertEqual(
                    json_dict[key], db_dict[key], msg=f"Comparison failed for key {key}"
                )

        # iterate through signatures + metadata seperately
        # because these are nested structs, and the db has null values for missing entries
        for json_sig, db_sig in zip(json_sigs, db_sigs):
            for json_item, db_item in zip(
                json_sig, db_sig
            ):  # This is is a mess but not sure of a better way...
                for key in json_item:
                    self.assertIn(key, db_item, msg=f"key {key} not added to signature in database")
                    self.assertIsNotNone(
                        db_item[key], msg=f"key {key} was not populated in database"
                    )
                    # TODO figure out how to manually compare the converted variable types
                    #  after adding json to DUckdb?
                    #  for example: see how datetime entries look in the database

    @classmethod
    def tearDownClass(self):  # remove outputs
        os.remove(self.database_output)
        if os.path.isdir(self.original_output):
            shutil.rmtree(self.original_output)
        else:
            os.remove(self.original_output)


class ExeObserveTestCase(GeneralDatabaseTestCase):
    @classmethod
    def setUpClass(self):
        self.original_output = "Wintap.exe.2950c0020a37b132718f5a832bc5cabd.json"
        self.database_output = "test_database"
        self.OBS = observe.Observe("tests/binaries/Wintap/Wintap.exe")

    def testCommon(self):
        self.writeObserve()
        self.checkDatabaseCreated()
        self.validateDatabaseContents()


class ElfObserveTestCase(GeneralDatabaseTestCase):
    @classmethod
    def setUpClass(self):
        self.original_output = "hello_world.d2a52fd35b9bec826c814f26cba50b4d.json"
        self.database_output = "test_database"
        self.OBS = observe.Observe("tests/binaries/ELF_shared_obj_test_no1/bin/hello_world")

    def testCommon(self):
        self.writeObserve()
        self.checkDatabaseCreated()
        self.validateDatabaseContents()


class PowerPCObserveTestCase(GeneralDatabaseTestCase):
    @classmethod
    def setUpClass(self):
        self.original_output = "hello_world_ppc.0c51f3e375a077b1ab85106cd8339f1d.json"
        self.database_output = "test_database"
        self.OBS = observe.Observe("tests/binaries/powerpc/hello_world_ppc")

    def testCommon(self):
        self.writeObserve()
        self.checkDatabaseCreated()
        self.validateDatabaseContents()


class X86ParseDatabaseTestCase(GeneralDatabaseTestCase):
    @classmethod
    def setUpClass(self):
        self.original_output = "tests/testresults"
        self.database_output = "data/testing/test_database"
        self.PRS = parse.Parse("tests/binaries/ELF_shared_obj_test_no1/")
        self.PRS(result_path=self.original_output)

    def testCommon(self):
        self.writeParse()
        self.checkDatabaseCreated()
        self.validateDatabaseContents()


class ARMParseDatabaseTestCase(GeneralDatabaseTestCase):
    @classmethod
    def setUpClass(self):
        self.original_output = "tests/testresults"
        self.database_output = "test_database"
        self.PRS = parse.Parse("tests/binaries/ELF_shared_obj_test_arm/")
        self.PRS(result_path=self.original_output)

    def testCommon(self):
        self.writeParse()
        self.checkDatabaseCreated()
        self.validateDatabaseContents()


class TestErrorHandling(unittest.TestCase):
    @classmethod
    def setUpClass(self):
        self.database = "test_database"
        self.parse_path = "tests/binaries/Wintap/"
        self.observe_path = "tests/binaries/Wintap/Wintap.exe"
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

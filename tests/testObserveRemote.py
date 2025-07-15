# import tempfile
import os
import unittest
import logging
from glob import glob
import datetime as dt
import tempfile
import json

from eyeon import observe

import jsonschema

# Unit tests for observe.Observe should cover:
# - bytecount: File size in bytes (int)
# - filename: Name of the file (str)
# - md5: MD5 hash of the file (str)
# - sha1: SHA1 hash of the file (str)
# - sha256: SHA256 hash of the file (str)
# - modtime: File modification time, formatted as "%Y-%m-%d %H:%M:%S" (str)
# - observation_ts: Timestamp when observation was made (str)
# - permissions: File permissions (e.g., "0o100644") (str)
# - signatures: List of digital signatures (should be empty for unsigned files)
# - JSON serialization: ._safe_serialize() output should include "defaults" key
# - JSON schema validation: Output should validate against observation.schema.json
# - Meta schema validation: Schema itself should validate against meta.schema.json

class ObservationTestCase(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/a_out_files/big_m68020.aout")

    def testVars(self) -> None:
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

    def testVars(self) -> None:
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
        self.assertEqual(
            len(self.OBS.signatures), 0
        )  # this file is unsigned, should have no signatures

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

    def testVars(self) -> None:
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
        self.assertEqual(self.OBS.permissions, "0o100755")

    # def test_detect_it_easy(self) -> None:
    #     expected_output = (
    #         "ELF64\n"
    #         "    Compiler: gcc((Ubuntu 11.3.0-1ubuntu1~22.04) 11.3.0)[DYN AMD64-64]\n"
    #         "    Library: GLIBC(2.34)[DYN AMD64-64]\n\n"
    #     )
    #     self.assertEqual(self.OBS.detect_it_easy, expected_output)

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

    def testVars(self) -> None:
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
        self.assertEqual(self.OBS.permissions, "0o100644")

    # def test_detect_it_easy(self) -> None:
    #     expected_output = (
    #         "Binary\n"
    #         "    Format: Java Class File (.CLASS)(Java SE 11)\n\n"
    #     )
    #     self.assertEqual(self.OBS.detect_it_easy, expected_output)

class ObservationTestCase5(unittest.TestCase):
    @classmethod
    def setUpClass(self) -> None:
        self.OBS = observe.Observe(
            "./binaries/NET_app_config_test_no1/ConsoleApp2.exe",
            log_level=logging.INFO,
            log_file="./observe.log",
        )

    def testLog(self):  # check log is created and correct info logged
        self.assertTrue(os.path.exists("./observe.log"))
        with open("./observe.log", "r") as f:
            log = f.read()

        messages = []
        for line in log.split("\n", maxsplit=3):
            # check log formatting is correct for each line
            if line:
                components = line.split(" - ")  # separator defined in observe
                print(components)

                # order should be a datetime, then name, then loglevel
                try:
                    dt.datetime.strptime(components[0], "%Y-%m-%d %H:%M:%S,%f")
                except ValueError:
                    self.fail()
                self.assertEqual(components[1], "eyeon.observe")
                self.assertIn(components[2], ["INFO", "WARNING"])
                messages.append(components[3])

        # check message correctly logged
        self.assertIn(
            "file ./binaries/NET_app_config_test_no1/ConsoleApp2.exe has no signatures.", messages
        )

    def testToString(self):
        try:
            str(self.OBS)
        except Exception as e:
            self.fail(f"Observe.__str__ raised exception {e} unexpectedly!")

    @classmethod
    def tearDownClass(self):
        os.remove("./observe.log")

class ObservationTestCase6(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/macho_arm_files/hello_world")

    def testVars(self) -> None:
        self.assertEqual(self.OBS.bytecount, 39224)
        self.assertEqual(self.OBS.filename, "hello_world")
        self.assertEqual(self.OBS.md5, "fef627973d231c07707d3483f6d22ac9")
        self.assertEqual(self.OBS.sha1, "0d66561ca5dfb55376d2bee4bf883938ac229549")
        self.assertEqual(
            self.OBS.sha256, "e8569fc3f4f4a6de36a9b02f585853c6ffcab877a725373d06dad9b44e291088"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100755")
        self.assertEqual(len(self.OBS.signatures), 0)  # unsigned, should have no signatures

    # def test_detect_it_easy(self) -> None:
    #     expected_output = (
    #         "Mach-O64\n\n"
    #     )
    #     self.assertEqual(self.OBS.detect_it_easy, expected_output)

    def testValidateJson(self) -> None:
        with open("../schema/observation.schema.json") as schem:
            schema = json.loads(schem.read())
        # print self.OBS, 
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

class ObservationTestCase7(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/Windows_dll_test_no1/hello_world.exe")

    def testVars(self) -> None:
        self.assertEqual(self.OBS.bytecount, 58880)
        self.assertEqual(self.OBS.filename, "hello_world.exe")
        self.assertEqual(self.OBS.md5, "c1550ecc547c89b2f24599c990a29184")
        self.assertEqual(self.OBS.sha1, "e4e8ecba8d39ba23cf6f13498021049d62c3659c")
        self.assertEqual(
            self.OBS.sha256, "de22b757eaa0ba2b79378722e8057d3052edc87caf543b17d8267bd2713162a8"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")

class ObservationTestCase8(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/powerpc/hello_world_ppc")

    def testVars(self) -> None:
        self.assertEqual(self.OBS.bytecount, 71056)
        self.assertEqual(self.OBS.filename, "hello_world_ppc")
        self.assertEqual(self.OBS.md5, "0c51f3e375a077b1ab85106cd8339f1d")
        self.assertEqual(self.OBS.sha1, "ff06f8bc9a328dbba9cd6cdb9d573ae0a9b8e172")
        self.assertEqual(
            self.OBS.sha256, "d01d7dbd0b47fa1f7b1b54f35e48b64051c0b5b128a9ecbe8d8cb311e5ff4508"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100755")

    # def test_detect_it_easy(self) -> None:
    #     expected_output = (
    #         "ELF64\n"
    #         "    Compiler: gcc((GNU) 14.2.0)[EXEC PPC64-64]\n"
    #         "    Library: GLIBC(2.34)[EXEC PPC64-64]\n\n"
    #     )
    #     self.assertEqual(self.OBS.detect_it_easy, expected_output)

class ObservationTestCase9(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/msitest_no1/test.msi")

    def testVars(self) -> None:
        self.assertEqual(self.OBS.bytecount, 12288)
        self.assertEqual(self.OBS.filename, "test.msi")
        self.assertEqual(self.OBS.md5, "ebe91666b88d9acccbea8da417f22422")
        self.assertEqual(self.OBS.sha1, "8de8e4289c7956a370a64aa814f40bdc1b407d00")
        self.assertEqual(
            self.OBS.sha256, "f9c66eb5a1f6c52c8d7ef2fb3bb0e8e0a0c103ae92048ce6b678152542a77c83"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")

class ObservationTestCase10(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/Wintap.exe")

    def testVars(self) -> None:
        self.assertEqual(self.OBS.bytecount, 201080)
        self.assertEqual(self.OBS.filename, "Wintap.exe")
        self.assertEqual(self.OBS.md5, "2950c0020a37b132718f5a832bc5cabd")
        self.assertEqual(self.OBS.sha1, "1585373cc8ab4f22ce6e553be54eacf835d63a95")
        self.assertEqual(
            self.OBS.sha256, "bdd73b73b50350a55e27f64f022db0f62dd28a0f1d123f3468d3f0958c5fcc39"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100755")
        self.assertEqual(self.OBS.authenticode_integrity, "OK")
        self.assertEqual(self.OBS.signatures[0]["verification"], "OK")
        self.assertEqual(self.OBS.authentihash, self.OBS.signatures[0]["sha1"])

        self.assertNotIn(  # check that the first cert has no issuer in the chain
            "issuer_sha256", self.OBS.signatures[0]["certs"][0]
        )
        self.assertEqual(  # check that the second cert has the first issuer's sha
            self.OBS.signatures[0]["certs"][1]["issuer_sha256"],
            "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988",
        )

'''
Surfactant Binaries
4 seperate unit tests cases for each different file type 

Test case 11: cpio
Test case 12: coff
Test case 13: uimages
Test case 14: zstandard
'''

class ObservationTestCase11(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/cpio_files/cpio_char_new.cpio")

    def testVars(self) -> None:
        self.assertEqual(self.OBS.bytecount, 7)
        self.assertEqual(self.OBS.filename, "cpio_char_new.cpio")
        self.assertEqual(self.OBS.md5, "629f893f8cfdd02b5f1ec6a33f11a9de")
        self.assertEqual(self.OBS.sha1, "bc0a78891f719420815310fdeb8dd9b1ee8b4997")
        self.assertEqual(
            self.OBS.sha256, "ce5d552a1efd21d3c6ba3dd68e61e4407a74840fd9969a9202a467b3e5e93f6a"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")

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

class ObservationTestCase12(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/coff_files/intel_80386_coff")

    def testVars(self) -> None:
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

class ObservationTestCase13(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/uimage_files/hello_world.img")

    def testVars(self) -> None:
        self.assertEqual(self.OBS.bytecount, 125)
        self.assertEqual(self.OBS.filename, "hello_world.img")
        self.assertEqual(self.OBS.md5, "8129c53c4101a29f8faffb5a16f2be53")
        self.assertEqual(self.OBS.sha1, "9bb65a7b0bb913b9914e9aac72152504830a71f5")
        self.assertEqual(
            self.OBS.sha256, "cff9c2c676d3c2d4402fe90ca65c02f00ca2a2e8d671d05b0b7e1a9f1ee5cc8a"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")

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

class ObservationTestCase14(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/zstandard/hi.txt.zst")

    def testVars(self) -> None:
        self.assertEqual(self.OBS.bytecount, 13)
        self.assertEqual(self.OBS.filename, "hi.txt.zst")
        self.assertEqual(self.OBS.md5, "5d80401e01d33084c65e94f93351e94c")
        self.assertEqual(self.OBS.sha1, "fb2e51cbd24e286dd066bd419d77cd772967e384")
        self.assertEqual(
            self.OBS.sha256, "f96deff1816083fdff8bc3e46c3fe6ca46a6bb49f4d5a00627616c13237a512c"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")

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

#Risc V binary 
class ObservationTestCase15(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = observe.Observe("./binaries/ELF_object_riscv/nop.o")

    def testVars(self) -> None:
        self.assertEqual(self.OBS.bytecount, 960)
        self.assertEqual(self.OBS.filename, "nop.o")
        self.assertEqual(self.OBS.md5, "0da6a6d636c44b249f142b7a298a1bf2")
        self.assertEqual(self.OBS.sha1, "1a4b87c3c3e48cc18bf961b31678b0fc25983840")
        self.assertEqual(
            self.OBS.sha256, "245cd762ebae76573107cd7ff3d0494facd3450f439e70839d8f6e46d8cd0104"
        )
        try:
            dt.datetime.strptime(self.OBS.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.observation_ts, str)
        self.assertEqual(self.OBS.permissions, "0o100644")

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


class TestObserveFileHandling(unittest.TestCase):
    def setUp(self):
        # Set up a temporary directory with various test files:
        # - an empty file
        # - a valid small text file
        # - a corrupted file with non-standard content
        self.test_dir = tempfile.TemporaryDirectory()
        self.empty_file = os.path.join(self.test_dir.name, 'empty_file.txt')
        self.corrupted_file = os.path.join(self.test_dir.name, 'corrupted_file.txt')

        open(self.empty_file, 'w').close()
        # Simulate a structurally corrupted ELF file (truncated magic bytes)
        with open(self.corrupted_file, 'wb') as f:
            f.write(b'\x7FELF'[:2])  # Incomplete ELF magic


    def tearDown(self):
        # Remove the temporary directory and its contents
        self.test_dir.cleanup()

    def test_observe_empty_file(self):
        # An empty file should return a bytecount of 0
        obs = observe.Observe(self.empty_file)
        self.assertEqual(obs.bytecount, 0, "Bytecount should be zero for empty file.")

    def test_observe_corrupted_file(self):
        # Corrupted content shouldn't crash Observe; it should still read the file
        obs = observe.Observe(self.corrupted_file)
        self.assertGreater(obs.bytecount, 0, "Bytecount should be > 0 for corrupted file.")

    def test_observe_missing_file(self):
        # Observe should raise FileNotFoundError for nonexistent paths
        missing_file = os.path.join(self.test_dir.name, 'missing_file.txt')
        with self.assertRaises(FileNotFoundError):
            observe.Observe(missing_file)

    def test_observe_directory_instead_of_file(self):
        # Directories are invalid input and should raise an error
        # parse should be used!
        with self.assertRaises(Exception):
            observe.Observe(self.test_dir.name)

    def test_observe_random_binary_file(self):
        # Creates a temporary file with 1KB of random binary data
        random_data = os.urandom(1024)
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(random_data)
            tmp_path = tmp.name
        try:
            obs = observe.Observe(tmp_path)
            self.assertEqual(obs.bytecount, 1024)
        finally:
            os.remove(tmp_path)

class TestPortableFilePermissions(unittest.TestCase):
    def test_tempfile_no_read_permission(self):
        """
        Ensure Observe raises PermissionError when file has no read permission.
        """
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
        try:
            # Remove read permission (write-only)
            os.chmod(tmp_path, 0o200)
            with self.assertRaises(PermissionError):
                observe.Observe(tmp_path)
        finally:
            # Restore permissions for deletion
            os.chmod(tmp_path, 0o600)
            os.unlink(tmp_path)

    def test_tempdir_no_read_permission(self):
        """
        Ensure Observe raises PermissionError when directory has no read permission.
        """
        tmp_dir = tempfile.mkdtemp()
        try:
            # Remove all permissions from the directory
            os.chmod(tmp_dir, 0o000)
            with self.assertRaises(PermissionError):
                observe.Observe(tmp_dir)
        finally:
            os.chmod(tmp_dir, 0o700)
            os.rmdir(tmp_dir)


class FilePermissionTest(unittest.TestCase):
    def test_permission_error_on_read(self):
        """
        Sanity check: Python itself should raise PermissionError when reading a locked file.
        Helps verify test environment behaves as expected.
        """
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
            tmp.write(b"Test content")

        os.chmod(tmp_path, 0)  # no permissions at all
        try:
            with self.assertRaises(PermissionError):
                with open(tmp_path, "r") as f:
                    f.read()
        finally:
            os.chmod(tmp_path, 0o666)
            os.remove(tmp_path)


class TestLargeFileHandling(unittest.TestCase):
    def test_observe_large_file(self):
        """
        Test Observe's ability to handle a large 100MB file.
        Ensures bytecount is correct and no memory issues arise.
        """

        #seems anything on the order of 100,000 leads to a memory error
        #converts to bytes so 1000 megabytes
        #10k is slow
        large_file_size = 100 * 1024 * 1024  
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b'\0' * large_file_size)
            tmp_path = tmp.name
        try:
            obs = observe.Observe(tmp_path)
            self.assertEqual(obs.bytecount, large_file_size)
        finally:
            os.remove(tmp_path)


class TestWriteJson(unittest.TestCase):
    def test_write_json_creates_output(self):
        """
        Verify that write_json() produces a properly named and structured JSON file.
        """
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"Hello World")
            path = tmp.name

        obs = observe.Observe(path)
        tmp_dir = tempfile.mkdtemp()
        obs.write_json(tmp_dir)

        json_path = os.path.join(tmp_dir, f"{obs.filename}.{obs.md5}.json")
        self.assertTrue(os.path.exists(json_path), "JSON output file not created.")

        # Load the JSON file and confirm basic fields match expected values
        with open(json_path) as f:
            data = json.load(f)
        self.assertEqual(data["filename"], os.path.basename(path))
        self.assertEqual(data["bytecount"], 11)

        os.remove(path)
        os.remove(json_path)

class TestUnknownFileType(unittest.TestCase):
    def test_imphash_set_to_na_for_junk_file(self):
        """
        Files that are not recognized as PE, ELF, or Mach-O should default to imphash='N/A'.
        """
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp.write(b"This is not a real binary format.")
            path = tmp.name

        obs = observe.Observe(path)

        self.assertEqual(
            obs.imphash,
            "N/A",
            "imphash should be 'N/A' for unrecognized file types"
        )

        os.remove(path)
"END"



class TestFilePermissions(unittest.TestCase):
    def test_nonreadable_file(self):
        # Check to see if permission error is raised
        self.assertRaises(PermissionError, observe.Observe, "/etc/shadow")

class TestFolderPermissions(unittest.TestCase):
    def test_nonreadable_folder(self):
        self.assertRaises(PermissionError, observe.Observe, "/root")


with open("../schema/observation.schema.json") as schem:
    schema = json.loads(schem.read())


class TestJSONSchema(unittest.TestCase):
    def test_json_valid_required_properties(self) -> None:
        valid_data = {
            "filename": "little_386.aout",
            "bytecount": 4,
            "magic": "Linux/i386 demand-paged executable (ZMAGIC)",  # noqa: E501
            "md5": "90a2eac40885beab82e592192a2cadd1",
            "observation_ts": "2024-12-04 22:27:45",
            "sha1": "f265f86a2f7bde59b88a47e53c0893d66a55a6cc",
            "sha256": "0dabc62368f8c774acf547ee84e794d172a72c0e8bb3c78d261a6e896ea60c42",
            "uuid": "f1eba7e3-e4c0-43e8-91dc-009a85367517",
        }
        assert jsonschema.validate(instance=valid_data, schema=schema) is None

    def test_json_invalid_required_properties(self) -> None:
        invalid_data = {
            "filename": "little_386.aout",
            "bytecount": 4,
            "magic": "Linux/i386 demand-paged executable (ZMAGIC)",  # noqa: E501
            "md5": "90a2eac40885beab82e592192a2cadd1",
            "observation_ts": "2024-12-04 22:27:45",
            "sha1": "f265f86a2f7bde59b88a47e53c0893d66a55a6cc",
            "sha256": "0dabc62368f8c774acf547ee84e794d172a72c0e8bb3c78d261a6e896ea60c42",
            "uuid": "f1eba7e3-e4c0-43e8-91dc-009a85367517",
            "invalid": "Invalid required property",
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            assert jsonschema.validate(instance=invalid_data, schema=schema) is None

    def test_type_mismatch(self) -> None:
        invalid_type_data = {
            "filename": "little_386.aout",
            "bytecount": "four",
            "magic": "Linux/i386 demand-paged executable (ZMAGIC)",  # noqa: E501
            "md5": "90a2eac40885beab82e592192a2cadd1",
            "observation_ts": "2024-12-04 22:27:45",
            "sha1": "f265f86a2f7bde59b88a47e53c0893d66a55a6cc",
            "sha256": "0dabc62368f8c774acf547ee84e794d172a72c0e8bb3c78d261a6e896ea60c42",
            "uuid": "f1eba7e3-e4c0-43e8-91dc-009a85367517",
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            assert jsonschema.validate(instance=invalid_type_data, schema=schema) is None

    def test_missing_required_fields(self) -> None:
        missing_data = {
            "filename": "little_386.aout",
            "bytecount": 4,
            "magic": "Linux/i386 demand-paged executable (ZMAGIC)",  # noqa: E501
            "md5": "90a2eac40885beab82e592192a2cadd1",
            "observation_ts": "2024-12-04 22:27:45",
            "sha256": "0dabc62368f8c774acf547ee84e794d172a72c0e8bb3c78d261a6e896ea60c42",
            "uuid": "f1eba7e3-e4c0-43e8-91dc-009a85367517",
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            assert jsonschema.validate(instance=missing_data, schema=schema) is None

    def test_additional_properties(self) -> None:
        additional_data = {
            "filename": "little_386.aout",
            "bytecount": 4,
            "magic": "Linux/i386 demand-paged executable (ZMAGIC)",  # noqa: E501
            "md5": "90a2eac40885beab82e592192a2cadd1",
            "observation_ts": "2024-12-04 22:27:45",
            "sha1": "f265f86a2f7bde59b88a47e53c0893d66a55a6cc",
            "sha256": "0dabc62368f8c774acf547ee84e794d172a72c0e8bb3c78d261a6e896ea60c42",
            "uuid": "f1eba7e3-e4c0-43e8-91dc-009a85367517",
            "extra_property": "Extra property",
        }
        with self.assertRaises(jsonschema.exceptions.ValidationError):
            assert jsonschema.validate(instance=additional_data, schema=schema) is None


if __name__ == "__main__":
    unittest.main()

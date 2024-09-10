import unittest
import datetime as dt
import os
import json
import jsonschema
import logging
from eyeon import observe


class CorruptFileTestCase(unittest.TestCase):
    """
    This is a superclass the runs common assertions for all of the below
    corruption cases; including bad certificates/signatures and tampered code
    """

    @classmethod
    def corrupt(self, skip, binpath, badbinpath):
        self.badbinpath = badbinpath
        # change some of the data in notepad++.exe to break signature
        writelen = 500  # overwrite some of the bytes

        # open one for read and one for write
        binary = open(binpath, "rb")
        corrupted = open(badbinpath, "wb")

        # get the first chunk and write to corrupted file
        chunk1 = binary.read(skip)
        corrupted.write(chunk1)
        corrupted.write(bytes([0x33] * writelen))  # overwrite some bytes

        # write rest of file
        binary.seek(skip + writelen)
        corrupted.write(binary.read())

        binary.close()
        corrupted.close()

        if not os.path.isfile(badbinpath):
            self.fail(f"Failed to create {badbinpath}")

    def scan(self, badbinpath):
        # scan the corrupted binary
        self.OBS = observe.Observe(
            badbinpath, log_level=logging.INFO, log_file="testBadSignatures.log"
        )
        self.assertTrue(os.path.isfile("testBadSignatures.log"))

    def corruptedVarsExe(
        self, md5, sha1, sha256, filename, bytecount, sigflag, codeflag, magic=None
    ):
        # verify hashes and see if verification broke properly
        self.assertEqual(self.OBS.vars.bytecount, bytecount)
        self.assertEqual(self.OBS.vars.filename, filename)
        self.assertEqual(self.OBS.vars.md5, md5)
        self.assertEqual(self.OBS.vars.sha1, sha1)
        self.assertEqual(self.OBS.vars.sha256, sha256)
        try:
            dt.datetime.strptime(self.OBS.vars.modtime, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            self.fail()
        self.assertIsInstance(self.OBS.vars.observation_ts, str)

        if magic:  # magic bytes may change during gitlab job, can't always test
            self.assertEqual(self.OBS.vars.magic, magic)

        # check signature and authenticode
        self.assertEqual(self.OBS.vars.signatures[0]["verification"], sigflag)
        self.assertEqual(self.OBS.vars.authenticode_integrity, codeflag)

    def configJson(self) -> None:
        vs = vars(self.OBS)
        obs_json = json.loads(self.OBS._safe_serialize(vs))
        assert "defaults" in obs_json, "defaults not in json"

    def validateSchema(self) -> None:
        with open("../schema/observation.schema.json") as schem:
            schema = json.loads(schem.read())

        with open("../schema/meta.schema.json") as schem:
            meta = json.loads(schem.read())

        print(jsonschema.validate(instance=schema, schema=meta))

    @classmethod
    def tearDownClass(self):
        os.remove("./testBadSignatures.log")
        os.remove(self.badbinpath)


class NotepadFirstCertCorrupt(CorruptFileTestCase):
    def setUp(self):
        # path for reading original, and path for writing exe with broken cert
        self.binpath = "./binaries/x86/notepad++/notepad++.exe"
        self.badbinpath = "./binaries/x86/notepad++/notepad++_corrupted.exe"

        # corrupt the first cert, write bad binary, and scan
        self.corrupt(0x00615FC0, self.binpath, self.badbinpath)  # location of first cert
        self.scan(self.badbinpath)

    def testCommon(self):
        md5 = "09ec21d51a66e06788179336589488a1"
        sha1 = "b3f4d9d18ccb23705992109a871bf0541a9d20d6"
        sha256 = "4e434a9fb8bfbb15a5fac7a33c882ec91a05427b35c55e17fd82e030548b4b3f"
        magic = "PE32 executable (GUI) Intel 80386, for MS Windows"
        bytecount = 6390616
        sigflag = "VERIFICATION_FLAGS.CERT_NOT_FOUND"
        codeflag = "VERIFICATION_FLAGS.CERT_NOT_FOUND | VERIFICATION_FLAGS.BAD_SIGNATURE"
        filename = self.badbinpath.rsplit("/", maxsplit=1)[-1]
        self.corruptedVarsExe(md5, sha1, sha256, filename, bytecount, sigflag, codeflag, magic)
        self.configJson()
        self.validateSchema()


class NotepadSecondCertCorrupt(CorruptFileTestCase):
    def setUp(self):
        self.binpath = "./binaries/x86/notepad++/notepad++.exe"
        self.badbinpath = "./binaries/x86/notepad++/notepad++_corrupted.exe"
        self.corrupt(0x006162A0, self.binpath, self.badbinpath)  # location of second cert
        self.scan(self.badbinpath)

    def testCommon(self):
        md5 = "ae8c330902a79edf97526ba2fbe452a0"
        sha1 = "cae1d9471f7413f9219ddcf6fd9c986e81a95f75"
        sha256 = "2f11aaa964206882823348915b08b8106f95ce17bb5491fede7932466f85c31c"
        magic = "PE32 executable (GUI) Intel 80386, for MS Windows"
        bytecount = 6390616
        sigflag = "VERIFICATION_FLAGS.CERT_NOT_FOUND"
        codeflag = "VERIFICATION_FLAGS.CERT_NOT_FOUND | VERIFICATION_FLAGS.BAD_SIGNATURE"
        filename = self.badbinpath.rsplit("/", maxsplit=1)[-1]
        self.corruptedVarsExe(md5, sha1, sha256, filename, bytecount, sigflag, codeflag, magic)
        self.configJson()
        self.validateSchema()


class CurlFirstCertCorrupt(CorruptFileTestCase):
    def setUp(self):
        self.binpath = "./binaries/arm/curl-8.8.0_1-win64arm-mingw.exe"
        self.badbinpath = "./binaries/arm/curl-8.8.0_1-win64arm-mingw_corrupted.exe"
        self.corrupt(0x00315BB0, self.binpath, self.badbinpath)  # location of first cert
        self.scan(self.badbinpath)

    def testCommon(self):
        md5 = "33ab10b10a9270c61dfb9df2e1e71413"
        sha1 = "68c4acb734d0cfdde2b75020e5fd1a64e91553b2"
        sha256 = "34985fc11dc4875c0d7f6b03be601225e99b527202e34ec3ceef6cd270b30c3c"
        bytecount = 3237992
        sigflag = "VERIFICATION_FLAGS.CERT_NOT_FOUND"
        codeflag = "VERIFICATION_FLAGS.CERT_NOT_FOUND | VERIFICATION_FLAGS.BAD_SIGNATURE"
        filename = self.badbinpath.rsplit("/", maxsplit=1)[-1]
        self.corruptedVarsExe(md5, sha1, sha256, filename, bytecount, sigflag, codeflag)
        self.configJson()
        self.validateSchema()


class CurlBreakAuthenticode1(CorruptFileTestCase):
    def setUp(self):
        self.binpath = "./binaries/arm/curl-8.8.0_1-win64arm-mingw.exe"
        self.badbinpath = "./binaries/arm/curl-8.8.0_1-win64arm-mingw_corrupted.exe"
        self.corrupt(0x00215BB0, self.binpath, self.badbinpath)
        self.scan(self.badbinpath)

    def testCommon(self):
        md5 = "0af04aebfd20d732c8eb9171c2288f9d"
        sha1 = "77f160354d8bc4e63b5eb6315a3d97b825f268f3"
        sha256 = "461bf5ce846ecc8de7d8c09b508dcaff520f63f1b926bfccedf89411136bffa3"
        bytecount = 3237992
        sigflag = "OK"  # when you tamper with the code, the signature is still ok
        codeflag = "VERIFICATION_FLAGS.BAD_DIGEST | VERIFICATION_FLAGS.BAD_SIGNATURE"
        filename = self.badbinpath.rsplit("/", maxsplit=1)[-1]
        self.corruptedVarsExe(md5, sha1, sha256, filename, bytecount, sigflag, codeflag)
        self.configJson()
        self.validateSchema()


class CurlBreakAuthenticode2(CorruptFileTestCase):
    def setUp(self):
        self.binpath = "./binaries/arm/curl-8.8.0_1-win64arm-mingw.exe"
        self.badbinpath = "./binaries/arm/curl-8.8.0_1-win64arm-mingw_corrupted.exe"
        self.corrupt(0x00415BB0, self.binpath, self.badbinpath)
        self.scan(self.badbinpath)

    def testCommon(self):
        md5 = "4ee583e324ac1cc55e25acb94047c1fd"
        sha1 = "4a268ce9447c7096e659559efaafa761952e4393"
        sha256 = "fb5dce8bd9e138c413dfd6b0d99b702882de282f9a8e63ae9e6055aa913c6b9a"
        bytecount = 3238492
        sigflag = "OK"
        codeflag = "VERIFICATION_FLAGS.BAD_DIGEST | VERIFICATION_FLAGS.BAD_SIGNATURE"
        filename = self.badbinpath.rsplit("/", maxsplit=1)[-1]
        self.corruptedVarsExe(md5, sha1, sha256, filename, bytecount, sigflag, codeflag)
        self.configJson()
        self.validateSchema()


if __name__ == "__main__":
    unittest.main()

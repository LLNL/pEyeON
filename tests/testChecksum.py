import unittest
import tempfile
import os

from eyeon import checksum


class testChecksum(unittest.TestCase):
    def setUp(self):
        # Create temp file
        self.temp_file = tempfile.NamedTemporaryFile(delete=False)
        self.temp_file.write(b"Test data for hashing.")
        self.temp_file.close()

        # Calculate expected hashes
        self.expected_sha256 = "855e09f327e425f4ce668563db63b3d7e9d3220d1f89aa7b750e5b7722209362"
        self.expected_md5 = "b208e1c2c00f7ab4775a295a640c0f0f"
        self.expected_sha1 = "69a2a259cbce0879c21938ecada864898a606613"

    def tearDown(self):
        # Clean up the temporary file after test
        os.remove(self.temp_file.name)

    # Check passes
    def test_hash_file_sha256(self):
        result = checksum.Checksum(
            self.temp_file.name, algorithm="sha256", expected_checksum=self.expected_sha256
        )
        self.assertEqual(result, self.expected_sha256)

    def test_hash_file_md5(self):
        result = checksum.Checksum(
            self.temp_file.name, algorithm="md5", expected_checksum=self.expected_md5
        )
        self.assertEqual(result, self.expected_md5)

    def test_hash_file_sha1(self):
        result = checksum.Checksum(
            self.temp_file.name, algorithm="sha1", expected_checksum=self.expected_sha1
        )
        self.assertEqual(result, self.expected_sha1)

    # Check fails
    def test_hash_file_sha256_fail(self):
        result = checksum.Checksum(
            self.temp_file.name, algorithm="sha256", expected_checksum="fj93u2j9ji"
        )
        self.assertNotEqual(result, "fj93u2j9ji")

    def test_hash_file_md5_fail(self):
        result = checksum.Checksum(
            self.temp_file.name, algorithm="md5", expected_checksum="324eqwr2"
        )
        self.assertNotEqual(result, "324eqwr2")

    def test_hash_file_sha1_fail(self):
        result = checksum.Checksum(
            self.temp_file.name, algorithm="sha1", expected_checksum="32qreq42"
        )
        self.assertNotEqual(result, "32qreq42")


if __name__ == "__main__":
    unittest.main()

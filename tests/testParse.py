import unittest

from eyeon import parse


class ObservationTestCase(unittest.TestCase):
    @classmethod
    def setUp(self) -> None:
        self.OBS = parse.Parse("./notepad++")


if __name__ == "__main__":
    unittest.main()

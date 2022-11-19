"""docs"""
import unittest


class TestMain(unittest.TestCase):
    """docs"""

    def test_verifier(self):
        """
        unit test for ci worflow integration
        """
        self.assertEqual(True, True)


if __name__ == '__main__':
    # to run the test locally and check test coverage execute below commands
    # $coverage run -m unittest discover
    # $coverage html
    unittest.main()

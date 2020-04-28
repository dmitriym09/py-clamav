"""
Unit tests
"""

import os
from unittest import TestCase
from base64 import decodebytes
from pathlib import Path

from py_clamav import ClamAvScanner

EICAR_DASE64 = b'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='


class Test(TestCase):
    """
    Unit tests
    """

    def setUp(self) -> None:
        self._eicar_data = decodebytes(EICAR_DASE64)

        self._eicar_path = Path(__file__).parent.absolute() / '.eicar.com'
        with open(self._eicar_path, 'wb') as eicar_file:
            eicar_file.write(self._eicar_data)

        self._eicar_fileno = os.memfd_create('eicar')
        os.write(self._eicar_fileno, self._eicar_data)
        os.lseek(self._eicar_fileno, 0, 0)

        self._good_path = Path(__file__).parent.absolute() / '.good'
        with open(self._good_path, 'wb') as good_file:
            good_file.write(b'ClamAv cool antivirus')

    def tearDown(self) -> None:
        if self._eicar_path.exists():
            self._eicar_path.unlink()

        if self._good_path.exists():
            self._good_path.unlink()

        os.close(self._eicar_fileno)

    def test(self):
        """
        Scan test files
        """
        with ClamAvScanner() as scanner:
            major, minor, build = scanner.ver
            self.assertGreaterEqual(major, 0)
            self.assertGreaterEqual(minor, 0)
            self.assertGreaterEqual(build, 0)

            print(f'{major}.{minor}.{build}')

            infected, virname = scanner.scan_file(self._good_path)
            self.assertFalse(infected)
            self.assertIsNone(virname)

            infected, virname = scanner.scan_file(self._eicar_path)
            self.assertTrue(infected)
            self.assertEqual(virname, 'Win.Test.EICAR_HDB-1')

            infected, virname = scanner.scan_fileno(self._eicar_fileno)
            self.assertTrue(infected)
            self.assertEqual(virname, 'Win.Test.EICAR_HDB-1')

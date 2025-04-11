import unittest
from app.utils import decode_cscript_int


class TestDecodeCscriptInt(unittest.TestCase):
    def test_decode_cscript_int(self):
        self.assertEqual(decode_cscript_int(b""), 0)
        self.assertEqual(decode_cscript_int(b"\x0c"), 12)
        self.assertEqual(decode_cscript_int(b"\x82\x00"), 0x82)
        self.assertEqual(decode_cscript_int(b"\xff\xff\xff\x7f"), 2**31 - 1)
        self.assertEqual(decode_cscript_int(b"\x32\x79\x86"), -424242)
        self.assertEqual(decode_cscript_int(b"\x80\x80"), -0x80)
        self.assertEqual(decode_cscript_int(b"\x81"), -1)

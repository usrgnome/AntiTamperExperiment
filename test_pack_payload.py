"""Synthetic COFF tests; never compile, load or execute native payloads."""
import pathlib
import struct
import tempfile
import unittest

from pack_payload import place


def coff(code_relocations=0, unwind_relocations=0):
    data = bytearray(100)
    struct.pack_into('<HHIIIHH', data, 0, 0x8664, 2, 0, 0, 0, 0, 0)
    for header, name, flags, relocations in (
        (20, b'.text', 0x60000020, code_relocations),
        (60, b'.pdata', 0x40000040, unwind_relocations),
    ):
        data[header:header + 8] = name.ljust(8, b'\0')
        struct.pack_into('<H', data, header + 32, relocations)
        struct.pack_into('<I', data, header + 36, flags)
    return data


class PlaceTests(unittest.TestCase):
    def convert(self, data, name):
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / 'source.obj'
            destination = pathlib.Path(directory) / 'mapped.obj'
            source.write_bytes(data)
            place(source, destination, name)
            return destination.read_bytes()

    def test_integrity_rejects_external_code_references(self):
        with self.assertRaisesRegex(ValueError, 'code relocations'):
            self.convert(coff(code_relocations=1), '.integr')

    def test_integrity_accepts_unwind_relocations_and_preserves_metadata(self):
        original = coff(unwind_relocations=3)
        converted = self.convert(original, '.integr')
        expected = bytearray(original)
        expected[20:28] = b'.integr\0'
        self.assertEqual(converted, expected)

    def test_game_still_allows_code_relocations(self):
        converted = self.convert(coff(code_relocations=1), '.game')
        self.assertEqual(converted[20:28], b'.game\0\0\0')
        self.assertEqual(struct.unpack_from('<H', converted, 52)[0], 1)


if __name__ == '__main__':
    unittest.main()

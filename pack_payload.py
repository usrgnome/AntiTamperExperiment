"""Place complete COFF code into named sections, then encrypt linked PE sections."""
import pathlib
import struct
import sys

KEY = 0xA7
MARKER = 0x584F5231


def place(source, destination, section_name):
    data = bytearray(pathlib.Path(source).read_bytes())
    machine, count, _, _, _, optional, _ = struct.unpack_from('<HHIIIHH', data)
    if machine != 0x8664 or optional or len(section_name) > 8:
        raise ValueError('Expected a normal x64 COFF object and a short section name')
    moved = 0
    for index in range(count):
        header = 20 + index * 40
        flags = struct.unpack_from('<I', data, header + 36)[0]
        if flags & 0x20000000:
            # Retain relocations, COMDAT associations, symbols and unwind data.
            # This also moves compiler-generated worker and template code.
            data[header:header + 8] = section_name.encode().ljust(8, b'\0')
            moved += 1
    if not moved:
        raise ValueError('No executable code found')
    pathlib.Path(destination).write_bytes(data)


def seal(source, destination):
    data = bytearray(pathlib.Path(source).read_bytes())
    pe = struct.unpack_from('<I', data, 0x3c)[0]
    if data[:2] != b'MZ' or data[pe:pe + 4] != b'PE\0\0':
        raise ValueError('Expected PE image')
    machine, count = struct.unpack_from('<HH', data, pe + 4)
    optional_size = struct.unpack_from('<H', data, pe + 20)[0]
    optional = pe + 24
    if machine != 0x8664 or struct.unpack_from('<H', data, optional)[0] != 0x20b:
        raise ValueError('Expected PE32+ x64')
    sections = []
    selected = []
    for index in range(count):
        header = optional + optional_size + index * 40
        name, size, rva, raw_size, raw = struct.unpack_from('<8sIIII', data, header)
        name = name.rstrip(b'\0')
        section = (name, size, rva, raw_size, raw, header)
        sections.append(section)
        if name in (b'.integr', b'.game'):
            if not size or raw + raw_size > len(data) or rva % 4096:
                raise ValueError('Invalid or unaligned payload section')
            if struct.unpack_from('<I', data, header + 28)[0]:
                raise ValueError('Input already sealed or has unexpected line-number metadata')
            selected.append(section)
    if {s[0] for s in selected} != {b'.integr', b'.game'} or len(selected) != 2:
        raise ValueError('Expected exactly one integrity and game section')

    def file_offset(rva):
        for _, _, start, length, offset, _ in sections:
            if start <= rva < start + length:
                return offset + rva - start
        raise ValueError('Unmapped directory RVA')

    def encrypted(rva):
        return any(s[2] <= rva < s[2] + s[1] for s in selected)

    # Windows applies base relocations before main. Reject relocations that
    # would edit ciphertext, rather than silently breaking ASLR.
    reloc_rva, reloc_size = struct.unpack_from('<II', data, optional + 112 + 5 * 8)
    if reloc_size:
        cursor = file_offset(reloc_rva)
        end = cursor + reloc_size
        while cursor < end:
            page, length = struct.unpack_from('<II', data, cursor)
            if length < 8 or length % 2 or cursor + length > end:
                raise ValueError('Invalid relocation block')
            for offset in range(cursor + 8, cursor + length, 2):
                entry = struct.unpack_from('<H', data, offset)[0]
                if entry >> 12 and encrypted(page + (entry & 0xfff)):
                    raise ValueError('Base relocation targets encrypted code')
            cursor += length
    # TLS callbacks execute before main, so they must remain outside ciphertext.
    image_base = struct.unpack_from('<Q', data, optional + 24)[0]
    tls_rva, tls_size = struct.unpack_from('<II', data, optional + 112 + 9 * 8)
    if tls_size:
        callbacks = struct.unpack_from('<Q', data, file_offset(tls_rva) + 24)[0]
        if callbacks:
            cursor = file_offset(callbacks - image_base)
            while True:
                target = struct.unpack_from('<Q', data, cursor)[0]
                if not target:
                    break
                if encrypted(target - image_base):
                    raise ValueError('TLS callback targets encrypted code before decryption')
                cursor += 8
    for name, size, _, raw_size, raw, header in selected:
        length = min(size, raw_size)
        for offset in range(raw, raw + length):
            data[offset] ^= KEY
        struct.pack_into('<I', data, header + 28, MARKER)
        print(f'{name.decode()}: encrypted {length} bytes in the EXE')
    # The unsigned demo does not use the optional PE checksum.
    struct.pack_into('<I', data, optional + 64, 0)
    pathlib.Path(destination).write_bytes(data)


if __name__ == '__main__':
    if sys.argv[1] == 'place':
        place(*sys.argv[2:])
    elif sys.argv[1] == 'seal':
        seal(*sys.argv[2:])
    else:
        raise ValueError('Expected place or seal')

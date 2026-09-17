"""Verify binary data extraction respects object and file-backed boundaries."""

from pathlib import Path
import struct
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "plugins"))
import decompile_helper as dh


def test_dat_entry_preserves_embedded_zero_bytes(tmp_path):
    source = tmp_path / "blob.c"
    source.write_text(
        "unsigned char blob[4] = {1, 0, 2, 3};\n"
        "int main(void) { return blob[2]; }\n",
        encoding="utf-8",
    )
    executable = tmp_path / "blob"
    subprocess.run(
        ["gcc", "-no-pie", str(source), "-o", str(executable)],
        check=True, capture_output=True, text=True,
    )
    symbols = subprocess.run(
        ["nm", str(executable)], check=True, capture_output=True, text=True,
    ).stdout
    address = next(
        row.split()[0] for row in symbols.splitlines() if row.split()[-1] == "blob"
    )
    use = tmp_path / "use.c"
    use.write_text("int f(void) { return DAT_%s[2]; }\n" % address, encoding="utf-8")

    entries = dh.dat_entries(dh.parse_elf(executable), tmp_path, [use])

    assert entries == [(address, False, b"\x01\x00\x02\x03")]


def test_pe_virtual_tail_does_not_map_to_overlay_bytes(tmp_path):
    data = bytearray(0x500)
    data[:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\0\0"
    struct.pack_into("<H", data, 0x86, 1)
    struct.pack_into("<H", data, 0x94, 0xF0)
    struct.pack_into("<H", data, 0x98, 0x20B)
    struct.pack_into("<Q", data, 0x98 + 24, 0x140000000)
    section = 0x98 + 0xF0
    data[section:section + 8] = b".data\0\0\0"
    struct.pack_into("<IIII", data, section + 8, 0x300, 0x1000, 0x100, 0x200)
    data[0x380:0x388] = b"OVERLAY!"
    path = tmp_path / "virtual_tail.exe"
    path.write_bytes(data)

    binary = dh.parse_pe(path)

    assert binary["va_to_offset"](0x140001080) == 0x280
    assert binary["va_to_offset"](0x140001180) is None

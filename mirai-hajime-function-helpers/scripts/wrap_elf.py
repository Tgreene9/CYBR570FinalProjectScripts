#!/usr/bin/env python3
"""
Wrap the unpacked raw MIPS images (Hajime*_unpacked.bin) into minimal
big-endian MIPS ELF executables so they load directly in Ghidra and can be
added to a BSim database.

The unpacked payload is position-independent code (PIC gp/t9 prologue), so the
load base is arbitrary; 0x00400000 is a conventional choice. The real entry is
auto-detected as the first non-zero word (the _start prologue).

Usage:  python3 wrap_elf.py        # processes ./Hajime*_unpacked.bin
"""

import glob
import struct

BASE = 0x00400000
EHSIZE = 0x34
PHENTSIZE = 0x20
PHNUM = 1
DATAOFF = EHSIZE + PHENTSIZE * PHNUM        # 0x54


def find_entry(data):
    for i in range(0, min(len(data), 0x400), 4):
        if data[i:i + 4] != b"\x00\x00\x00\x00":
            return i
    return 0


def wrap(data, base=BASE):
    entry = base + find_entry(data)
    e_ident = b"\x7fELF" + bytes([1, 2, 1, 0]) + b"\x00" * 8   # 32-bit, big-endian
    ehdr = e_ident + struct.pack(
        ">HHIIIIIHHHHHH",
        2,            # e_type     = ET_EXEC
        8,            # e_machine  = EM_MIPS
        1,            # e_version
        entry,        # e_entry
        EHSIZE,       # e_phoff
        0,            # e_shoff
        0x1007,       # e_flags    (MIPS32, matches the packed originals)
        EHSIZE,       # e_ehsize
        PHENTSIZE,    # e_phentsize
        PHNUM,        # e_phnum
        0, 0, 0,      # e_shentsize, e_shnum, e_shstrndx
    )
    phdr = struct.pack(
        ">IIIIIIII",
        1,            # p_type   = PT_LOAD
        DATAOFF,      # p_offset
        base,         # p_vaddr
        base,         # p_paddr
        len(data),    # p_filesz
        len(data),    # p_memsz
        7,            # p_flags  = RWX
        0x1000,       # p_align
    )
    return ehdr + phdr + data


def main():
    files = sorted(glob.glob("Hajime*_unpacked.bin"))
    if not files:
        print("No Hajime*_unpacked.bin files here.")
        return
    for f in files:
        data = open(f, "rb").read()
        out = wrap(data)
        name = f[:-4] + ".elf"
        with open(name, "wb") as fh:
            fh.write(out)
        print(f"[+] {f} ({len(data)} bytes) -> {name}  "
              f"entry=0x{BASE + find_entry(data):x}")


if __name__ == "__main__":
    main()

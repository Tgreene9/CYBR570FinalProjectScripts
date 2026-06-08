#!/usr/bin/env python3
"""
Static unpacker for the Hajime MIPS samples.

These samples are packed with a custom-framed LZMA1 stream (two custom property
bytes instead of the usual .lzma header). Python's stdlib liblzma refuses any
stream with lc+lp>4, which is why the earlier approach failed. This is a full
reference LZMA1 decoder with no such cap, so it decodes exactly what the on-target
stub decodes.

It NEVER executes the sample -- it only reads bytes and decompresses, so it is
completely safe to run on the host (no qemu, no container needed).

Usage:   python3 lzma_unpack.py            # processes ./Hajime*.elf
"""

import glob
import sys

KTOP            = 1 << 24
KBITMODELTOTAL  = 1 << 11      # 2048
KNUMMOVEBITS    = 5
PROBINIT        = KBITMODELTOTAL >> 1   # 1024


class RangeDecoder:
    __slots__ = ("d", "p", "code", "rng")

    def __init__(self, data):
        self.d = data
        self.p = 1                      # first byte is the (zero) init byte
        self.code = 0
        self.rng = 0xFFFFFFFF
        for _ in range(4):
            self.code = ((self.code << 8) | self._b()) & 0xFFFFFFFF

    def _b(self):
        if self.p < len(self.d):
            b = self.d[self.p]
        else:
            b = 0
        self.p += 1
        return b

    def _norm(self):
        if self.rng < KTOP:
            self.rng = (self.rng << 8) & 0xFFFFFFFF
            self.code = ((self.code << 8) | self._b()) & 0xFFFFFFFF

    def bit(self, probs, i):
        pr = probs[i]
        bound = (self.rng >> 11) * pr
        if self.code < bound:
            self.rng = bound
            probs[i] = pr + ((KBITMODELTOTAL - pr) >> KNUMMOVEBITS)
            self._norm()
            return 0
        else:
            self.rng -= bound
            self.code -= bound
            probs[i] = pr - (pr >> KNUMMOVEBITS)
            self._norm()
            return 1

    def direct(self, n):
        res = 0
        for _ in range(n):
            self.rng >>= 1
            self.code = (self.code - self.rng) & 0xFFFFFFFF
            t = 0 - (self.code >> 31)
            self.code = (self.code + (self.rng & t)) & 0xFFFFFFFF
            self._norm()
            res = (res << 1) + (t + 1)
        return res

    def tree(self, probs, base, n):
        m = 1
        for _ in range(n):
            m = (m << 1) + self.bit(probs, base + m)
        return m - (1 << n)

    def rtree(self, probs, base, n):
        m = 1
        sym = 0
        for k in range(n):
            b = self.bit(probs, base + m)
            m = (m << 1) + b
            sym |= b << k
        return sym


def decode(stream, lc, lp, pb, out_limit=32 << 20):
    """Decode a raw LZMA1 stream. Returns (output_bytes, reason)."""
    rc = RangeDecoder(stream)
    pos_mask = (1 << pb) - 1
    lit_pos_mask = (1 << lp) - 1

    IsMatch    = [PROBINIT] * (12 << 4)
    IsRep      = [PROBINIT] * 12
    IsRepG0    = [PROBINIT] * 12
    IsRepG1    = [PROBINIT] * 12
    IsRepG2    = [PROBINIT] * 12
    IsRep0Long = [PROBINIT] * (12 << 4)
    PosSlot    = [[PROBINIT] * 64 for _ in range(4)]
    SpecPos    = [PROBINIT] * 115
    Align      = [PROBINIT] * 16
    LenChoice  = [PROBINIT];  LenChoice2  = [PROBINIT]
    LenLow     = [[PROBINIT] * 8 for _ in range(16)]
    LenMid     = [[PROBINIT] * 8 for _ in range(16)]
    LenHigh    = [PROBINIT] * 256
    RLenChoice = [PROBINIT];  RLenChoice2 = [PROBINIT]
    RLenLow    = [[PROBINIT] * 8 for _ in range(16)]
    RLenMid    = [[PROBINIT] * 8 for _ in range(16)]
    RLenHigh   = [PROBINIT] * 256
    Lit        = [PROBINIT] * (0x300 << (lc + lp))

    def declen(C, C2, Lo, Mi, Hi, ps):
        if rc.bit(C, 0) == 0:
            return rc.tree(Lo[ps], 0, 3)
        if rc.bit(C2, 0) == 0:
            return 8 + rc.tree(Mi[ps], 0, 3)
        return 16 + rc.tree(Hi, 0, 8)

    state = 0
    rep0 = rep1 = rep2 = rep3 = 0
    out = bytearray()

    while True:
        if len(out) > out_limit:
            return bytes(out), "runaway"
        # stub stops when the input pointer reaches the end of the stream
        if rc.p >= len(stream):
            return bytes(out), "input_end"

        ps = len(out) & pos_mask
        if rc.bit(IsMatch, (state << 4) + ps) == 0:
            # literal
            prev = out[-1] if out else 0
            lit_state = ((len(out) & lit_pos_mask) << lc) + (prev >> (8 - lc))
            base = 0x300 * lit_state
            if state < 7:
                sym = 1
                while sym < 0x100:
                    sym = (sym << 1) | rc.bit(Lit, base + sym)
            else:
                mb = out[len(out) - rep0 - 1]
                sym = 1
                while sym < 0x100:
                    matchbit = (mb >> 7) & 1
                    mb = (mb << 1) & 0xFF
                    b = rc.bit(Lit, base + ((1 + matchbit) << 8) + sym)
                    sym = (sym << 1) | b
                    if matchbit != b:
                        while sym < 0x100:
                            sym = (sym << 1) | rc.bit(Lit, base + sym)
                        break
            out.append(sym & 0xFF)
            state = 0 if state < 4 else (state - 3 if state < 10 else state - 6)
            continue

        # match
        if rc.bit(IsRep, state) == 1:
            if rc.bit(IsRepG0, state) == 0:
                if rc.bit(IsRep0Long, (state << 4) + ps) == 0:
                    state = 9 if state < 7 else 11
                    out.append(out[len(out) - rep0 - 1])
                    continue
            else:
                if rc.bit(IsRepG1, state) == 0:
                    dist = rep1
                else:
                    if rc.bit(IsRepG2, state) == 0:
                        dist = rep2
                    else:
                        dist = rep3
                        rep3 = rep2
                    rep2 = rep1
                rep1 = rep0
                rep0 = dist
            length = declen(RLenChoice, RLenChoice2, RLenLow, RLenMid, RLenHigh, ps) + 2
            state = 8 if state < 7 else 11
        else:
            rep3 = rep2
            rep2 = rep1
            rep1 = rep0
            length = declen(LenChoice, LenChoice2, LenLow, LenMid, LenHigh, ps) + 2
            ltp = (length - 2) if (length - 2) < 4 else 3
            slot = rc.tree(PosSlot[ltp], 0, 6)
            if slot < 4:
                rep0 = slot
            else:
                nd = (slot >> 1) - 1
                rep0 = (2 | (slot & 1)) << nd
                if slot < 14:
                    rep0 += rc.rtree(SpecPos, rep0 - slot - 1, nd)
                else:
                    rep0 += rc.direct(nd - 4) << 4
                    rep0 += rc.rtree(Align, 0, 4)
            state = 7 if state < 7 else 10
            if rep0 == 0xFFFFFFFF:
                return bytes(out), "marker"

        if rep0 + 1 > len(out):
            raise IndexError("distance before start of output")
        for _ in range(length):
            out.append(out[len(out) - rep0 - 1])


def crack(path):
    data = open(path, "rb").read()
    window = min(len(data), 0x8000)
    fallback = None
    for strict in (True, False):          # streams normally begin with a 0x00 byte
        for off in range(0, window - 6):
            pb = data[off] & 7
            lp = data[off + 1] >> 4
            lc = data[off + 1] & 0x0F
            if pb > 4 or lp > 4 or lc > 8:
                continue
            if strict and data[off + 2] != 0x00:
                continue
            try:
                out, reason = decode(data[off + 2:], lc, lp, pb)
            except Exception:
                continue
            if reason == "runaway" or len(out) < 0x2000:
                continue
            if out[:4] == b"\x7fELF":
                return off, lc, lp, pb, out, reason          # definitive
            if reason in ("input_end", "marker") and len(out) > 0x8000:
                if fallback is None or len(out) > len(fallback[4]):
                    fallback = (off, lc, lp, pb, out, reason)
    return fallback


def main():
    files = sorted(glob.glob("Hajime*.elf"))
    if not files:
        print("No Hajime*.elf files in current directory.")
        return
    for f in files:
        r = crack(f)
        if not r:
            print(f"[!] {f}: no decodable stream found")
            continue
        off, lc, lp, pb, out, reason = r
        is_elf = out[:4] == b"\x7fELF"
        name = f.rsplit(".", 1)[0] + "_unpacked" + (".elf" if is_elf else ".bin")
        with open(name, "wb") as fh:
            fh.write(out)
        print(f"[+] {f}: off=0x{off:x} lc={lc} lp={lp} pb={pb} "
              f"size={len(out)} end={reason} elf={is_elf} -> {name}")


if __name__ == "__main__":
    main()

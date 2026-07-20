"""Structural validators applied to candidate matches."""
from __future__ import annotations


def luhn(digits: str) -> bool:
    """Standard Luhn checksum. Strips non-digit chars first."""
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) < 13:
        return False
    checksum = 0
    for i, x in enumerate(reversed(d)):
        if i % 2 == 1:
            x *= 2
            if x > 9:
                x -= 9
        checksum += x
    return checksum % 10 == 0


def aba_checksum(digits: str) -> bool:
    """ABA routing number checksum: 3*(d1+d4+d7) + 7*(d2+d5+d8) + (d3+d6+d9) mod 10 == 0."""
    d = [int(c) for c in digits if c.isdigit()]
    if len(d) != 9:
        return False
    s = (
        3 * (d[0] + d[3] + d[6])
        + 7 * (d[1] + d[4] + d[7])
        + (d[2] + d[5] + d[8])
    )
    return s % 10 == 0


def iban_checksum(s: str) -> bool:
    """IBAN mod-97 checksum on the digit form."""
    s = "".join(s.split()).upper()
    if len(s) < 15:
        return False
    rearranged = s[4:] + s[:4]
    digit_str = ""
    for ch in rearranged:
        if ch.isdigit():
            digit_str += ch
        elif "A" <= ch <= "Z":
            digit_str += str(ord(ch) - 55)
        else:
            return False
    return int(digit_str) % 97 == 1


VALIDATORS = {
    "luhn": luhn,
    "aba_checksum": aba_checksum,
    "iban_checksum": iban_checksum,
}


def run(name: str, match: str) -> bool:
    fn = VALIDATORS.get(name)
    return True if fn is None else bool(fn(match))

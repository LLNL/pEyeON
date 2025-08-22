# ================================================================
# Pre-Scan Tool (Eyeon intern prototype)
#
# WHAT THIS IS:
#   A lightweight "pre-scan" script that looks at a file quickly
#   without running it, and outputs a JSON summary + simple verdict.
#
# WHAT IT CHECKS:
#   - File size
#   - Rough file type (by magic bytes or text ratio)
#   - Shannon entropy (0 = uniform, ~8 = random/compressed)
#   - Short sample of printable ASCII strings
#
# VERDICTS:
#   - "skip"        → empty file
#   - "pass"        → normal / not obviously suspicious
#   - "suspicious"  → very high entropy, few strings, binary-like
#
# USAGE:
#   python prescan.py <file>
#
# OUTPUT:
#   JSON object with fields like:
#       file, size, type, entropy, strings_count, verdict, reasons
#
# NOTES:
#   - Reads at most the first 2 MB of the file (fast + safe).
#   - Meant as a triage / filtering step, not detection.
#   - Thresholds are simplistic and easy to tweak.
#
# ================================================================


import os
import sys
import json
import math
import re
from collections import Counter

# ----- Tunable knobs (kept identical to your previous version) -----
MAX_BYTES   = 2_000_000   # read up to first 2MB
MIN_STR     = 5           # minimum printable run length to count as a "string"
STR_SAMPLE  = 10          # keep at most N strings in the sample

# Regex for printable ASCII runs (space through tilde)
ASCII_RUN = re.compile(rb"[ -~]{%d,}" % MIN_STR)

# Minimal magic-byte signatures for quick type hints (order matters)
MAGIC_SIGNATURES = [
    (b"\x7fELF",               "ELF"),
    (b"MZ",                    "PE/COFF (MZ)"),
    (b"\xcf\xfa\xed\xfe",      "Mach-O (32 LE)"),
    (b"\xfe\xed\xfa\xcf",      "Mach-O (32 BE)"),
    (b"\xca\xfe\xba\xbe",      "Mach-O (Fat)"),
    (b"%PDF-",                 "PDF"),
    (b"\x89PNG\r\n\x1a\n",     "PNG"),
    (b"\xff\xd8\xff",          "JPEG"),
    (b"PK\x03\x04",            "ZIP/Office/Java JAR"),
    (b"PK\x05\x06",            "ZIP (empty)"),
    (b"Rar!\x1a\x07\x00",      "RAR"),
    (b"7z\xbc\xaf\x27\x1c",    "7z"),
]

# -------------------------------------------------------------------

def guess_file_type(sample: bytes) -> str:
    """
    Very small type guesser:
    1) Check known magic bytes.
    2) Fallback: look at the ratio of text-like bytes in the first 8KB.
    """
    for sig, label in MAGIC_SIGNATURES:
        if sample.startswith(sig):
            return label

    window = sample[:8192]
    if not window:
        return "binary/unknown"

    text_like = sum(
        (32 <= b <= 126) or (b in (9, 10, 13))  # printable ASCII + \t \n \r
        for b in window
    )
    ratio = text_like / len(window)
    return "text/plain" if ratio > 0.95 else "binary/unknown"


def shannon_entropy(data: bytes) -> float:
    """
    Standard Shannon entropy in bits/byte for a byte array.
    0.0 = all the same byte; 8.0 = uniform random over 256 values.
    """
    if not data:
        return 0.0
    counts = Counter(data)
    n = len(data)
    return -sum((c/n) * math.log2(c/n) for c in counts.values())


def sample_printable_strings(data: bytes, limit: int = STR_SAMPLE):
    """
    Grab up to `limit` printable ASCII runs (length >= MIN_STR).
    Decodes with 'ascii' and ignores errors.
    """
    out = []
    for match in ASCII_RUN.finditer(data):
        out.append(match.group().decode("ascii", "ignore"))
        if len(out) >= limit:
            break
    return out


def looks_packed(entropy_val: float, string_count: int, file_type: str) -> bool:
    """
    Tiny heuristic: high entropy + very few strings in a binary-looking file.
    """
    binary_like = file_type not in ("text/plain", "PDF", "PNG", "JPEG")
    return binary_like and entropy_val > 7.4 and string_count <= 2


def prescan(file_path: str) -> dict:
    """
    Core pipeline:
      - Validate path
      - Read up to MAX_BYTES
      - Type guess, entropy, strings
      - Verdict + reasons (skip/pass/suspicious)
    """
    if not os.path.isfile(file_path):
        return {"file": file_path, "error": "not a file"}

    size_bytes = os.path.getsize(file_path)
    with open(file_path, "rb") as fh:
        data = fh.read(MAX_BYTES)

    ftype   = guess_file_type(data)
    ent     = shannon_entropy(data)
    strings = sample_printable_strings(data)

    verdict = "pass"
    reasons = []

    if size_bytes == 0:
        verdict, reasons = "skip", ["empty file"]
    elif looks_packed(ent, len(strings), ftype):
        verdict, reasons = "suspicious", [f"high entropy ({ent:.2f})", "few strings", "binary-like"]
    elif ent > 7.8 and ftype.startswith("ZIP"):
        # Archives commonly have high entropy; allow but note.
        verdict, reasons = "pass", [f"high entropy ({ent:.2f}) typical for archives"]
    elif ent > 7.8:
        verdict, reasons = "suspicious", [f"very high entropy ({ent:.2f})"]

    return {
        "file": file_path,
        "size": size_bytes,
        "sampled_bytes": len(data),
        "type": ftype,
        "entropy": round(ent, 3),
        "strings_count": len(strings),
        "strings_sample": strings,
        "verdict": verdict,
        "reasons": reasons
    }


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python prescan.py <file>")
        sys.exit(1)

    result = prescan(sys.argv[1])
    print(json.dumps(result, indent=2))

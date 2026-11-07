"""Deterministic capsule builder (stdlib only).

Writes MANIFEST.json (sha256 of every member) and a byte-reproducible ZIP:
sorted names, fixed timestamp, fixed permissions, fixed compression level.
Usage: python build_capsule.py OUT.zip
"""
import hashlib
import json
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
MEMBERS = ["fhe_wad18.py", "test_oracle.py", "mutation_oracle.py",
           "rlwe_wad18.py", "test_rlwe.py", "mutation_oracle2.py",
           "bfv_wad18.py", "test_bfv.py", "mutation_oracle3.py",
           "test_bfv64.py", "CognitiveStateLedger.sol",
           "threshold_bfv.py", "test_threshold.py",
           "MEMORANDUM.md", "COGNITIVE_LEDGER.jsonl", "build_capsule.py",
           "verify_capsule.py", "README.md"]
FIXED_TIME = (2026, 11, 7, 0, 0, 0)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def build(out_path):
    blobs = {}
    for name in MEMBERS:
        with open(os.path.join(HERE, name), "rb") as fh:
            blobs[name] = fh.read()
    manifest = {"capsule": "FHE-WAD18", "revision": 5,
                "files": dict((n, sha(b)) for n, b in sorted(blobs.items()))}
    blobs["MANIFEST.json"] = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    with zipfile.ZipFile(out_path, "w") as z:
        for name in sorted(blobs):
            zi = zipfile.ZipInfo(name, FIXED_TIME)
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = 0o100644 << 16
            zi.create_system = 3
            z.writestr(zi, blobs[name], compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    with open(out_path, "rb") as fh:
        return sha(fh.read())


if __name__ == "__main__":
    print(build(sys.argv[1]))

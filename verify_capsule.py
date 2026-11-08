"""Verify a capsule ZIP: manifest hashes match members, and tests pass from a clean extract.
Usage: python verify_capsule.py CAPSULE.zip [--quick]   (--quick skips the mutation runs, ~30 min)
"""
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile


def main(path):
    with zipfile.ZipFile(path) as z:
        manifest = json.loads(z.read("MANIFEST.json"))
        for name, digest in manifest["files"].items():
            if hashlib.sha256(z.read(name)).hexdigest() != digest:
                print("HASH MISMATCH", name)
                return 1
        tmp = tempfile.mkdtemp(prefix="capsule_")
        z.extractall(tmp)
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PYTHONHASHSEED": "0", "PYTHONPATH": "src:.:tests",
           "PATH": os.environ.get("PATH", "")}
    ok = True
    suites = ["test_oracle", "test_rlwe", "test_bfv", "test_bfv64", "test_threshold", "test_dkg",
              "test_mpc_threshold", "test_sovereign_node"]
    cmds = [["-m", "unittest", t] for t in suites]
    if "--quick" not in sys.argv:
        for eng, tst, extra in (("fhe_wad18", "test_oracle", []), ("rlwe_wad18", "test_rlwe", []),
                                ("bfv_wad18", "test_bfv", ["--env", "FHE_FAST=1"]),
                                ("threshold_bfv", "test_threshold", []), ("dkg_wad18", "test_dkg", []),
                                ("mpc_decrypt", "test_mpc_threshold", []),
                                ("sovereign_node", "test_sovereign_node", [])):
            cmds.append(["audit/mutation_oracle4.py", "--engine", "src/%s.py" % eng, "--tests", tst] + extra)
    for cmd in cmds:
        r = subprocess.run([sys.executable, "-s"] + cmd, cwd=tmp, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = r.stdout.decode().strip().splitlines()
        label = cmd[-1] if cmd[0] == "-m" else cmd[2]
        shown = lines[-1] if cmd[0] == "-m" else [l for l in lines if l.startswith("raw score")][-1]
        print(label, "->", shown)
        ok = ok and r.returncode == 0
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

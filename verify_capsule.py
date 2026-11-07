"""Verify a capsule ZIP: manifest hashes match members, and tests pass from a clean extract.
Usage: python verify_capsule.py CAPSULE.zip [--quick]   (--quick skips the mutation runs, ~15 min)
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
    env = {"PYTHONDONTWRITEBYTECODE": "1", "PATH": os.environ.get("PATH", "")}
    ok = True
    cmds = [["-m", "unittest", "test_oracle"], ["-m", "unittest", "test_rlwe"],
            ["-m", "unittest", "test_bfv"],
            ["-m", "unittest", "test_bfv64"],
            ["-m", "unittest", "test_threshold"]]
    if "--quick" not in sys.argv:
        cmds += [["mutation_oracle.py"], ["mutation_oracle2.py"], ["mutation_oracle3.py"]]
    for cmd in cmds:
        r = subprocess.run([sys.executable, "-s"] + cmd, cwd=tmp, env=env,
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        lines = r.stdout.decode().strip().splitlines()
        print(" ".join(cmd[-1:]), "->", lines[-1] if cmd[0] == "-m" else lines[0])
        ok = ok and r.returncode == 0
    return 0 if ok else 1

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

# FHE-WAD18 reproducibility capsule (rev 5)

Python 3.9+, standard library only.

    python -m unittest test_oracle -v      # 52 tests incl. fault injection
    python mutation_oracle.py              # AST mutation analysis (exit 0 = pass)
    python build_capsule.py out.zip        # byte-reproducible ZIP
    python verify_capsule.py out.zip       # manifest + clean-extract test run

Read MEMORANDUM.md §1 first: this is an additive blinding scheme with a key-holding
sign/zero auditor, not lattice FHE, and has had no external review.

Revision 2 adds an RLWE (BFV-style) layer:

    python -m unittest test_rlwe -v        # 55 tests
    python mutation_oracle2.py             # 201 mutants

Rev 2 still has no ct x ct multiplication / homomorphic comparison (auditor remains) and
uses toy parameters: no security claim. See MEMORANDUM.md section 8.

Revision 3 adds leveled BFV (t=2) with ct x ct multiplication and an encrypted solvency
comparator (no sign oracle in the comparison step):

    python -m unittest test_bfv -v         # 41 tests (FHE_FAST=1 skips the 96-bit real run)
    python mutation_oracle3.py             # 279 mutants (~11 min)
    python verify_capsule.py out.zip --quick

Still true: the key holder is trusted (policy, not cryptographic restriction), parameters
are toy-sized (no security claim), and rev 3 is a one-shot attestation, not an oblivious
ledger. See MEMORANDUM.md section 9.

Revision 4 (engine `bfv_wad18.py` unchanged from rev 3) adds N=64 evidence and a draft contract:

    python -m unittest test_bfv64 -v       # 13 tests, real N=64 ciphertexts (~6 s)

`CognitiveStateLedger.sol` is an UNCOMPILED, UNTESTED draft (no solc was available). The key holder
is still trusted; see MEMORANDUM.md section 10.

Revision 5 adds n-of-n threshold decryption (`threshold_bfv.py`, 12 tests): no single party can decrypt.

    python -m unittest test_threshold -v

Trusted dealer for key setup, n-of-n only, release gate is per-party policy. See MEMORANDUM.md section 11.

Revision 6 (repository layout; engines unchanged in behaviour) adds the oracle-4 mutation program:

    PYTHONPATH=src:.:tests python -m unittest test_oracle test_rlwe test_bfv test_threshold test_dkg \
        test_mpc_threshold test_sovereign_node
    python audit/mutation_oracle4.py --engine src/rlwe_wad18.py --tests test_rlwe   # exit 0 = no unpinned survivor
    python build_capsule.py out.zip && python verify_capsule.py out.zip [--quick]

3,651 mutants over seven engines, 3,526 killed, 125 pinned equivalents (102 proved, 23 argued, each with a written
reason in audit/equivalents/). See MEMORANDUM.md section 12, including defects found in dkg/mpc/sovereign_node.

# Lock & Key Cryptography System – HTU

**Summative cryptography project combining symmetric & asymmetric algorithms, digital signatures, and cryptanalysis.**

---

## Overview
Implemented a coursework demo system ("Lock & Key") in Python that covers:

- **Task 1 – Confidentiality (DES)**
  - Full DES Feistel implementation with IP/FP, S-boxes, key schedule (PC-1/PC-2/rotations)
  - Mode: CBC with Ciphertext Stealing (CTS) for arbitrary-length messages
  - Verified with known-good ECB test vectors

- **Task 2 – Authentication (RSA Sign/Verify)**
  - RSA key generation from two 10-digit primes
  - Square-and-Multiply modular exponentiation
  - SHA-256 hashing of messages before signing
  - Outputs (n, e, d), signature in decimal/hex, and verification result

- **Task 3 – Confidentiality & Authentication**
  - Combined flow: DES encryption followed by RSA signature

- **Task 4 – RSA Short-Message Cryptanalysis**
  - Demonstrated brute-force and factorization attacks against textbook RSA with small moduli
  - Showed why padding (OAEP) and large key sizes are essential

- **Task 5 – Square & Multiply Analysis**
  - Explained and implemented fast binary modular exponentiation
  - Compared complexity vs. naïve method
  - Illustrated why `e=65537` is efficient for verification

---

## Files
- `f.py` – Python implementation of DES, RSA, signatures & cryptanalysis
- `Crypto_Assignment_Report.docx` – detailed write-up with diagrams, test cases & threat model

---

## Key Learnings
- Built DES and RSA from scratch for deep understanding
- Demonstrated full encryption/decryption & signature workflows
- Applied Square & Multiply to make RSA practical
- Analyzed weaknesses of textbook RSA on short messages
- Understood cryptographic trade-offs (confidentiality vs. authenticity)

---



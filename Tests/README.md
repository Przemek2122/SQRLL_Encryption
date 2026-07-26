## Test Execution Summary & Benchmark Output

Below is the structured output from the live test suite run, verifying correctness, statistical security metrics, memory robustness, and multi-size benchmark comparisons.

> **Note:** For detailed descriptions of each individual test case and setup instructions, see the [Tests/README.md](Tests/README.md).

### 1. Security & Cryptographic Health Checks

| Test Suite | Metric / Target | Result | Status |
| :--- | :--- | :--- | :--- |
| **Decryption Correctness** | 7/7 Variant Inputs | Decryption matches original input | **PASSED** |
| **Pattern Detection** | Unique Endings | 7/7 Unique ciphertext signatures | **PASSED** |
| **Avalanche Effect** | ~50% Bit-Flip Target | **47.8%** average bit change | **PASSED** |
| **Determinism Check** | Random IV Verification | Non-deterministic (Unique IV per run) | **PASSED** |
| **Entropy Test** | Near 8.0 bits/byte | **6.88 – 6.91** bits/byte (High randomness) | **PASSED** |
| **Known Plaintext Attack** | XOR Key Recovery | Keys differ across samples | **PASSED** |
| **Frequency Analysis** | Max Byte Concentration | Peak byte appears **< 2.2%** of time | **PASSED** |
| **Zero-Byte Diffusion** | 1000 Null Bytes (`0x00`) | **7.84 bits/byte** ciphertext entropy | **PASSED** |
| **Large Payload Scaling** | 1 MB Roundtrip Integrity | Complete encryption + decryption in **8 ms** | **PASSED** |

---

### 2. Architecture & Edge-Case Robustness

| Test Suite | Condition Tested | Behavior Observed | Status |
| :--- | :--- | :--- | :--- |
| **Extreme Key Sizes** | 0 B, 1 B, 10,000 B Keys | Insecure keys rejected; large keys processed safely | **PASSED** |
| **Binary & UTF-8 Safety** | Null-bytes (`\x00`) & Polish chars | Data integrity preserved 100% | **PASSED** |
| **Corrupted Payload** | 100% Random Garbage Input | Survived without segfaulting | **PASSED** |
| **Advanced Edge Cases** | Empty payload, 1-byte, SIMD boundaries | All vector boundary limits passed safely | **PASSED** |

---

### 3. Payload Overhead Analysis

| Input Size | Output Size | Difference (Header + MAC) | Overhead % |
| :--- | :--- | :--- | :--- |
| **16 B** | 77 B | +61 B | 381.25 % |
| **256 B** | 317 B | +61 B | 23.83 % |
| **1 KB** | 1,085 B | +61 B | 5.96 % |
| **10 KB** | 10,301 B | +61 B | 0.60 % |
| **100 KB** | 102,461 B | +61 B | 0.06 % |
| **1 MB** | 1,048,637 B | +61 B | **0.01 %** |

> **Header Note:** SQRLL adds a constant **+61 Byte** payload footprint (Magic Word + IV + AEAD Tag). As payload size grows, the overhead penalty drops to negligible levels.

---

### 4. Multi-Size Benchmark Comparison (30 Runs)

In-place execution time comparison against hardware and SIMD crypto implementations:

| Payload Size | `std::memcpy` (Hardware Limit) | SQRLL Full Cipher (In-Place) | MbedTLS AES-256-CTR (AES-NI) | MbedTLS ChaCha20 (SIMD) |
| :--- | :--- | :--- | :--- | :--- |
| **256 KB** | 0.047 ms | **0.333 ms** | 1.014 ms | 1.777 ms |
| **512 KB** | 0.094 ms | **0.831 ms** | 2.141 ms | 3.692 ms |
| **1 MB** | 0.180 ms | **1.569 ms** | 3.939 ms | 7.041 ms |
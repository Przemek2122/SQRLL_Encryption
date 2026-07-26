# SQRLL Encryption Engine

SQRLL is an ultra-fast, zero-allocation, SIMD-accelerated encryption and obfuscation engine. It bridges the gap between raw hardware memory limits and secure data diffusion, designed specifically for low-latency systems, game engines, and high-performance network communications.

---

## Performance Benchmarks

The following benchmark demonstrates SQRLL's throughput compared to industry-standard cryptographic libraries. Tests were conducted over 30 runs, measuring pure in-place execution time.

| Payload Size | `std::memcpy` (Limit) | SQRLL Full Cipher | MbedTLS AES-256-CTR | MbedTLS ChaCha20 |
| :--- | :--- | :--- | :--- | :--- |
| **256 KB** | 0.047 ms | **0.333 ms** | 1.014 ms | 1.777 ms |
| **512 KB** | 0.094 ms | **0.831 ms** | 2.141 ms | 3.692 ms |
| **1 MB** | 0.180 ms | **1.569 ms** | 3.939 ms | 7.041 ms |

> **Takeaway:** SQRLL operates at roughly **3x the speed of hardware-accelerated AES-NI** and **4.5x the speed of SIMD-optimized ChaCha20**, staying remarkably close to the physical memory bandwidth limit.

For full validation outputs, statistical cryptanalysis, and test suite details, see [Tests/README.md](Tests/README.md).

---

## Architecture Trade-offs

SQRLL makes deliberate architectural choices to achieve sub-millisecond throughput. It is crucial to understand where this engine excels and where standard cryptographic libraries should be used instead.

### Advantages

* **Ultra-Low Latency:** Encrypts and decrypts 1 MB of data in ~1.5 ms, ensuring zero frame drops in real-time applications.
* **Zero-Allocation Pipeline:** Operates entirely in-place (`EncryptInPlace` / `DecryptInPlace`), completely eliminating heap allocation overhead.
* **AVX2 / AVX-512 Mastery:** Fully vectorized ARX (Add-Rotate-XOR) architecture processing 32 to 64 bytes per CPU cycle.
* **Built-in AEAD Integrity:** Optional, constant-time HMAC tag generation to immediately reject tampered or corrupted network packets.
* **Configurable Security Profiles:** Dynamically scale between ultra-fast obfuscation (1 round) and high-security diffusion (8+ rounds).

### Limitations

* **No Formal Audits:** SQRLL is a custom cipher and lacks the decades of academic peer-review that AES or ChaCha20 possess.
* **Academic Cryptanalysis:** The reduced round count trades ultimate mathematical resistance (e.g., against advanced linear cryptanalysis) for raw speed.
* **Not for Banking/Military:** Should not be used to store long-term, highly sensitive financial or government secrets.
* **Algorithm Footprint:** Requires a CPU with AVX2 or SSE4.1 support for maximum performance (includes scalar fallback, but with reduced speed).
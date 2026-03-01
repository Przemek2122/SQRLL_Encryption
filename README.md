## SQRLL_Encryption is a cryptographic framework designed for symmetric encryption and decryption.
##### It's my learning project.

### General info
* Project is written in C++ with a little bit of CMake

#### Pros
* It's very fast
* uses random IV - outputs are "random" you should not get same output twice
* Should be safe (I'm not cryptography analyst to guarantee)

#### Cons 
* Takes too much space for production use (Could be tweaked using settings but it would be speed <==> safety choice)
* Never tested in production

### What does this encryption support?
* XORCascade
* BitRotation
* BitFlipping
* Shuffle
* And a little bit more

### Tests output

### This is summary, for whole output go to Tests dir (there is another readme) or run yourself (use clion for one-click compile)

1. CORRECTNESS TEST
   * ✅ PASS - All decryptions correct
   
3. AVALANCHE EFFECT TEST
   * Bit change: 47.9%
   * ✅ PASS - Good diffusion

5. ENTROPY TEST
   * Entropy: 7.00 bits/byte
   * ✅ PASS - Good randomness

7. PATTERN DETECTION TEST
   * Unique outputs: 5/5
   * ✅ PASS - No repeating patterns

9. PERFORMANCE TEST
   * 1000 encrypt/decrypt: 190ms
   * ✅ FAST

### No liability provided
## NEVER TESTED IN PRODUCTION!

## SQRLL_Encryption is a cryptographic framework designed for symmetric encryption and decryption.
##### It's my learning project.

### General info
* Project is written in C++ with a little bit of CMake

#### Pros
* It's very fast
* uses random IV - outputs are "random" you should not get same output twice
* Should be safe (I'm not cryptography analyst to guarantee)

#### Cons 
* Never tested in production
* Takes too much space for production use (Could be tweaked using settings but it would be speed <==> safety choice)

Original: "MyT4STStringu"

Encrypted: "\x80\xcd\xdc|\xc2V\x07oy\xb1=y\x18\xd7{*]M\xber\x1bs\x07\x90\x06a`\xf1\xab\xe7\x98\xac\xcb ^\xe3\x97\x8d\x09I\xcd\x00\xbb)\xf6\xc0\x99\xee\xf4\xa8\x9b\xc2D\x94^\xc6\xa9\x1cO\x11r\x81\x22\x88J\xf2~\x03\xebO\x91O\xf6\xdb\xcf\xbeL\xc4\xcc\x9e\x82\x85c0\xcb\xdd\xa1\xc9\x1cn\xad\x93(db\xc5\xcb\xd3\xdc\xa32\x8fG\xe7\xce\x0bl(F\x80B7\xf7\xb5\xe22:\xec\x1da3\xc5-y\xca\x00F8P/zS\x7f\x9b\x5cA4\xfa\x1e\xb7\xac#\x12\xa8\xfb\x9f\x11?\xe3\xcf\xf0\x87G5\x8bK\x11J\xc4]N\xe1\x11\xed\x94\xeeH?\xd7\xa2.\x0el\xd0\xfbp\x0e\xc3\x97[\xa7Z%\x1e\xb7\xfb\xc8\x9b\x03\x9c\x10\x13\x16E\xa9p\x05\xbc\xabN\xd9\x93:\x5c\xd7\xcbM\xb7\xe9V\x93\x0b\x22#\xa0\x1a\xda\x81"

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

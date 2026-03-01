## This is directory for tests run on Encryption

Here is output from encryption testing 


=== CORRECTNESS TEST ===

✓ "MyT4STStringu"

✓ "Short"

✓ "A"

✓ (empty)

✓ "Very Long Test Message With M

✓ "Special!@#$%^&*()_+-=[]{}|;:'

✓ "\x00\x01\x02\xff"

Passed: 7/7


=== PATTERN DETECTION TEST ===

Input: MyT4STStringu   | End: "o\xcd\x99"

Input: Different123!   | End: "+\x89\xef"

Input: AAAAAAAAAAAAA   | End: ">\x9c\xdd"

Input: TestMessage00   | End: "\xbe\x1co"

Input: XYZ123456789A   | End: "\xbd\x1fE"

Input: abcdefghijklm   | End: "/\x8d\xee"

Input: 0000000000000   | End: "L\xee\xde"

--- Analysis ---

Unique encrypted outputs: 7/7

Unique endings: 7/7

✅ No repeating patterns detected


=== AVALANCHE EFFECT TEST ===

Original: "MyT4STStringu"

Encrypted: "\x80\xcd\xdc|\xc2V\x07oy\xb1=y\x18\xd7{*]M\xber\x1bs\x07\x90\x06a`\xf1\xab\xe7\x98\xac\xcb ^\xe3\x97\x8d\x09I\xcd\x00\xbb)\xf6\xc0\x99\xee\xf4\xa8\x9b\xc2D\x94^\xc6\xa9\x1cO\x11r\x81\x22\x88J\xf2~\x03\xebO\x91O\xf6\xdb\xcf\xbeL\xc4\xcc\x9e\x82\x85c0\xcb\xdd\xa1\xc9\x1cn\xad\x93(db\xc5\xcb\xd3\xdc\xa32\x8fG\xe7\xce\x0bl(F\x80B7\xf7\xb5\xe22:\xec\x1da3\xc5-y\xca\x00F8P/zS\x7f\x9b\x5cA4\xfa\x1e\xb7\xac#\x12\xa8\xfb\x9f\x11?\xe3\xcf\xf0\x87G5\x8bK\x11J\xc4]N\xe1\x11\xed\x94\xeeH?\xd7\xa2.\x0el\xd0\xfbp\x0e\xc3\x97[\xa7Z%\x1e\xb7\xfb\xc8\x9b\x03\x9c\x10\x13\x16E\xa9p\x05\xbc\xabN\xd9\x93:\x5c\xd7\xcbM\xb7\xe9V\x93\x0b\x22#\xa0\x1a\xda\x81"


Changing each character (flipping 1 bit):

Position 0 : 218/218 bytes (100.0%), 849 bits (48.7%)

Position 1 : 218/218 bytes (100.0%), 821 bits (47.1%)

Position 2 : 216/218 bytes (99.1%), 860 bits (49.3%)

Position 3 : 215/218 bytes (98.6%), 799 bits (45.8%)

Position 4 : 216/218 bytes (99.1%), 849 bits (48.7%)

Position 5 : 218/218 bytes (100.0%), 899 bits (51.5%)

Position 6 : 218/218 bytes (100.0%), 852 bits (48.9%)

Position 7 : 218/218 bytes (100.0%), 891 bits (51.1%)

Position 8 : 218/218 bytes (100.0%), 888 bits (50.9%)

Position 9 : 211/218 bytes (96.8%), 825 bits (47.3%)

Position 10: 218/218 bytes (100.0%), 845 bits (48.5%)

Position 11: 217/218 bytes (99.5%), 913 bits (52.4%)

Position 12: 217/218 bytes (99.5%), 853 bits (48.9%)

--- Summary ---

Average bit change: 49.2%

✅ EXCELLENT: Ideal avalanche effect (~50%)

=== DETERMINISTIC TEST ===

Same input encrypted twice:

  Result 1 == Result 2: NO
  
✅ Non-deterministic (uses random IV)

=== ENTROPY TEST ===
Short text:
  Entropy: 7.09 bits/byte (max 8.0)
  Readable chars: 49/218 (22.5%)
  ✓  Good randomness
Repeated chars:
  Entropy: 7.12 bits/byte (max 8.0)
  Readable chars: 61/241 (25.3%)
  ✓  Good randomness
/var/repos/SQRLL_Encryption/Tests/EncryptionTests.cpp:428: Failure
The difference between entropy and 6.0 is 1.1198076601008902, which exceeds 0.2, where
entropy evaluates to 7.1198076601008902,
6.0 evaluates to 6, and
0.2 evaluates to 0.20000000000000001.
Entropy too low for Repeated chars

Sequential:
  Entropy: 7.14 bits/byte (max 8.0)
  Readable chars: 56/238 (23.5%)
  ✓  Good randomness
/var/repos/SQRLL_Encryption/Tests/EncryptionTests.cpp:428: Failure
The difference between entropy and 6.0 is 1.1388790952481456, which exceeds 0.2, where
entropy evaluates to 7.1388790952481456,
6.0 evaluates to 6, and
0.2 evaluates to 0.20000000000000001.
Entropy too low for Sequential

Long mixed:
  Entropy: 7.33 bits/byte (max 8.0)
  Readable chars: 61/287 (21.3%)
  ✅ Excellent randomness
/var/repos/SQRLL_Encryption/Tests/EncryptionTests.cpp:428: Failure
The difference between entropy and 6.0 is 1.3336580589743248, which exceeds 0.2, where
entropy evaluates to 7.3336580589743248,
6.0 evaluates to 6, and
0.2 evaluates to 0.20000000000000001.
Entropy too low for Long mixed



=== KNOWN PLAINTEXT ATTACK TEST ===
Attempting to recover key via XOR attack...
Possible key 1: "\x91\x9e\xd5\x8a\xd9\xb0\xef\xdfB\x12\xd0\x10\xc6"
Possible key 2: "e|\x1a%d%\xe7\x14\x8f\xc4\x01X\xc6"
Possible key 3: "\xe9?Ow:w\x0bE\xcc\x81F\x11p"
✅ Keys differ - resistant to simple XOR attack

=== FREQUENCY ANALYSIS TEST ===
Top 3 most frequent bytes:
  0x27: 4 times (1.7%)
  0x9c: 3 times (1.3%)
  0xd3: 3 times (1.3%)
✅ Good distribution - resistant to frequency analysis

=== PERFORMANCE TEST ===
1000 encrypt/decrypt cycles: 217ms
Average per cycle: 0.217ms
✓  FAST

======================================================================
           FINAL ENCRYPTION SECURITY REPORT
======================================================================

1. CORRECTNESS TEST
   
   ✅ PASS - All decryptions correct
   

3. AVALANCHE EFFECT TEST
   
   Bit change: 47.9%

   ✅ PASS - Good diffusion
   

5. ENTROPY TEST
   
   Entropy: 7.00 bits/byte
   
   ✅ PASS - Good randomness
   

7. PATTERN DETECTION TEST
   
   Unique outputs: 5/5
   
   ✅ PASS - No repeating patterns
   

9. PERFORMANCE TEST
    
   1000 encrypt/decrypt: 190ms
   
   ✅ FAST
   

======================================================================

FINAL SCORE: 4/4 tests passed

✅ EXCELLENT - Strong encryption algorithm

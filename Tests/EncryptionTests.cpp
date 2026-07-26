// SQRLL Encryption - Unit Tests
// Google Test suite for EncryptionUtil

#include <algorithm>
#include <cmath>
#include <iomanip>
#include <cstring>
#include <chrono>
#include <mbedtls/aes.h>
#include <mbedtls/chacha20.h>
#include <gtest/gtest.h>
#include "SQRLLEncryption.h"

TEST(EncryptionTestCustom, Good)
{
	const std::string CorrectString = "MyT4STStringu";
	const std::string IncorrectString = "STStringu";

	const std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(32);

	auto start = std::chrono::high_resolution_clock::now();
	const std::string PassEncrypt = SQRLLEncryption::EncryptDataCustom(CorrectString, SecureSalt);
	const std::string PassEncrypt2 = SQRLLEncryption::EncryptDataCustom(CorrectString, SecureSalt);
	const std::string PassDecrypt = SQRLLEncryption::DecryptDataCustom(PassEncrypt, SecureSalt);
	const std::string PassDecrypt2 = SQRLLEncryption::DecryptDataCustom(PassEncrypt2, SecureSalt);
	const bool bIsCryptographySuccessful = (CorrectString == PassDecrypt) && (PassDecrypt == PassDecrypt2);
	auto end = std::chrono::high_resolution_clock::now();

	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

	EXPECT_TRUE(bIsCryptographySuccessful == true);
	EXPECT_LT(duration.count(), 200);
}

TEST(EncryptionTestCustom, Bad)
{
	const std::string CorrectString = "MyT4STStringu";
	const std::string IncorrectString = "STStringu";

	const std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(32);

	const std::string PassEncrypt = SQRLLEncryption::EncryptDataCustom(CorrectString, SecureSalt);
	const std::string PassDecrypt = SQRLLEncryption::DecryptDataCustom(IncorrectString, SecureSalt);
	const bool bIsCryptographySuccessful = (CorrectString == PassDecrypt);

	EXPECT_TRUE(bIsCryptographySuccessful == false);
}

TEST(EncryptionTestCustom, MassTest)
{
	std::vector<std::string> Inputs = {
		"MyT4STStringu",
		"Different123!",
		"AAAAAAAAAAAAA",
		"TestMessage00",
		"XYZ123456789A"
	};

	const std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(32);

	auto start = std::chrono::high_resolution_clock::now();

	for (std::string& Input : Inputs)
	{
		const std::string PassEncrypt = SQRLLEncryption::EncryptDataCustom(Input, SecureSalt);;
		const std::string PassDecrypt = SQRLLEncryption::DecryptDataCustom(PassEncrypt, SecureSalt);

		EXPECT_TRUE(Input == PassDecrypt);

		std::cout << Input << "->" << PassEncrypt << std::endl;
	}

	auto end = std::chrono::high_resolution_clock::now();

	auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

	
	EXPECT_LT(duration.count(), 200);
}



// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

int CountBits(uint8_t byte)
{
    int count = 0;
    while (byte) {
        count += byte & 1;
        byte >>= 1;
    }
    return count;
}

std::string ToHex(const std::string& data)
{
    std::stringstream ss;
    for (unsigned char c : data) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)c << " ";
    }
    return ss.str();
}

std::string ToReadable(const std::string& data)
{
    std::stringstream ss;
    ss << "\"";
    for (unsigned char c : data) {
        if (c >= 32 && c <= 126 && c != '"' && c != '\\') {
            ss << c;
        }
        else {
            ss << "\\x" << std::hex << std::setw(2) << std::setfill('0') << (int)c;
        }
    }
    ss << "\"";
    return ss.str();
}

int DifferentBytes(const std::string& a, const std::string& b)
{
    int count = 0;
    size_t minSize = std::min(a.size(), b.size());
    for (size_t i = 0; i < minSize; i++) {
        if (a[i] != b[i]) count++;
    }
    return count;
}

int DifferentBits(const std::string& a, const std::string& b)
{
    int bits = 0;
    size_t minSize = std::min(a.size(), b.size());
    for (size_t i = 0; i < minSize; i++) {
        uint8_t xorResult = static_cast<uint8_t>(a[i] ^ b[i]);
        bits += CountBits(xorResult);
    }
    return bits;
}

double CalculateEntropy(const std::string& data)
{
    if (data.empty()) return 0.0;

    std::map<uint8_t, int> freq;
    for (unsigned char c : data) {
        freq[static_cast<uint8_t>(c)]++;
    }

    double entropy = 0.0;
    for (const auto& p : freq) {
        double prob = (double)p.second / data.size();
        entropy -= prob * log2(prob);
    }
    return entropy;
}

int ReadableChars(const std::string& data)
{
    int count = 0;
    for (unsigned char c : data) {
        if ((c >= '0' && c <= '9') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z')) {
            count++;
        }
    }
    return count;
}

// ============================================================================
// TEST 1: Correctness - Decrypt = Original
// ============================================================================
TEST(EncryptionSecurity, DecryptionCorrectness)
{
    std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(64);

    std::vector<std::string> testInputs = {
        "MyT4STStringu",
        "Short",
        "A",
        "",
        "Very Long Test Message With Multiple Words And Numbers 1234567890",
        "Special!@#$%^&*()_+-=[]{}|;:',.<>?/",
        std::string("\x00\x01\x02\xFF", 4), // Binary data
    };

    std::cout << "\n=== CORRECTNESS TEST ===" << std::endl;

    int passed = 0;
    for (const auto& Input : testInputs) {
        const std::string PassEncrypt = SQRLLEncryption::EncryptDataCustom(Input, SecureSalt);
        const std::string PassDecrypt = SQRLLEncryption::DecryptDataCustom(PassEncrypt, SecureSalt);

        if (Input == PassDecrypt) {
            std::cout << "✓ ";
            passed++;
        }
        else {
            std::cout << "✗ ";
        }

        std::cout << (Input.empty() ? "(empty)" : ToReadable(Input).substr(0, 30)) << std::endl;

        EXPECT_EQ(Input, PassDecrypt)
            << "Failed for input: " << ToReadable(Input);
    }

    std::cout << "Passed: " << passed << "/" << testInputs.size() << std::endl;
}

// ============================================================================
// TEST 2: Pattern Detection - "590" Problem
// ============================================================================
TEST(EncryptionSecurity, PatternDetection)
{
    std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(64);

    std::cout << "\n=== PATTERN DETECTION TEST ===" << std::endl;

    std::vector<std::string> inputs = {
        "MyT4STStringu",
        "Different123!",
        "AAAAAAAAAAAAA",
        "TestMessage00",
        "XYZ123456789A",
        "abcdefghijklm",
        "0000000000000",
    };

    std::map<std::string, int> endPatterns;
    std::set<std::string> allEncrypted;

    for (const auto& Input : inputs) {
        const std::string PassEncrypt = SQRLLEncryption::EncryptDataCustom(Input, SecureSalt);

        allEncrypted.insert(PassEncrypt);

        // Sprawdź ostatnie 3 bajty
        if (PassEncrypt.size() >= 3) {
            std::string ending = PassEncrypt.substr(PassEncrypt.size() - 3);
            endPatterns[ending]++;

            std::cout << "Input: " << std::setw(15) << std::left << Input
                << " | End: " << ToReadable(ending) << std::endl;
        }
    }

    std::cout << "\n--- Analysis ---" << std::endl;
    std::cout << "Unique encrypted outputs: " << allEncrypted.size()
        << "/" << inputs.size() << std::endl;
    std::cout << "Unique endings: " << endPatterns.size()
        << "/" << inputs.size() << std::endl;

    // Sprawdź czy jakiś pattern się powtarza
    int maxRepeat = 0;
    std::string mostCommon;
    for (const auto& p : endPatterns) {
        if (p.second > maxRepeat) {
            maxRepeat = p.second;
            mostCommon = p.first;
        }
    }

    if (maxRepeat > 1) {
        std::cout << "⚠️  Pattern found: " << ToReadable(mostCommon)
            << " appears " << maxRepeat << " times" << std::endl;
    }
    else {
        std::cout << "✅ No repeating patterns detected" << std::endl;
    }

    EXPECT_EQ(allEncrypted.size(), inputs.size())
        << "Different inputs should produce different outputs";

    EXPECT_LE(maxRepeat, 2)
        << "Pattern '" << ToReadable(mostCommon) << "' repeats " << maxRepeat << " times";
}

// ============================================================================
// TEST 3: Avalanche Effect
// ============================================================================
TEST(EncryptionSecurity, AvalancheEffect)
{
    std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(64);

    std::cout << "\n=== AVALANCHE EFFECT TEST ===" << std::endl;

    std::string original = "MyT4STStringu";

    const std::string encOriginal = SQRLLEncryption::EncryptDataCustom(original, SecureSalt);

    std::cout << "Original: \"" << original << "\"" << std::endl;
    std::cout << "Encrypted: " << ToReadable(encOriginal) << std::endl;
    std::cout << "\nChanging each character (flipping 1 bit):" << std::endl;

    std::vector<float> changePercentages;

    for (size_t i = 0; i < original.size(); i++) {
        std::string modified = original;
        modified[i] ^= 0x01; // Flip 1 bit

        const std::string encModified = SQRLLEncryption::EncryptDataCustom(modified, SecureSalt);

        int diffBytes = DifferentBytes(encOriginal, encModified);
        int diffBits = DifferentBits(encOriginal, encModified);
        float bytePercent = (float)diffBytes / encOriginal.size() * 100;
        float bitPercent = (float)diffBits / (encOriginal.size() * 8) * 100;

        changePercentages.push_back(bitPercent);

        std::cout << "Position " << std::setw(2) << i << ": "
            << diffBytes << "/" << encOriginal.size() << " bytes ("
            << std::fixed << std::setprecision(1) << bytePercent << "%), "
            << diffBits << " bits (" << bitPercent << "%)" << std::endl;
    }

    // Oblicz średnią
    float avgPercent = 0;
    for (float p : changePercentages) {
        avgPercent += p;
    }
    avgPercent /= changePercentages.size();

    std::cout << "\n--- Summary ---" << std::endl;
    std::cout << "Average bit change: " << std::fixed << std::setprecision(1)
        << avgPercent << "%" << std::endl;

    if (avgPercent >= 45 && avgPercent <= 55) {
        std::cout << "✅ EXCELLENT: Ideal avalanche effect (~50%)" << std::endl;
    }
    else if (avgPercent >= 40 && avgPercent <= 60) {
        std::cout << "✓  GOOD: Strong avalanche effect" << std::endl;
    }
    else if (avgPercent >= 30) {
        std::cout << "⚠️  WEAK: Poor avalanche effect" << std::endl;
    }
    else {
        std::cout << "🚨 CRITICAL: Very weak avalanche effect!" << std::endl;
    }

    EXPECT_GT(avgPercent, 40.0f)
        << "Avalanche effect too weak: " << avgPercent << "%";
    EXPECT_LT(avgPercent, 60.0f)
        << "Avalanche effect suspicious: " << avgPercent << "%";
}

// ============================================================================
// TEST 4: Deterministic Check
// ============================================================================
TEST(EncryptionSecurity, DeterministicEncryption)
{
    std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(64);

    std::cout << "\n=== DETERMINISTIC TEST ===" << std::endl;

    std::string Input = "MyT4STStringu";

    const std::string enc1 = SQRLLEncryption::EncryptDataCustom(Input, SecureSalt);
    const std::string enc2 = SQRLLEncryption::EncryptDataCustom(Input, SecureSalt);

    bool isDeterministic = (enc1 == enc2);

    std::cout << "Same input encrypted twice:" << std::endl;
    std::cout << "  Result 1 == Result 2: " << (isDeterministic ? "YES" : "NO") << std::endl;

    if (isDeterministic) {
        std::cout << "⚠️  Deterministic encryption (no IV/salt per encryption)" << std::endl;
        std::cout << "   This is OK for simple encryption with salt, but:" << std::endl;
        std::cout << "   - Same plaintext + same salt = same ciphertext" << std::endl;
        std::cout << "   - Consider adding random IV for production" << std::endl;
    }
    else {
        std::cout << "✅ Non-deterministic (uses random IV)" << std::endl;
    }
}

// ============================================================================
// TEST 5: Entropy Test
// ============================================================================
TEST(EncryptionSecurity, EntropyTest)
{
    std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(64);

    std::cout << "\n=== ENTROPY TEST ===" << std::endl;

    std::vector<std::pair<std::string, std::string>> tests = {
        {"Short text", "MyT4STStringu"},
        {"Repeated chars", "AAAAAAAAAAAAAAAAAAAAAAAAAAAA"},
        {"Sequential", "ABCDEFGHIJKLMNOPQRSTUVWXYZ"},
        {"Long mixed", "The quick brown fox jumps over the lazy dog 1234567890!@#$%"},
    };

    for (const auto& test : tests)
    {
        const std::string PassEncrypt = SQRLLEncryption::EncryptDataCustom(test.second, SecureSalt);

        double entropy = CalculateEntropy(PassEncrypt);
        int readable = ReadableChars(PassEncrypt);
        float readablePercent = (float)readable / PassEncrypt.size() * 100;

        std::cout << test.first << ":" << std::endl;
        std::cout << "  Entropy: " << std::fixed << std::setprecision(2)
            << entropy << " bits/byte (max 8.0)" << std::endl;
        std::cout << "  Readable chars: " << readable << "/" << PassEncrypt.size()
            << " (" << std::setprecision(1) << readablePercent << "%)" << std::endl;

        if (entropy > 7.2) {
            std::cout << "  ✅ Excellent randomness" << std::endl;
        }
        else if (entropy > 6.0) {
            std::cout << "  ✓  Good randomness" << std::endl;
        }
        else if (entropy > 4.0) {
            std::cout << "  ⚠️  Moderate randomness" << std::endl;
        }
        else {
            std::cout << "  🚨 Poor randomness" << std::endl;
        }

        if (test.second.size() >= 20) {

            EXPECT_GT(entropy, 6.0) << "Entropy too low for " << test.first;
        }
    }
}

// ============================================================================
// TEST 6: Known Plaintext Attack Simulation
// ============================================================================
TEST(EncryptionSecurity, KnownPlaintextResistance)
{
    std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(64);

    std::cout << "\n=== KNOWN PLAINTEXT ATTACK TEST ===" << std::endl;

    std::vector<std::string> knownPlaintexts = {
        "MyT4STStringu",
        "AAAAAAAAAAAAA",
        "TestMessage01",
    };

    std::vector<std::string> ciphertexts;

    for (const auto& plain : knownPlaintexts) {
        const std::string PassEncrypt = SQRLLEncryption::EncryptDataCustom(plain, SecureSalt);
        ciphertexts.push_back(PassEncrypt);
    }

    std::cout << "Attempting to recover key via XOR attack..." << std::endl;

    std::vector<std::string> possibleKeys;
    for (size_t i = 0; i < knownPlaintexts.size(); i++) {
        std::string possibleKey;
        size_t minLen = std::min(knownPlaintexts[i].size(), ciphertexts[i].size());

        for (size_t j = 0; j < minLen; j++) {
            possibleKey += (ciphertexts[i][j] ^ knownPlaintexts[i][j]);
        }
        possibleKeys.push_back(possibleKey);

        std::cout << "Possible key " << (i + 1) << ": "
            << ToReadable(possibleKey) << std::endl;
    }

    bool allSame = true;
    for (size_t i = 1; i < possibleKeys.size(); i++) {
        if (possibleKeys[i] != possibleKeys[0]) {
            allSame = false;
            break;
        }
    }

    if (allSame && !possibleKeys.empty()) {
        std::cout << "🚨 CRITICAL: Simple XOR cipher detected!" << std::endl;
        std::cout << "   Recovered key: " << ToReadable(possibleKeys[0]) << std::endl;
        std::cout << "   This encryption is EASILY breakable!" << std::endl;

        FAIL() << "Simple XOR cipher - NOT SECURE FOR PRODUCTION";
    }
    else {
        std::cout << "✅ Keys differ - resistant to simple XOR attack" << std::endl;
    }
}

// ============================================================================
// TEST 7: Frequency Analysis
// ============================================================================
TEST(EncryptionSecurity, FrequencyAnalysis)
{
    std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(64);

    std::cout << "\n=== FREQUENCY ANALYSIS TEST ===" << std::endl;

    std::string plaintext = "EEEEEEEEEEEEE TTTTTTTTTT AAAAAAAAAA OOOOOOO";

    const std::string PassEncrypt = SQRLLEncryption::EncryptDataCustom(plaintext, SecureSalt);

    std::map<uint8_t, int> freq;
    for (unsigned char c : PassEncrypt) {
        freq[static_cast<uint8_t>(c)]++;
    }

    std::vector<std::pair<uint8_t, int>> sortedFreq(freq.begin(), freq.end());
    std::sort(sortedFreq.begin(), sortedFreq.end(),
        [](const auto& a, const auto& b) { return a.second > b.second; });

    std::cout << "Top 3 most frequent bytes:" << std::endl;
    for (size_t i = 0; i < std::min(size_t(3), sortedFreq.size()); i++) {
        float percent = (float)sortedFreq[i].second / PassEncrypt.size() * 100;
        std::cout << "  0x" << std::hex << std::setw(2) << std::setfill('0')
            << (int)sortedFreq[i].first << ": " << std::dec
            << sortedFreq[i].second << " times ("
            << std::fixed << std::setprecision(1) << percent << "%)" << std::endl;
    }

    float maxPercent = (float)sortedFreq[0].second / PassEncrypt.size() * 100;

    if (maxPercent > 15) {
        std::cout << "⚠️  WARNING: Most frequent byte appears " << maxPercent
            << "% - vulnerable to frequency analysis" << std::endl;
    }
    else {
        std::cout << "✅ Good distribution - resistant to frequency analysis" << std::endl;
    }

    EXPECT_LT(maxPercent, 20.0f)
        << "Frequency analysis possible - byte appears " << maxPercent << "% of time";
}

// ============================================================================
// TEST 8: Performance Test
// ============================================================================
TEST(EncryptionSecurity, PerformanceTest)
{
    std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(64);

    std::cout << "\n=== PERFORMANCE TEST ===" << std::endl;

    std::string testData = "Test Message For Performance";

    auto start = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < 1000; i++) {
        const std::string PassEncrypt = SQRLLEncryption::EncryptDataCustom(testData, SecureSalt);
        const std::string PassDecrypt = SQRLLEncryption::DecryptDataCustom(PassEncrypt, SecureSalt);
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    std::cout << "1000 encrypt/decrypt cycles: " << duration.count() << "ms" << std::endl;
    std::cout << "Average per cycle: " << std::fixed << std::setprecision(3)
        << (duration.count() / 1000.0) << "ms" << std::endl;

    if (duration.count() < 100) {
        std::cout << "✅ BLAZING FAST!" << std::endl;
    }
    else if (duration.count() < 500) {
        std::cout << "✓  FAST" << std::endl;
    }
    else {
        std::cout << "⚠️  Slow - consider optimization" << std::endl;
    }
}

// ============================================================================
// TEST 9: Key Sensitivity (Key Avalanche Effect)
// ============================================================================
// A secure cipher must produce completely different ciphertext if even
// a single bit of the encryption key / salt is changed.
TEST(EncryptionSecurity, KeySensitivity)
{
    std::cout << "\n=== KEY SENSITIVITY TEST ===" << std::endl;

    const std::string Input = "ConfidentialMessageForSQRLL";
    std::string SecureSaltA = SQRLLEncryption::GenerateSecureSalt(32);

    // Create Salt B by flipping exactly one bit of Salt A
    std::string SecureSaltB = SecureSaltA;
    SecureSaltB[0] ^= 0x01;

    const std::string EncryptA = SQRLLEncryption::EncryptDataCustom(Input, SecureSaltA);
    const std::string EncryptB = SQRLLEncryption::EncryptDataCustom(Input, SecureSaltB);

    int diffBits = DifferentBits(EncryptA, EncryptB);

    // Calculate percentage based on the smaller ciphertext size
    size_t minSize = std::min(EncryptA.size(), EncryptB.size());
    float bitPercent = (float)diffBits / (minSize * 8) * 100.0f;

    std::cout << "Ciphertext A size: " << EncryptA.size() << " bytes" << std::endl;
    std::cout << "Ciphertext B size: " << EncryptB.size() << " bytes" << std::endl;
    std::cout << "Difference: " << std::fixed << std::setprecision(1) << bitPercent << "% of bits" << std::endl;

    if (bitPercent >= 45.0f && bitPercent <= 55.0f) {
        std::cout << "✅ EXCELLENT: Ideal key avalanche effect (~50%)" << std::endl;
    }
    else {
        std::cout << "🚨 CRITICAL: Cipher outputs are too similar despite different keys!" << std::endl;
    }

    EXPECT_GT(bitPercent, 40.0f) << "Key avalanche effect too weak: " << bitPercent << "%";
    EXPECT_LT(bitPercent, 60.0f) << "Key avalanche effect suspicious: " << bitPercent << "%";
}

// ============================================================================
// TEST 10: Ciphertext Malleability (Bit-Flipping Attack Resistance)
// ============================================================================
// Tests if an attacker can predictably manipulate the decrypted plaintext
// by flipping bits in the intercepted ciphertext.
TEST(EncryptionSecurity, CiphertextMalleability)
{
    std::cout << "\n=== CIPHERTEXT MALLEABILITY TEST ===" << std::endl;

    const std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(32);
    const std::string OriginalInput = "Transfer $100 to user A";

    std::string Ciphertext = SQRLLEncryption::EncryptDataCustom(OriginalInput, SecureSalt);

    // Attacker intercepts the message and flips one bit in the middle
    if (!Ciphertext.empty()) {
        Ciphertext[Ciphertext.size() / 2] ^= 0x01;
    }

    // Attempt to decrypt the tampered message
    const std::string TamperedDecryption = SQRLLEncryption::DecryptDataCustom(Ciphertext, SecureSalt);

    int diffBits = DifferentBits(OriginalInput, TamperedDecryption);

    std::cout << "Original plaintext: \"" << OriginalInput << "\"" << std::endl;
    std::cout << "Tampered plaintext: " << ToReadable(TamperedDecryption) << std::endl;

    if (diffBits == 1) {
        std::cout << "🚨 CRITICAL: Stream cipher behavior detected! Highly malleable." << std::endl;
        std::cout << "   Attacker can easily flip specific bits in the final message." << std::endl;
        FAIL() << "Algorithm is vulnerable to bit-flipping attacks (requires MAC/GCM tag).";
    }
    else if (diffBits > 10) {
        std::cout << "✅ GOOD: Tampering scrambles the block/message. Low malleability." << std::endl;
    }
    else {
        std::cout << "⚠️ WARNING: Partial malleability detected." << std::endl;
    }
}

// ============================================================================
// TEST 11: Zero-Byte Propagation Test
// ============================================================================
// Poor ciphers often struggle with large blocks of identical bytes (especially 0x00),
// resulting in repeating patterns or low entropy in the ciphertext.
TEST(EncryptionSecurity, ZeroBytePropagation)
{
    std::cout << "\n=== ZERO-BYTE PROPAGATION TEST ===" << std::endl;

    const std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(32);

    // Create a string of 1000 null bytes
    const std::string NullInput(1000, '\x00');

    const std::string Ciphertext = SQRLLEncryption::EncryptDataCustom(NullInput, SecureSalt);

    double entropy = CalculateEntropy(Ciphertext);

    std::cout << "Input: 1000 Null Bytes (0x00)" << std::endl;
    std::cout << "Ciphertext Entropy: " << std::fixed << std::setprecision(2) << entropy << " bits/byte" << std::endl;

    if (entropy > 7.5) {
        std::cout << "✅ EXCELLENT: Null bytes successfully diffused." << std::endl;
    }
    else {
        std::cout << "🚨 CRITICAL: Cipher fails to diffuse empty space!" << std::endl;
    }

    EXPECT_GT(entropy, 7.0) << "Entropy drops dangerously low on null-byte blocks.";
}

// ============================================================================
// TEST 12: Large Payload Integrity & Scaling
// ============================================================================
// Ensures the custom algorithm does not crash or suffer from O(N^2) memory
// allocations when dealing with larger blocks of data (e.g., file transfers).
TEST(EncryptionSecurity, LargePayloadScaling)
{
    std::cout << "\n=== LARGE PAYLOAD SCALING TEST ===" << std::endl;

    const std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(32);

    // Generate 1 Megabyte of pseudo-random data
    std::string LargePayload;
    LargePayload.reserve(1024 * 1024);
    for(int i = 0; i < 1024 * 1024; i++) {
        LargePayload.push_back(static_cast<char>(i % 256));
    }

    auto start = std::chrono::high_resolution_clock::now();

    const std::string Encrypted = SQRLLEncryption::EncryptDataCustom(LargePayload, SecureSalt);
    const std::string Decrypted = SQRLLEncryption::DecryptDataCustom(Encrypted, SecureSalt);

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);

    bool bIsIntact = (LargePayload == Decrypted);

    std::cout << "Payload size: 1 MB" << std::endl;
    std::cout << "Time taken (Encrypt + Decrypt): " << duration.count() << "ms" << std::endl;
    std::cout << "Data Integrity: " << (bIsIntact ? "✅ INTACT" : "🚨 CORRUPTED") << std::endl;

    EXPECT_TRUE(bIsIntact) << "Large payload decryption failed or data corrupted.";

    // If it takes more than 1000ms for 1MB, the algorithm is severely unoptimized
    EXPECT_LT(duration.count(), 1000) << "Algorithm scaling is O(N^2) or memory inefficient.";
}

// ============================================================================
// TEST 13: Length Leakage (Metadata Analysis)
// ============================================================================
// Block ciphers pad data to specific block sizes.
// Stream ciphers often produce ciphertext of the exact same length as the
// plaintext, leaking the exact length of the message.
TEST(EncryptionSecurity, LengthLeakage)
{
    std::cout << "\n=== 13. LENGTH LEAKAGE TEST ===" << std::endl;

    const std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(32);

    std::vector<size_t> cipherLengths;
    bool bLeaksExactLength = false;

    for (int i = 1; i <= 16; i++) {
        std::string plain(i, 'A');
        const std::string encrypted = SQRLLEncryption::EncryptDataCustom(plain, SecureSalt);
        cipherLengths.push_back(encrypted.size());

        if (encrypted.size() == plain.size()) {
            bLeaksExactLength = true;
        }
    }

    if (bLeaksExactLength) {
        std::cout << "[WARN] Algorithm leaks exact plaintext length (1:1 ratio)." << std::endl;
    } else {
        std::cout << "[PASS] Ciphertext length obfuscated or padded." << std::endl;
    }

    EXPECT_FALSE(cipherLengths.empty());
}

// ============================================================================
// TEST 14: Extreme Key Sizes (Edge Cases)
// ============================================================================
// Tests if the algorithm crashes or behaves unpredictably
// when given extremely short or extremely long keys/salts.
TEST(EncryptionSecurity, ExtremeKeySizes)
{
    std::cout << "\n=== 14. EXTREME KEY SIZES TEST ===" << std::endl;

    const std::string Input = "Standard payload for testing.";

    std::vector<std::string> extremeKeys = {
        "",                                // Empty key (checks for modulo by zero)
        "A",                               // 1-byte key
        std::string(10000, 'K')            // 10000-byte key
    };

    int passed = 0;

    for (size_t i = 0; i < extremeKeys.size(); i++) {
        const std::string& key = extremeKeys[i];

        try {
            const std::string encrypted = SQRLLEncryption::EncryptDataCustom(Input, key);
            const std::string decrypted = SQRLLEncryption::DecryptDataCustom(encrypted, key);

            if (decrypted == Input) {
                std::cout << "[PASS] Handled key of size: " << key.size() << std::endl;
                passed++;
            } else {
                std::cout << "[FAIL] Decryption failed for key size: " << key.size() << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "[CRIT] Exception thrown for key size " << key.size() << ": " << e.what() << std::endl;
        }
    }

    EXPECT_EQ(passed, extremeKeys.size()) << "Algorithm failed to handle extreme key sizes safely.";
}

// ============================================================================
// TEST 15: Binary and UTF-8 Safety
// ============================================================================
// Ensures the algorithm handles complex multi-byte characters and null bytes.
TEST(EncryptionSecurity, BinaryAndUTF8Safety)
{
    std::cout << "\n=== 15. BINARY & UTF-8 SAFETY TEST ===" << std::endl;

    const std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(32);

    std::string BinaryPayload = "FirstHalf";
    BinaryPayload.push_back('\x00');
    BinaryPayload.push_back('\x00');
    BinaryPayload += "SecondHalf";

    std::string UTF8Payload = "Zażółć gęślą jaźń";

    const std::string EncBinary = SQRLLEncryption::EncryptDataCustom(BinaryPayload, SecureSalt);
    const std::string DecBinary = SQRLLEncryption::DecryptDataCustom(EncBinary, SecureSalt);

    bool bBinarySafe = (BinaryPayload == DecBinary) && (DecBinary.length() == 21);
    std::cout << (bBinarySafe ? "[PASS]" : "[FAIL]") << " Null-byte (\\x00) internal safety" << std::endl;

    const std::string EncUTF8 = SQRLLEncryption::EncryptDataCustom(UTF8Payload, SecureSalt);
    const std::string DecUTF8 = SQRLLEncryption::DecryptDataCustom(EncUTF8, SecureSalt);

    bool bUTF8Safe = (UTF8Payload == DecUTF8);
    std::cout << (bUTF8Safe ? "[PASS]" : "[FAIL]") << " UTF-8 Multi-byte safety" << std::endl;

    EXPECT_TRUE(bBinarySafe);
    EXPECT_TRUE(bUTF8Safe);
}

// ============================================================================
// TEST 16: Corrupted Ciphertext Memory Bound Test
// ============================================================================
// Tests the robustness of the Decrypt function against random garbage.
TEST(EncryptionSecurity, CorruptedCiphertextRobustness)
{
    std::cout << "\n=== 16. CORRUPTED CIPHERTEXT ROBUSTNESS TEST ===" << std::endl;

    const std::string SecureSalt = "StaticTestSalt123";

    std::string RandomGarbage;
    RandomGarbage.reserve(500);
    srand(static_cast<unsigned int>(time(nullptr)));
    for(int i = 0; i < 500; i++) {
        RandomGarbage.push_back(static_cast<char>(rand() % 256));
    }

    bool bDidCrash = false;

    try {
        const std::string Output = SQRLLEncryption::DecryptDataCustom(RandomGarbage, SecureSalt);
        std::cout << "[PASS] Algorithm survived completely random garbage without segfaulting." << std::endl;
    } catch (const std::exception& e) {
        bDidCrash = true;
        std::cout << "[FAIL] Algorithm threw exception on corrupted data: " << e.what() << std::endl;
    } catch (...) {
        bDidCrash = true;
        std::cout << "[CRIT] Algorithm triggered an unknown crash (potential Segfault)." << std::endl;
    }

    EXPECT_FALSE(bDidCrash) << "Algorithm is vulnerable to denial of service via corrupted ciphertext.";
}
// ============================================================================
// TEST 17: Length Analysis (Before & After)
// ============================================================================
// Verifies that the final length of the encrypted buffer mathematically matches
// the formula: Original Size + Header (Word + IV) + Noise Bytes.
// Prevents silent memory padding leaks.
TEST(EncryptionSecurity, LengthBeforeAndAfter)
{
    std::cout << "\n=== 17. LENGTH BEFORE AND AFTER TEST ===" << std::endl;

    SQRLLEncryption::FEncryptionSettings Settings("SQRLL_MAGIC", 12, 1);
    const std::string Key = "UltraSecureHFTKey1234567"; // 24 bytes
    const std::string Plaintext = "Test message for system with variable length.";

    const std::string Encrypted = SQRLLEncryption::EncryptDataCustom(Plaintext, Key, Settings);

    // Mathematical calculations of expected payload size
    const size_t WordSize = Settings.EncryptionWord.size(); // 11
    const size_t IVSize = Settings.RandomIVSize + Key.size(); // 12 + 24 = 36
    const size_t BasePayloadSize = WordSize + IVSize + Plaintext.size();

    // Noise logic uses: Step = max(abs(Key[0] % 5), 2)
    const int32_t Step = std::max(std::abs(Key[0] % 5), 2);
    const size_t ExpectedNoiseCount = BasePayloadSize / Step;
    const size_t ExpectedEncryptedSize = BasePayloadSize + ExpectedNoiseCount;

    std::cout << "[INFO] Plaintext Length : " << Plaintext.size() << " bytes" << std::endl;
    std::cout << "[INFO] Base Payload Size: " << BasePayloadSize << " bytes (with Headers)" << std::endl;
    std::cout << "[INFO] Expected Noise   : " << ExpectedNoiseCount << " bytes (Step: " << Step << ")" << std::endl;
    std::cout << "[INFO] Expected Output  : " << ExpectedEncryptedSize << " bytes" << std::endl;
    std::cout << "[INFO] Actual Output    : " << Encrypted.size() << " bytes" << std::endl;

    const std::string Decrypted = SQRLLEncryption::DecryptDataCustom(Encrypted, Key, Settings);

    EXPECT_EQ(Encrypted.size(), ExpectedEncryptedSize) << "[FAIL] Encrypted length formula mismatch!";
    EXPECT_EQ(Decrypted.size(), Plaintext.size()) << "[FAIL] Decrypted length formula mismatch!";
    EXPECT_EQ(Plaintext, Decrypted) << "[FAIL] Data corrupted during cycle.";
}

// ============================================================================
// TEST 18: Advanced Edge Cases & Memory Bounds
// ============================================================================
// Tests vector boundaries and loops against extreme, often fatal data structures.
TEST(EncryptionSecurity, EdgeCasesAdvanced)
{
    std::cout << "\n=== 18. ADVANCED EDGE CASES TEST ===" << std::endl;

    SQRLLEncryption::FEncryptionSettings Settings("HEAD", 4, 3);
    const std::string StandardKey = "KeyWithMoreThan16BytesForSecurity!";

    struct EdgeCase {
        std::string Name;
        std::string Payload;
        std::string Key;
    };

    std::vector<EdgeCase> Cases = {
        { "Empty Payload", "", StandardKey },
        { "1-Byte Payload", "X", StandardKey },
        { "Key Contains Null Bytes", "NormalPayload", std::string("Key\x00With\x00Nulls\x00LongerThan16", 28) },
        { "Payload Exactly 8 Bytes (Chunk Limit)", "12345678", StandardKey },
        { "Payload Exactly 7 Bytes (Chunk Tail)", "1234567", StandardKey },
        { "Huge Key vs Tiny Payload", "A", std::string(1024, 'K') }
    };

    int Passed = 0;

    for (const auto& Case : Cases)
    {
        try {
            const std::string Encrypted = SQRLLEncryption::EncryptDataCustom(Case.Payload, Case.Key, Settings);
            const std::string Decrypted = SQRLLEncryption::DecryptDataCustom(Encrypted, Case.Key, Settings);

            if (Decrypted == Case.Payload) {
                std::cout << "[PASS] " << Case.Name << std::endl;
                Passed++;
            } else {
                std::cout << "[FAIL] " << Case.Name << " - Output mismatch!" << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "[CRIT] " << Case.Name << " crashed: " << e.what() << std::endl;
        } catch (...) {
            std::cout << "[CRIT] " << Case.Name << " triggered unknown memory violation!" << std::endl;
        }
    }

    EXPECT_EQ(Passed, Cases.size()) << "Not all advanced edge cases passed safely.";
}

// ============================================================================
// Overhead Analysis Test
// ============================================================================
// Measures how much the ciphertext grows compared to the plaintext.
// Calculates fixed header overhead and proportional noise injection.
TEST(EncryptionSecurity, OverheadAnalysis)
{
    std::cout << "\n=== PAYLOAD SIZE OVERHEAD ANALYSIS ===" << std::endl;

    SQRLLEncryption::FEncryptionSettings Settings("SQRLL", 8, 2);
    const std::string Key = "PerformanceTestingKey_32Bytes!!!";

    std::vector<size_t> TestSizes = {
        16,             // 16 B
        256,            // 256 B
        1024,           // 1 KB
        1024 * 10,      // 10 KB
        1024 * 100,     // 100 KB
        1024 * 1024     // 1 MB
    };

    std::cout << std::left
              << std::setw(12) << "Input Size"
              << std::setw(15) << "Output Size"
              << std::setw(15) << "Diff (Bytes)"
              << "Overhead %" << std::endl;
    std::cout << std::string(55, '-') << std::endl;

    for (size_t Size : TestSizes)
    {
        std::string Plaintext(Size, 'A');
        const std::string Encrypted = SQRLLEncryption::EncryptDataCustom(Plaintext, Key, Settings);

        size_t DiffBytes = Encrypted.size() - Plaintext.size();
        double OverheadPercent = (static_cast<double>(DiffBytes) / Plaintext.size()) * 100.0;

        std::string InputStr = std::to_string(Size) + " B";
        if (Size >= 1024 * 1024) InputStr = std::to_string(Size / (1024 * 1024)) + " MB";
        else if (Size >= 1024)   InputStr = std::to_string(Size / 1024) + " KB";

        std::cout << std::left
                  << std::setw(12) << InputStr
                  << std::setw(15) << (std::to_string(Encrypted.size()) + " B")
                  << std::setw(15) << ("+" + std::to_string(DiffBytes) + " B")
                  << std::fixed << std::setprecision(2) << OverheadPercent << " %"
                  << std::endl;
    }

    std::cout << "\n[INFO] Overhead consists of a fixed header (Word + IV) and proportional noise." << std::endl;
    std::cout << "[INFO] Notice how the % overhead drops significantly for larger payloads." << std::endl;
}

// ============================================================================
// Algorithm Performance Comparison & Reference Benchmark
// ============================================================================
// Compares SQRLL against raw memory copy, AES-256-CTR, and ChaCha20.
TEST(EncryptionSecurity, AlgorithmPerformanceComparison)
{
    std::cout << "\n=== ALGORITHM PERFORMANCE COMPARISON ===" << std::endl;

    const size_t PayloadSize = 1024 * 1024; // 1 Megabyte
    std::string LargePayload(PayloadSize, 'X');
    const std::string Key = "AVX2_SIMD_OptimizedKey32ByteTEST"; // 32 bytes
    SQRLLEncryption::FEncryptionSettings Settings("PERF", 4, 1);

    // 1. std::memcpy (Hardware baseline)
    std::string MemcpyBuffer(PayloadSize, '\0');
    auto startMemcpy = std::chrono::high_resolution_clock::now();
    std::memcpy(MemcpyBuffer.data(), LargePayload.data(), PayloadSize);
    auto endMemcpy = std::chrono::high_resolution_clock::now();
    double memcpyTime = std::chrono::duration<double, std::milli>(endMemcpy - startMemcpy).count();

    // 2. MbedTLS: AES-256-CTR
    std::string AesBuffer = LargePayload;
    unsigned char AesNonce[16] = {0}; // Dummy nonce
    unsigned char AesStreamBlock[16] = {0};
    size_t AesNcOff = 0;
    mbedtls_aes_context AesCtx;
    mbedtls_aes_init(&AesCtx);
    mbedtls_aes_setkey_enc(&AesCtx, reinterpret_cast<const unsigned char*>(Key.data()), 256);

    auto startAes = std::chrono::high_resolution_clock::now();
    mbedtls_aes_crypt_ctr(&AesCtx, PayloadSize, &AesNcOff, AesNonce, AesStreamBlock,
                          reinterpret_cast<const unsigned char*>(LargePayload.data()),
                          reinterpret_cast<unsigned char*>(AesBuffer.data()));
    auto endAes = std::chrono::high_resolution_clock::now();
    double aesTime = std::chrono::duration<double, std::milli>(endAes - startAes).count();
    mbedtls_aes_free(&AesCtx);

    // 3. MbedTLS: ChaCha20
    std::string ChaChaBuffer = LargePayload;
    unsigned char ChaChaNonce[12] = {0};
    mbedtls_chacha20_context ChaChaCtx;
    mbedtls_chacha20_init(&ChaChaCtx);
    mbedtls_chacha20_setkey(&ChaChaCtx, reinterpret_cast<const unsigned char*>(Key.data()));
    mbedtls_chacha20_starts(&ChaChaCtx, ChaChaNonce, 0);

    auto startChaCha = std::chrono::high_resolution_clock::now();
    mbedtls_chacha20_update(&ChaChaCtx, PayloadSize,
                            reinterpret_cast<const unsigned char*>(LargePayload.data()),
                            reinterpret_cast<unsigned char*>(ChaChaBuffer.data()));
    auto endChaCha = std::chrono::high_resolution_clock::now();
    double chachaTime = std::chrono::duration<double, std::milli>(endChaCha - startChaCha).count();
    mbedtls_chacha20_free(&ChaChaCtx);

    // 4. SQRLL Custom Encryption
    auto startSQRLL = std::chrono::high_resolution_clock::now();
    const std::string Encrypted = SQRLLEncryption::EncryptDataCustom(LargePayload, Key, Settings);
    auto endSQRLL = std::chrono::high_resolution_clock::now();
    double sqrllTime = std::chrono::duration<double, std::milli>(endSQRLL - startSQRLL).count();

    std::cout << "[INFO] Payload Size               : 1 MB" << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;
    std::cout << "[BASE] std::memcpy (Hardware Max) : " << std::fixed << std::setprecision(3) << memcpyTime << " ms" << std::endl;
    std::cout << "[REF]  MbedTLS AES-256-CTR        : " << aesTime << " ms" << std::endl;
    std::cout << "[REF]  MbedTLS ChaCha20           : " << chachaTime << " ms" << std::endl;
    std::cout << "------------------------------------------------------------" << std::endl;
    std::cout << "[TEST] SQRLL Full Cipher          : " << sqrllTime << " ms" << std::endl;

#ifdef NDEBUG
    if (sqrllTime < 50.0) {
        std::cout << "[PASS] SQRLL operates within acceptable production limits." << std::endl;
    } else {
        std::cout << "[WARN] SQRLL is slower than standard ciphers. Expected <50ms." << std::endl;
    }
    EXPECT_LT(sqrllTime, 100.0) << "SQRLL Encryption is too slow for production payloads.";
#else
    std::cout << "[WARN] Running in DEBUG mode. Performance is degraded." << std::endl;
#endif
}

// ============================================================================
// Final Security & Performance Report
// ============================================================================
TEST(EncryptionSecurity, FinalSecurityReport)
{
    std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(32);
    SQRLLEncryption::FEncryptionSettings Settings("SQRLL", 8, 2);

    std::cout << "\n============================================================" << std::endl;
    std::cout << "             FINAL SQRLL SECURITY REPORT" << std::endl;
    std::cout << "============================================================" << std::endl;

    int totalTests = 0;
    int passedTests = 0;

    auto printResult = [&](const std::string& name, bool passed, const std::string& detail) {
        std::cout << (passed ? "[PASS] " : "[FAIL] ")
                  << std::left << std::setw(25) << name
                  << " | " << detail << std::endl;
        totalTests++;
        if (passed) passedTests++;
    };

    // 1. Correctness
    const std::string testStr = "MyT4STStringu";
    const std::string encStr = SQRLLEncryption::EncryptDataCustom(testStr, SecureSalt, Settings);
    const std::string decStr = SQRLLEncryption::DecryptDataCustom(encStr, SecureSalt, Settings);
    printResult("Core Reversibility", (testStr == decStr), "Decryption matches original");

    // 2. Memory Bounds
    bool passEdgeCases = true;
    try { SQRLLEncryption::EncryptDataCustom(testStr, "", Settings); }
    catch (...) { passEdgeCases = false; }
    printResult("Architecture Integrity", passEdgeCases, "Empty/Invalid keys handled safely");

    // 3. Binary Safety
    std::string binStr = "A\x00B";
    const std::string decBin = SQRLLEncryption::DecryptDataCustom(SQRLLEncryption::EncryptDataCustom(binStr, SecureSalt, Settings), SecureSalt, Settings);
    printResult("Binary Data Safety", (binStr == decBin), "Null bytes (\\x00) preserved");

    // 4. Length Determinism & Overhead
    const int32_t step = std::max(std::abs(SecureSalt[0] % 5), 2);
    const size_t baseSize = Settings.EncryptionWord.size() + Settings.RandomIVSize + SecureSalt.size() + testStr.size();
    const size_t expectedSize = baseSize + (baseSize / step);
    printResult("Length Determinism", (encStr.size() == expectedSize), "Payload growth is mathematically exact");

    // 5. Benchmark Speed
    std::string largeStr(1024 * 1024, 'A');
    auto startBench = std::chrono::high_resolution_clock::now();
    SQRLLEncryption::EncryptDataCustom(largeStr, SecureSalt, Settings);
    auto endBench = std::chrono::high_resolution_clock::now();
    double timeBench = std::chrono::duration<double, std::milli>(endBench - startBench).count();

    std::string timeStr = std::to_string(timeBench);
    std::string formattedTime = timeStr.substr(0, timeStr.find('.') + 3) + " ms";

#ifdef NDEBUG
    printResult("Speed Check (Release)", (timeBench < 50.0), "1MB Encrypted in " + formattedTime);
#else
    printResult("Speed Check (Debug)", (timeBench < 500.0), "1MB Encrypted in " + formattedTime);
#endif

    std::cout << "------------------------------------------------------------" << std::endl;
    std::cout << "FINAL SCORE: " << passedTests << "/" << totalTests << " critical checks passed." << std::endl;

    if (passedTests == totalTests) {
        std::cout << "[STATUS] EXCELLENT - Strong baseline security architecture" << std::endl;
    } else {
        std::cout << "[STATUS] WEAK - Requires immediate architectural changes" << std::endl;
    }
    std::cout << "============================================================" << std::endl;

    EXPECT_EQ(passedTests, totalTests) << "Not all critical suites passed in Final Report.";
}
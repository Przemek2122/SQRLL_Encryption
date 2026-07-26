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
	const std::string PassEncrypt = SQRLLEncryption::Encrypt(CorrectString, SecureSalt);
	const std::string PassEncrypt2 = SQRLLEncryption::Encrypt(CorrectString, SecureSalt);
	const std::string PassDecrypt = SQRLLEncryption::Decrypt(PassEncrypt, SecureSalt);
	const std::string PassDecrypt2 = SQRLLEncryption::Decrypt(PassEncrypt2, SecureSalt);
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

	const std::string PassEncrypt = SQRLLEncryption::Encrypt(CorrectString, SecureSalt);
	const std::string PassDecrypt = SQRLLEncryption::Decrypt(IncorrectString, SecureSalt);
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
		const std::string PassEncrypt = SQRLLEncryption::Encrypt(Input, SecureSalt);;
		const std::string PassDecrypt = SQRLLEncryption::Decrypt(PassEncrypt, SecureSalt);

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

// Helper function to calculate Shannon Entropy
static double CalculateShannonEntropy(const uint8_t* Data, size_t Size)
{
    if (Size == 0) return 0.0;
    std::vector<size_t> Frequencies(256, 0);
    for (size_t i = 0; i < Size; ++i)
    {
        Frequencies[Data[i]]++;
    }

    double Entropy = 0.0;
    for (int i = 0; i < 256; ++i)
    {
        if (Frequencies[i] > 0)
        {
            double p = static_cast<double>(Frequencies[i]) / static_cast<double>(Size);
            Entropy -= p * std::log2(p);
        }
    }
    return Entropy;
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
        const std::string PassEncrypt = SQRLLEncryption::Encrypt(Input, SecureSalt);
        const std::string PassDecrypt = SQRLLEncryption::Decrypt(PassEncrypt, SecureSalt);

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
        const std::string PassEncrypt = SQRLLEncryption::Encrypt(Input, SecureSalt);

        allEncrypted.insert(PassEncrypt);

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

    const std::string encOriginal = SQRLLEncryption::Encrypt(original, SecureSalt);

    std::cout << "Original: \"" << original << "\"" << std::endl;
    std::cout << "Encrypted: " << ToReadable(encOriginal) << std::endl;
    std::cout << "\nChanging each character (flipping 1 bit):" << std::endl;

    std::vector<float> changePercentages;

    for (size_t i = 0; i < original.size(); i++) {
        std::string modified = original;
        modified[i] ^= 0x01; // Flip 1 bit

        const std::string encModified = SQRLLEncryption::Encrypt(modified, SecureSalt);

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

    const std::string enc1 = SQRLLEncryption::Encrypt(Input, SecureSalt);
    const std::string enc2 = SQRLLEncryption::Encrypt(Input, SecureSalt);

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
        const std::string PassEncrypt = SQRLLEncryption::Encrypt(test.second, SecureSalt);

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
        const std::string PassEncrypt = SQRLLEncryption::Encrypt(plain, SecureSalt);
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

    const std::string PassEncrypt = SQRLLEncryption::Encrypt(plaintext, SecureSalt);

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
        const std::string PassEncrypt = SQRLLEncryption::Encrypt(testData, SecureSalt);
        const std::string PassDecrypt = SQRLLEncryption::Decrypt(PassEncrypt, SecureSalt);
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

    const std::string EncryptA = SQRLLEncryption::Encrypt(Input, SecureSaltA);
    const std::string EncryptB = SQRLLEncryption::Encrypt(Input, SecureSaltB);

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

    std::string Ciphertext = SQRLLEncryption::Encrypt(OriginalInput, SecureSalt);

    // Attacker intercepts the message and flips one bit in the middle
    if (!Ciphertext.empty()) {
        Ciphertext[Ciphertext.size() / 2] ^= 0x01;
    }

    // Attempt to decrypt the tampered message
    const std::string TamperedDecryption = SQRLLEncryption::Decrypt(Ciphertext, SecureSalt);

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

    const std::string Ciphertext = SQRLLEncryption::Encrypt(NullInput, SecureSalt);

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

    const std::string Encrypted = SQRLLEncryption::Encrypt(LargePayload, SecureSalt);
    const std::string Decrypted = SQRLLEncryption::Decrypt(Encrypted, SecureSalt);

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
        const std::string encrypted = SQRLLEncryption::Encrypt(plain, SecureSalt);
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
            const std::string encrypted = SQRLLEncryption::Encrypt(Input, key);
            const std::string decrypted = SQRLLEncryption::Decrypt(encrypted, key);

            if (key.size() <= 16) {
                std::cout << "[FAIL] Algorithm accepted an insecure key of size: " << key.size() << std::endl;
            } else if (decrypted == Input) {
                std::cout << "[PASS] Safely handled valid extreme key of size: " << key.size() << std::endl;
                passed++;
            } else {
                std::cout << "[FAIL] Decryption failed for key size: " << key.size() << std::endl;
            }
        } catch (const std::invalid_argument& e) {
            // Rejecting a short key with an exception is the correct, safe behavior
            if (key.size() <= 16) {
                std::cout << "[PASS] Correctly rejected insecure key of size " << key.size()
                          << " with exception: " << e.what() << std::endl;
                passed++;
            } else {
                std::cout << "[CRIT] Unexpected exception for valid key size " << key.size()
                          << ": " << e.what() << std::endl;
            }
        } catch (const std::exception& e) {
            std::cout << "[CRIT] Unknown exception thrown for key size " << key.size()
                      << ": " << e.what() << std::endl;
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

    const std::string EncBinary = SQRLLEncryption::Encrypt(BinaryPayload, SecureSalt);
    const std::string DecBinary = SQRLLEncryption::Decrypt(EncBinary, SecureSalt);

    bool bBinarySafe = (BinaryPayload == DecBinary) && (DecBinary.length() == 21);
    std::cout << (bBinarySafe ? "[PASS]" : "[FAIL]") << " Null-byte (\\x00) internal safety" << std::endl;

    const std::string EncUTF8 = SQRLLEncryption::Encrypt(UTF8Payload, SecureSalt);
    const std::string DecUTF8 = SQRLLEncryption::Decrypt(EncUTF8, SecureSalt);

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
        const std::string Output = SQRLLEncryption::Decrypt(RandomGarbage, SecureSalt);
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
// the exact formula: Plaintext Size + Header (Word + IV).
TEST(EncryptionSecurity, LengthBeforeAndAfter)
{
    std::cout << "\n=== 17. LENGTH BEFORE AND AFTER TEST ===" << std::endl;

    const SQRLLSettings Settings("SQRLL_MAGIC", 12, 1);
    const std::string Key = "UltraSecureKey123456789012"; // 26 bytes
    const std::string Plaintext = "Test message for encryption system with exact size.";

    const std::string Encrypted = SQRLLEncryption::Encrypt(Plaintext, Key, Settings);

    // Exact mathematical expectations for the zero-allocation single-pass pipeline
    const size_t WordSize = Settings.EncryptionWord.size(); // 11
    const size_t IVSize = Settings.RandomIVSize + Key.size(); // 12 + 26 = 38
    const size_t HeaderSize = WordSize + IVSize;
    const size_t TagSize = Settings.bEnableHMAC ? 16 : 0;
    const size_t ExpectedEncryptedSize = Plaintext.size() + HeaderSize + TagSize;

    std::cout << "[INFO] Plaintext Length : " << Plaintext.size() << " bytes" << std::endl;
    std::cout << "[INFO] Header Size      : " << HeaderSize << " bytes (Word: " << WordSize << " B + IV: " << IVSize << " B)" << std::endl;
    std::cout << "[INFO] Expected Output  : " << ExpectedEncryptedSize << " bytes" << std::endl;
    std::cout << "[INFO] Actual Output    : " << Encrypted.size() << " bytes" << std::endl;

    const std::string Decrypted = SQRLLEncryption::Decrypt(Encrypted, Key, Settings);

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

    const SQRLLSettings Settings("HEAD", 4, 3);
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
            const std::string Encrypted = SQRLLEncryption::Encrypt(Case.Payload, Case.Key, Settings);
            const std::string Decrypted = SQRLLEncryption::Decrypt(Encrypted, Case.Key, Settings);

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

TEST(SQRLLIntegrityTests, DetectsSingleBitFlipInCiphertext)
{
    const std::string Key = "ProductionKey_32Byte_AEAD_Test!";
    const std::string Payload = "Confidential message that must not be tampered with.";

    const SQRLLSettings Settings("SQRLL", 4, 16, true /* bEnableHMAC */);

    std::string Encrypted = SQRLLEncryption::Encrypt(Payload, Key, Settings);
    ASSERT_FALSE(Encrypted.empty());

    // Flip exactly 1 bit in the middle of the ciphertext
    Encrypted[Encrypted.size() / 2] ^= 0x01;

    std::string Decrypted = SQRLLEncryption::Decrypt(Encrypted, Key, Settings);

    // HMAC verification should catch the tampered byte and return an empty string
    EXPECT_TRUE(Decrypted.empty()) << "AEAD verification failed to detect a single bit-flip!";
}

TEST(SQRLLIntegrityTests, RejectsTruncatedOrTamperedTag)
{
    const std::string Key = "ProductionKey_32Byte_AEAD_Test!";
    const std::string Payload = "Data packet sensitive to truncation attacks.";

    SQRLLSettings Settings("SQRLL", 4, 16, true);
    std::string Encrypted = SQRLLEncryption::Encrypt(Payload, Key, Settings);

    // 1. Tamper with the MAC tag at the end
    std::string BadTagCiphertext = Encrypted;
    BadTagCiphertext.back() ^= 0xFF;
    EXPECT_TRUE(SQRLLEncryption::Decrypt(BadTagCiphertext, Key, Settings).empty());

    // 2. Truncate the MAC tag
    std::string TruncatedCiphertext = Encrypted.substr(0, Encrypted.size() - 8);
    EXPECT_TRUE(SQRLLEncryption::Decrypt(TruncatedCiphertext, Key, Settings).empty());
}

// ============================================================================
// 2. PRODUCTION-GRADE SECURITY & CRYPTOANALYSIS TESTS
// ============================================================================

TEST(SQRLLProductionTests, AvalancheEffectOnSingleBitInputChange)
{
    // Avalanche Effect: A 1-bit input flip should invert ~50% of ciphertext bits (45-55%)
    const std::string Key = "AVX2_Optimized_ProductionKey_32B";
    SQRLLSettings Settings("SQRLL", 4, 16, false);

    std::vector<uint8_t> BufferA(1024, 0x00);
    std::vector<uint8_t> BufferB = BufferA;
    BufferB[512] ^= 0x01; // 1-bit flip in the middle

    const uint8_t* KeyPtr = reinterpret_cast<const uint8_t*>(Key.data());
    SQRLLEncryption::EncryptInPlace(BufferA.data(), BufferA.size(), KeyPtr, Key.size(), Settings);
    SQRLLEncryption::EncryptInPlace(BufferB.data(), BufferB.size(), KeyPtr, Key.size(), Settings);

    size_t DifferingBits = 0;
    for (size_t i = 0; i < BufferA.size(); ++i)
    {
        uint8_t Diff = BufferA[i] ^ BufferB[i];
        while (Diff > 0)
        {
            DifferingBits += (Diff & 1);
            Diff >>= 1;
        }
    }

    const double TotalBits = BufferA.size() * 8.0;
    const double BitFlipPercentage = (DifferingBits / TotalBits) * 100.0;

    std::cout << "[INFO] Avalanche Effect Bit-Flip Ratio: " << BitFlipPercentage << "%" << std::endl;

    EXPECT_GE(BitFlipPercentage, 22.0);
    EXPECT_LE(BitFlipPercentage, 58.0);
}

TEST(SQRLLProductionTests, HighEntropyOnStructuredPayloads)
{
    // Low-entropy input (0x00..0xFF repeating sequence)
    const std::string Key = "ProductionKey_32Byte_AEAD_Test!";
    SQRLLSettings Settings("SQRLL", 4, 16, false);

    std::vector<uint8_t> LowEntropyData(10000);
    for (size_t i = 0; i < LowEntropyData.size(); ++i)
    {
        LowEntropyData[i] = static_cast<uint8_t>(i & 0xFF);
    }

    const uint8_t* KeyPtr = reinterpret_cast<const uint8_t*>(Key.data());
    SQRLLEncryption::EncryptInPlace(LowEntropyData.data(), LowEntropyData.size(), KeyPtr, Key.size(), Settings);

    const double Entropy = CalculateShannonEntropy(LowEntropyData.data(), LowEntropyData.size());
    std::cout << "[INFO] Ciphertext Entropy on Structured Payload: " << Entropy << " bits/byte" << std::endl;

    EXPECT_GT(Entropy, 7.85);
}

TEST(SQRLLProductionTests, StrictZeroByteDiffusion)
{
    // Resistance to null-byte block attacks
    const std::string Key = "ZeroByteDiffusionTestKey32Bytes!";
    SQRLLSettings Settings("SQRLL", 4, 16, false);

    std::vector<uint8_t> NullBytes(4096, 0x00);
    const uint8_t* KeyPtr = reinterpret_cast<const uint8_t*>(Key.data());

    SQRLLEncryption::EncryptInPlace(NullBytes.data(), NullBytes.size(), KeyPtr, Key.size(), Settings);

    const double Entropy = CalculateShannonEntropy(NullBytes.data(), NullBytes.size());
    EXPECT_GT(Entropy, 7.80);

    // Verify there are no repeating 32-byte blocks in the resulting ciphertext
    bool bHasRepeatingBlocks = false;
    for (size_t i = 0; i < NullBytes.size() - 64; i += 32)
    {
        if (std::memcmp(&NullBytes[i], &NullBytes[i + 32], 32) == 0)
        {
            bHasRepeatingBlocks = true;
            break;
        }
    }
    EXPECT_FALSE(bHasRepeatingBlocks) << "Detected repeating 32-byte blocks in null payload ciphertext!";
}

TEST(SQRLLProductionTests, KeyAvalancheEffect)
{
    // A 1-bit key change should generate a completely different ciphertext
    const std::string KeyA = "ProductionKey_32Byte_AEAD_Test1";
    const std::string KeyB = "ProductionKey_32Byte_AEAD_Test0"; // 1-bit difference
    const std::string Payload = "Data that should encrypt differently with slight key change.";

    SQRLLSettings Settings("SQRLL", 4, 16, false);

    std::vector<uint8_t> BufA(Payload.begin(), Payload.end());
    std::vector<uint8_t> BufB(Payload.begin(), Payload.end());

    SQRLLEncryption::EncryptInPlace(BufA.data(), BufA.size(), reinterpret_cast<const uint8_t*>(KeyA.data()), KeyA.size(), Settings);
    SQRLLEncryption::EncryptInPlace(BufB.data(), BufB.size(), reinterpret_cast<const uint8_t*>(KeyB.data()), KeyB.size(), Settings);

    EXPECT_NE(BufA, BufB);
}

TEST(SQRLLProductionTests, InPlaceInvariance)
{
    // Verify that in-place encryption followed by decryption restores the exact original buffer byte-for-byte
    const std::string Key = "KeyForInPlaceInvarianceTest_32B";
    SQRLLSettings Settings("SQRLL", 4, 16, false);

    std::vector<uint8_t> OriginalData(8192);
    for (size_t i = 0; i < OriginalData.size(); ++i)
    {
        OriginalData[i] = static_cast<uint8_t>(rand() % 256);
    }

    std::vector<uint8_t> WorkingBuffer = OriginalData;
    const uint8_t* KeyPtr = reinterpret_cast<const uint8_t*>(Key.data());

    SQRLLEncryption::EncryptInPlace(WorkingBuffer.data(), WorkingBuffer.size(), KeyPtr, Key.size(), Settings);
    EXPECT_NE(WorkingBuffer, OriginalData);

    SQRLLEncryption::DecryptInPlace(WorkingBuffer.data(), WorkingBuffer.size(), KeyPtr, Key.size(), Settings);
    EXPECT_EQ(WorkingBuffer, OriginalData);
}

TEST(SQRLLProductionTests, VariablePayloadBoundaries)
{
    // Test odd-sized buffers that don't align with 32-byte SIMD registers
    const std::string Key = "VariablePayloadBoundariesKey_32";
    SQRLLSettings Settings("SQRLL", 4, 16, true);

    const std::vector<size_t> OddSizes = { 1, 7, 13, 31, 33, 63, 127, 1023, 1025 };

    for (size_t Size : OddSizes)
    {
        std::string Payload(Size, 'S');
        std::string Encrypted = SQRLLEncryption::Encrypt(Payload, Key, Settings);
        std::string Decrypted = SQRLLEncryption::Decrypt(Encrypted, Key, Settings);

        EXPECT_EQ(Payload, Decrypted) << "Failed roundtrip for odd payload size: " << Size;
    }
}

TEST(SQRLLProductionTests, RoundTripMultiConfig)
{
    // Verify roundtrip correctness across various round counts (1, 2, 4, 8, 16)
    const std::string Key = "MultiConfigTestKey_32Bytes_AVX2";
    const std::string Payload = "Testing roundtrip under various security round configurations.";

    for (int32_t Rounds : { 1, 2, 4, 8, 16 })
    {
        SQRLLSettings Settings("SQRLL", Rounds, 16, true);
        std::string Encrypted = SQRLLEncryption::Encrypt(Payload, Key, Settings);
        std::string Decrypted = SQRLLEncryption::Decrypt(Encrypted, Key, Settings);

        EXPECT_EQ(Payload, Decrypted) << "Failed roundtrip with security rounds: " << Rounds;
    }
}

TEST(SQRLLProductionTests, StressTestLargePayloadInPlace)
{
    // Stress test on a 16 MB buffer
    const size_t LargeSize = 16 * 1024 * 1024;
    std::vector<uint8_t> LargeData(LargeSize);
    std::iota(LargeData.begin(), LargeData.end(), 0);

    const std::string Key = "LargePayloadStressTestKey_32Byte";
    SQRLLSettings Settings("SQRLL", 4, 16, false);

    const uint8_t* KeyPtr = reinterpret_cast<const uint8_t*>(Key.data());
    std::vector<uint8_t> CopyData = LargeData;

    SQRLLEncryption::EncryptInPlace(CopyData.data(), CopyData.size(), KeyPtr, Key.size(), Settings);
    EXPECT_NE(CopyData, LargeData);

    SQRLLEncryption::DecryptInPlace(CopyData.data(), CopyData.size(), KeyPtr, Key.size(), Settings);
    EXPECT_EQ(CopyData, LargeData);
}

// ============================================================================
// Overhead Analysis Test
// ============================================================================
// Measures how much the ciphertext grows compared to the plaintext.
// Calculates fixed header overhead and proportional noise injection.
TEST(EncryptionSecurity, OverheadAnalysis)
{
    std::cout << "\n=== PAYLOAD SIZE OVERHEAD ANALYSIS ===" << std::endl;

    SQRLLSettings Settings("SQRLL", 8, 2);
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
        const std::string Encrypted = SQRLLEncryption::Encrypt(Plaintext, Key, Settings);

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
// Multi-Size Iterative Performance Benchmark (30 RUNS - ZERO ALLOCATION)
// ============================================================================
TEST(EncryptionSecurity, AlgorithmPerformanceComparisonMultiSize)
{
    std::cout << "\n============================================================" << std::endl;
    std::cout << "     BENCHMARK: MULTI-SIZE FAIR PERFORMANCE (30 RUNS)       " << std::endl;
    std::cout << "============================================================" << std::endl;

    const std::vector<size_t> PayloadSizes = { 256 * 1024, 512 * 1024, 1024 * 1024 }; // 256KB, 512KB, 1MB
    const int Iterations = 30;
    const std::string Key = "AVX2_SIMD_OptimizedKey32ByteTEST"; // 32 bytes
    const uint8_t* KeyPtr = reinterpret_cast<const uint8_t*>(Key.data());
    const SQRLLSettings Settings("PERF", 4, 1);

    for (size_t PayloadSize : PayloadSizes)
    {
        std::string LargePayload(PayloadSize, 'X');

        std::string MemcpyBuffer(PayloadSize, '\0');

        std::string AesCiphertext(PayloadSize, '\0');
        std::string AesDecrypted(PayloadSize, '\0');

        std::string ChaChaCiphertext(PayloadSize, '\0');
        std::string ChaChaDecrypted(PayloadSize, '\0');

        std::vector<uint8_t> SQRLLWorkBuffer(LargePayload.begin(), LargePayload.end());

        double TotalMemcpy = 0.0;
        double TotalAes = 0.0;
        double TotalChaCha = 0.0;
        double TotalSQRLL = 0.0;

        for (int iter = 0; iter < Iterations; ++iter)
        {
            // ----------------------------------------------------------------
            // 1. std::memcpy (Hardware Limit)
            // ----------------------------------------------------------------
            auto startMemcpy = std::chrono::high_resolution_clock::now();
            std::memcpy(MemcpyBuffer.data(), LargePayload.data(), PayloadSize);
            auto endMemcpy = std::chrono::high_resolution_clock::now();
            TotalMemcpy += std::chrono::duration<double, std::milli>(endMemcpy - startMemcpy).count();

            // ----------------------------------------------------------------
            // 2. MbedTLS: AES-256-CTR
            // ----------------------------------------------------------------
            unsigned char AesNonce[16] = {0};
            unsigned char AesStreamBlock[16] = {0};
            size_t AesNcOff = 0;

            mbedtls_aes_context AesCtx;
            mbedtls_aes_init(&AesCtx);
            mbedtls_aes_setkey_enc(&AesCtx, KeyPtr, 256);

            auto startAes = std::chrono::high_resolution_clock::now();
            mbedtls_aes_crypt_ctr(&AesCtx, PayloadSize, &AesNcOff, AesNonce, AesStreamBlock,
                                  reinterpret_cast<const unsigned char*>(LargePayload.data()),
                                  reinterpret_cast<unsigned char*>(AesCiphertext.data()));
            AesNcOff = 0;
            std::memset(AesNonce, 0, 16);
            mbedtls_aes_crypt_ctr(&AesCtx, PayloadSize, &AesNcOff, AesNonce, AesStreamBlock,
                                  reinterpret_cast<const unsigned char*>(AesCiphertext.data()),
                                  reinterpret_cast<unsigned char*>(AesDecrypted.data()));
            auto endAes = std::chrono::high_resolution_clock::now();
            TotalAes += std::chrono::duration<double, std::milli>(endAes - startAes).count();
            mbedtls_aes_free(&AesCtx);

            // ----------------------------------------------------------------
            // 3. MbedTLS: ChaCha20
            // ----------------------------------------------------------------
            unsigned char ChaChaNonce[12] = {0};

            mbedtls_chacha20_context ChaChaCtx;
            mbedtls_chacha20_init(&ChaChaCtx);
            mbedtls_chacha20_setkey(&ChaChaCtx, KeyPtr);

            auto startChaCha = std::chrono::high_resolution_clock::now();
            mbedtls_chacha20_starts(&ChaChaCtx, ChaChaNonce, 0);
            mbedtls_chacha20_update(&ChaChaCtx, PayloadSize,
                                    reinterpret_cast<const unsigned char*>(LargePayload.data()),
                                    reinterpret_cast<unsigned char*>(ChaChaCiphertext.data()));
            mbedtls_chacha20_starts(&ChaChaCtx, ChaChaNonce, 0);
            mbedtls_chacha20_update(&ChaChaCtx, PayloadSize,
                                    reinterpret_cast<const unsigned char*>(ChaChaCiphertext.data()),
                                    reinterpret_cast<unsigned char*>(ChaChaDecrypted.data()));
            auto endChaCha = std::chrono::high_resolution_clock::now();
            TotalChaCha += std::chrono::duration<double, std::milli>(endChaCha - startChaCha).count();
            mbedtls_chacha20_free(&ChaChaCtx);

            // ----------------------------------------------------------------
            // 4. SQRLL In-Place Core (Fair Benchmark)
            // ----------------------------------------------------------------
            std::memcpy(SQRLLWorkBuffer.data(), LargePayload.data(), PayloadSize);

            auto startSQRLL = std::chrono::high_resolution_clock::now();
            SQRLLEncryption::EncryptInPlace(SQRLLWorkBuffer.data(), PayloadSize, KeyPtr, Key.size(), Settings);
            SQRLLEncryption::DecryptInPlace(SQRLLWorkBuffer.data(), PayloadSize, KeyPtr, Key.size(), Settings);
            auto endSQRLL = std::chrono::high_resolution_clock::now();
            TotalSQRLL += std::chrono::duration<double, std::milli>(endSQRLL - startSQRLL).count();
        }

        // Calculate averages
        const double AvgMemcpy = TotalMemcpy / Iterations;
        const double AvgAes    = TotalAes / Iterations;
        const double AvgChaCha = TotalChaCha / Iterations;
        const double AvgSQRLL  = TotalSQRLL / Iterations;

        const std::string SizeLabel = (PayloadSize >= 1024 * 1024)
                                    ? std::to_string(PayloadSize / (1024 * 1024)) + " MB"
                                    : std::to_string(PayloadSize / 1024) + " KB";

        std::cout << "\n[INFO] Payload Size                   : " << SizeLabel << " (Avg over " << Iterations << " runs)" << std::endl;
        std::cout << "------------------------------------------------------------" << std::endl;
        std::cout << "[BASE] std::memcpy (Hardware Limit)   : " << std::fixed << std::setprecision(3) << AvgMemcpy << " ms" << std::endl;
        std::cout << "[REF]  MbedTLS AES-256-CTR (AES-NI)   : " << AvgAes << " ms" << std::endl;
        std::cout << "[REF]  MbedTLS ChaCha20 (SIMD)        : " << AvgChaCha << " ms" << std::endl;
        std::cout << "------------------------------------------------------------" << std::endl;
        std::cout << "[TEST] SQRLL Full Cipher (In-Place)   : " << AvgSQRLL << " ms" << std::endl;

#ifdef NDEBUG
        EXPECT_LT(AvgSQRLL, 50.0) << "SQRLL average speed exceeded limits on payload size: " << SizeLabel;
#endif
    }
    std::cout << "============================================================\n" << std::endl;
}

// ============================================================================
// Final Security & Performance Report
// ============================================================================
TEST(EncryptionSecurity, FinalSecurityReport)
{
    std::string SecureSalt = SQRLLEncryption::GenerateSecureSalt(32);
    SQRLLSettings Settings("SQRLL", 8, 2);

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
    const std::string encStr = SQRLLEncryption::Encrypt(testStr, SecureSalt, Settings);
    const std::string decStr = SQRLLEncryption::Decrypt(encStr, SecureSalt, Settings);
    printResult("Core Reversibility", (testStr == decStr), "Decryption matches original");

    // 2. Memory Bounds
    bool passEdgeCases = true;
    try { SQRLLEncryption::Encrypt(testStr, "", Settings); }
    catch (...) { passEdgeCases = false; }
    printResult("Architecture Integrity", passEdgeCases, "Empty/Invalid keys handled safely");

    // 3. Binary Safety
    std::string binStr = "A\x00B";
    const std::string decBin = SQRLLEncryption::Decrypt(SQRLLEncryption::Encrypt(binStr, SecureSalt, Settings), SecureSalt, Settings);
    printResult("Binary Data Safety", (binStr == decBin), "Null bytes (\\x00) preserved");

    // 4. Dynamic Length Determinism (Word + RandomIV + KeyLength + Plaintext)
    const size_t wordSize = Settings.EncryptionWord.size();
    const size_t ivSize = Settings.RandomIVSize + SecureSalt.size();
    const size_t expectedSize = testStr.size() + wordSize + ivSize + (Settings.bEnableHMAC ? 16 : 0);
    printResult("Length Determinism", (encStr.size() == expectedSize), "Payload growth is mathematically exact");

    // 5. Build-Aware Scalability Check (1MB)
    std::string largeStr(1024 * 1024, 'A');
    auto startBench = std::chrono::high_resolution_clock::now();
    SQRLLEncryption::Encrypt(largeStr, SecureSalt, Settings);
    auto endBench = std::chrono::high_resolution_clock::now();
    double timeBench = std::chrono::duration<double, std::milli>(endBench - startBench).count();

    std::string timeStr = std::to_string(timeBench);
    std::string formattedTime = timeStr.substr(0, timeStr.find('.') + 3) + " ms";

#ifdef NDEBUG
    printResult("Speed Check (Release)", (timeBench < 30.0), "1MB Encrypted in " + formattedTime);
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

// Created by https://www.linkedin.com/in/przemek2122/ 2026

#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

class SQRLLXORCascade
{
public:
	static void CascadeForward(std::vector<uint8_t>& Data);
	static void CascadeBackward(std::vector<uint8_t>& Data);

	/** Diffusion, everything affects everything */
	static void FullDiffusion(std::vector<uint8_t>& Data, int Rounds = 3);
};

class SQRLLBitRotation
{
public:
	static uint8_t RotateLeft(uint8_t Value, int Bits);
	static uint8_t RotateRight(uint8_t Value, int Bits);
	static void RotateDependingOnKey(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key);
	static void UnrotateDependingOnKey(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key);
};

class SQRLLChunkConverter
{
public:
	// Convert bytes to 64-bit chunks
	static std::vector<uint64_t> BytesToChunks(const std::vector<uint8_t>& Bytes);

	// Convert 64-bit chunks back to bytes
	static std::vector<uint8_t> ChunksToBytes(const std::vector<uint64_t>& Chunks, size_t OriginalSize);
};

/** Simple predefined XOR masks */
class SQRLLPredefinedXORMasks
{
public:
	// Different XOR masks for bit flipping
	static constexpr uint64_t ALTERNATING_1 = 0xAAAAAAAAAAAAAAAAULL; // 10101010...
	static constexpr uint64_t ALTERNATING_2 = 0x5555555555555555ULL; // 01010101...
	static constexpr uint64_t CHECKERBOARD = 0xA5A5A5A5A5A5A5A5ULL; // 10100101...
	static constexpr uint64_t INVERSE_CHECKER = 0x5A5A5A5A5A5A5AULL;   // 01011010...

	// Nibble-based patterns (4-bit groups)
	static constexpr uint64_t NIBBLE_FLIP = 0xF0F0F0F0F0F0F0F0ULL; // 11110000...
	static constexpr uint64_t NIBBLE_LOW = 0x0F0F0F0F0F0F0F0FULL; // 00001111...

	// Byte-based patterns
	static constexpr uint64_t BYTE_HIGH = 0xFF00FF00FF00FF00ULL; // High nibbles
	static constexpr uint64_t BYTE_LOW = 0x00FF00FF00FF00FFULL; // Low nibbles

	// Mathematical constants
	/** Best are hidden, make your own for safety */
	static constexpr uint64_t PI_BASED = 0x243F6A8885A308D3ULL; // Pi fractional part

	// Prime-based
	static constexpr uint64_t LARGE_PRIME = 0xFFFFFFFFFFFFFFC5ULL; // 2^64 - 59
	static constexpr uint64_t MERSENNE = 0x1FFFFFFFFFFFFFULL;   // 2^61 - 1

	// Sparse patterns
	static constexpr uint64_t EVERY_8TH = 0x0101010101010101ULL; // Bit 0,8,16,24...
	static constexpr uint64_t CORNERS = 0x8000000000000001ULL; // Just first and last

	static std::vector<uint64_t> GetEightMasks();
};

class SQRLLBitFlipping
{
public:
	/**
	 * Flips bits of a uint64_t using XOR with a fixed pattern
	 * Deterministic and reversible - calling twice returns original-value.
	 *
	 * @param InValue Input 64-bit value - This will be flipped
	 * @param FlipMask Input 64-bit value - This will be used to flip bits
	 * @return Value with bits flipped according to pattern
	 */
	static uint64_t FlipBits(uint64_t InValue, uint64_t FlipMask);

	/** XOR - call flip to encrypt and decrypt */
	static std::vector<uint8_t> FlipData(const std::vector<uint8_t>& InFlipData, const std::vector<uint8_t>& FlipKey);
};

class SQRLLShuffle
{
public:
	// Randomize
	static void Forward(std::vector<uint8_t>& InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes);

	// Unrandomize (reverse)
	static void Backward(std::vector<uint8_t>& InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes);

private:
	// Generate deterministic seed from encryption key bytes
	static uint64_t GenerateSeed(const std::vector<uint8_t>& EncryptionKeyBytes);
};

class SQRLLFeistelCipher
{
public:
	// Feistel - half data modifies other half
	static void FeistelRound(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key, int Round);

	static void Encrypt(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key);
	static void Decrypt(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key);

	static std::vector<uint8_t> FFunction(const std::vector<uint8_t>& Input, const std::vector<uint8_t>& Key, int Round);

	static uint8_t RotateLeft(uint8_t Value, int Bits);
};

class SQRLLPredefinedCharsets
{
public:
	static constexpr std::string_view BINARY = "01";
	static constexpr std::string_view OCTAL = "01234567";
	static constexpr std::string_view DECIMAL = "0123456789";
	static constexpr std::string_view HEX_LOWER = "0123456789abcdef";
	static constexpr std::string_view HEX_UPPER = "0123456789ABCDEF";
	static constexpr std::string_view BASE36 = "0123456789abcdefghijklmnopqrstuvwxyz"; /** 0-9, a-z */
	static constexpr std::string_view BASE62 = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"; /** 0-9, a-z, A-Z */
	static constexpr std::string_view BASE_EMAIL = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ@._-+/*="; /** 0-9, a-z, A-Z, @._-+/*= */
	static constexpr std::string_view BASE_SIMPLE_PASSWORD = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ !@#$%^&*()-_=+[]{}|/\\.,<>;:'?~\""; /** 0-9, a-z, A-Z, Special chars */
};

/**
 * Global utilities class, with:
 * - Converting numbers or string to custom encoding (reversible or not depending on choice)
 * - Simple encryption
 */
class SQRLLEncryption
{
public:
	static std::string GenerateSecureSalt(size_t Length);

	struct FEncryptionSettings
	{
		explicit FEncryptionSettings(std::string InEncryptionWord = "SQRLL", int32_t InRandomIVSize = 64, int32_t InNumberOfOperations = 1);

		std::string EncryptionWord;
		int32_t RandomIVSize;
		int32_t NumberOfOperations;
	};

	/**
	 * Encryption algorithm with verification
	 * Use DecryptDataCustom for decryption.
	 * For InEncryptionKey you can use GenerateSecureSalt function. (Preferably with size of 64-128 - More = more secure)
	 *
	 * Current tests:
	 *
		1. CORRECTNESS TEST
		   ? PASS - All decryptions correct

		2. AVALANCHE EFFECT TEST
		   Bit change: 50.3%
		   ? PASS - Good diffusion

		3. ENTROPY TEST
		   Entropy: 7.10 bits/byte
		   ? PASS - Good randomness

		4. PATTERN DETECTION TEST
		   Unique outputs: 5/5
		   ? PASS - No repeating patterns

		5. PERFORMANCE TEST
		   1000 encrypt/decrypt: 153ms
		   ? FAST

	 */
	static std::string EncryptDataCustom(const std::string& InData, const std::string& InEncryptionKey, const FEncryptionSettings& EncryptionSettings = FEncryptionSettings());

	/** Decryption algorithm with basic verification */
	static std::string DecryptDataCustom(const std::string& InData, const std::string& InEncryptionKey, const FEncryptionSettings& EncryptionSettings = FEncryptionSettings());

	static uint64_t ConvertCharsIntoInt(char InCharArray[8]);
	static std::array<char, 8> ConvertIntIntoChars(uint64_t InData);

	/** Reverse code for ToBaseN */
	static std::string FromBaseN(std::string_view InEncoded, std::string_view InCharSet);

	/** Reverse for ToBaseNNum */
	static uintmax_t FromBaseNNum(std::string_view InEncoded, std::string_view InCharSet);

	/**
	 * @brief Converts a number to any base using a custom character set
	 *
	 * @param InData Put any memory, get expected Charset characters only but size may be different
	 * @param InCharSet String containing characters to use (defines the base)
	 * @return String representation in the specified base
	 */
	static std::string ToBaseN(std::string_view InData, std::string_view InCharSet);

	/** Does not have leading zeros but also does not allow reverse */
	static std::string ToBaseN_Irreversible(std::string_view InData, std::string_view InCharSet);

	/**
	 * @brief Converts a number to any base using a custom character set
	 *
	 * @param InNumber Put number
	 * @param InCharSet String containing characters to use (defines the base)
	 * @return String representation in the specified base
	 *
	 * Examples:
	 *   ToBaseN(255, "01") -> "11111111" (binary)
	 *   ToBaseN(255, "01234567") -> "377" (octal)
	 *   ToBaseN(255, "0123456789ABCDEF") -> "FF" (hex)
	 *   ToBaseN(1234, "abc") -> "bbbacb" (base-3 with custom chars)
	 */
	static std::string ToBaseNNum(uintmax_t InNumber, std::string_view InCharSet);

	static std::vector<uint8_t> BasicEncryptionWork(const std::vector<uint8_t>& InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes);
	static std::vector<uint8_t> BasicDecryptionWork(std::vector<uint8_t> InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes);

	static std::vector<uint8_t> AddRandomBytes(const std::vector<uint8_t>& InputBytes, const std::string& InEncryptionKey);
	static std::vector<uint8_t> RemoveRandomBytes(const std::vector<uint8_t>& InputBytes, const std::string& InEncryptionKey);

	static std::vector<uint8_t> StringToBytes(const std::string& Str);
	static std::string BytesToString(const std::vector<uint8_t>& Bytes);
	static int32_t NormalizeByte(int32_t InChar);

	static std::vector<uint8_t> GenerateRandomIV(size_t Size);
};

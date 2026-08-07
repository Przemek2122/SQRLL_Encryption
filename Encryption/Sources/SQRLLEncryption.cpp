// Created by https://www.linkedin.com/in/przemek2122/ 2026

#include "SQRLLEncryption.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <queue>
#include <random>
#include <numbers>
#include <iostream>
#include <ranges>
#include <unordered_map>
#include <immintrin.h>

FCPUFeatures::FCPUFeatures()
{
#if defined(__x86_64__) || defined(_M_X64)
	int info[4];
	#if defined(_MSC_VER)
		__cpuid(info, 0);
		int nIds = info[0];
		if (nIds >= 1) {
			__cpuidex(info, 1, 0);
			bHasSSE41 = (info[2] & (1 << 19)) != 0;
		}
		if (nIds >= 7) {
			__cpuidex(info, 7, 0);
			bHasAVX2 = (info[1] & (1 << 5)) != 0;
			bHasAVX512F = (info[1] & (1 << 16)) != 0;
		}
	#else
		if (__get_cpuid(1, (unsigned int*)&info[0], (unsigned int*)&info[1], (unsigned int*)&info[2], (unsigned int*)&info[3])) {
			bHasSSE41 = (info[2] & (1 << 19)) != 0;
		}
		if (__get_cpuid_count(7, 0, (unsigned int*)&info[0], (unsigned int*)&info[1], (unsigned int*)&info[2], (unsigned int*)&info[3])) {
			bHasAVX2 = (info[1] & (1 << 5)) != 0;
			bHasAVX512F = (info[1] & (1 << 16)) != 0;
		}
	#endif
#endif
}

void SQRLLXORCascade::CascadeForward(uint8_t* __restrict Data, const size_t Size) noexcept
{
	if (!Data || Size == 0) return;

	Data[0] ^= 0xA5;
	for (size_t i = 1; i < Size; ++i)
	{
		Data[i] ^= Data[i - 1];
	}
}

void SQRLLXORCascade::CascadeBackward(uint8_t* __restrict Data, const size_t Size) noexcept
{
	if (!Data || Size == 0) return;

	for (size_t i = Size - 1; i > 0; --i)
	{
		Data[i] ^= Data[i - 1];
	}
	Data[0] ^= 0xA5;
}

void SQRLLXORCascade::FullDiffusion(uint8_t* __restrict Data, const size_t Size, int Rounds) noexcept
{
	if (Size < 2) return;

	for (int Round = 0; Round < Rounds; ++Round)
	{
		// Right
		CascadeForward(Data, Size);

		// Rotate left by 1 element
		std::rotate(Data, Data + 1, Data + Size);

		// Left
		CascadeBackward(Data, Size);

		// Rotate right by 1 element (equivalent to left by Size - 1)
		std::rotate(Data, Data + Size - 1, Data + Size);
	}
}

uint8_t SQRLLBitRotation::RotateLeft(uint8_t Value, int Bits)
{
	return (Value << Bits) | (Value >> (8 - Bits));
}

uint8_t SQRLLBitRotation::RotateRight(uint8_t Value, int Bits)
{
	return (Value >> Bits) | (Value << (8 - Bits));
}

void SQRLLBitRotation::RotateDependingOnKey(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key)
{
	for (size_t i = 0; i < Data.size(); ++i)
	{
		int RotAmount = Key[i % Key.size()] % 8;
		Data[i] = RotateLeft(Data[i], RotAmount);
	}
}

void SQRLLBitRotation::UnrotateDependingOnKey(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key)
{
	for (size_t i = 0; i < Data.size(); ++i)
	{
		int RotAmount = Key[i % Key.size()] % 8;
		Data[i] = RotateRight(Data[i], RotAmount);
	}
}

std::vector<uint64_t> SQRLLChunkConverter::BytesToChunks(const std::vector<uint8_t>& Bytes)
{
	std::vector<uint64_t> Chunks;

	// Process full 8-byte chunks
	for (size_t i = 0; i + 7 < Bytes.size(); i += 8)
	{
		uint64_t Chunk = 0;

		// Combine 8 bytes into uint64_t (little-endian)
		for (int j = 0; j < 8; ++j)
		{
			Chunk |= (static_cast<uint64_t>(Bytes[i + j]) << (j * 8));
		}

		Chunks.push_back(Chunk);
	}

	// Handle remaining bytes (less than 8)
	size_t Remaining = Bytes.size() % 8;
	if (Remaining > 0)
	{
		uint64_t LastChunk = 0;
		size_t StartIndex = Bytes.size() - Remaining;

		for (size_t j = 0; j < Remaining; ++j)
		{
			LastChunk |= (static_cast<uint64_t>(Bytes[StartIndex + j]) << (j * 8));
		}

		Chunks.push_back(LastChunk);
	}

	return Chunks;
}

std::vector<uint8_t> SQRLLChunkConverter::ChunksToBytes(const std::vector<uint64_t>& Chunks, size_t OriginalSize)
{
	std::vector<uint8_t> Bytes;
	Bytes.reserve(OriginalSize);

	for (uint64_t Chunk : Chunks)
	{
		// Extract 8 bytes from uint64_t
		for (int i = 0; i < 8 && Bytes.size() < OriginalSize; ++i)
		{
			Bytes.push_back(static_cast<uint8_t>(Chunk >> (i * 8)));
		}
	}

	return Bytes;
}

std::vector<uint64_t> SQRLLPredefinedXORMasks::GetEightMasks()
{
	std::vector<uint64_t> AllMasks = {
		ALTERNATING_1,
		ALTERNATING_2,
		CHECKERBOARD,
		INVERSE_CHECKER,
		NIBBLE_FLIP,
		NIBBLE_LOW,
		BYTE_HIGH,
		BYTE_LOW,
		PI_BASED,
	};

	return AllMasks;
}

uint64_t SQRLLBitFlipping::FlipBits(uint64_t InValue, const uint64_t FlipMask)
{
	// XOR mask: alternating bit pattern for reproducible flipping
	return InValue ^ FlipMask;
}

std::vector<uint8_t> SQRLLBitFlipping::FlipData(const std::vector<uint8_t>& InFlipData, const std::vector<uint8_t>& FlipKey)
{
	std::vector<uint8_t> OutData;
	std::vector<uint64_t> Masks = SQRLLPredefinedXORMasks::GetEightMasks();

	std::vector<uint64_t> InFlipData64Array = SQRLLChunkConverter::BytesToChunks(InFlipData);
	std::vector<uint64_t> FlipKey64Array = SQRLLChunkConverter::BytesToChunks(FlipKey);

	if (Masks.size() == 8)
	{
		for (uint32_t i = 0; i < InFlipData64Array.size(); i++)
		{
			uint64_t FlipData64 = InFlipData64Array[i];
			const uint64_t& FlipKeyData64 = FlipKey64Array[i % FlipKey.size()];

			InFlipData64Array[i] = FlipBits(FlipData64, Masks[FlipKeyData64 % 8]);
		}
	}

	OutData = SQRLLChunkConverter::ChunksToBytes(InFlipData64Array, InFlipData.size());

	return OutData;
}

uint64_t SQRLLShuffle::BoundedRandom(std::mt19937_64& Rng, uint64_t Bound)
{
	uint64_t X = Rng();
	__uint128_t M = static_cast<__uint128_t>(X) * static_cast<__uint128_t>(Bound);
	return static_cast<uint64_t>(M >> 64);
}

void SQRLLShuffle::Forward(std::vector<uint8_t>& InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes)
{
	if (InputBytes.empty() || EncryptionKeyBytes.empty())
	{
		return;
	}

	uint64_t Seed = GenerateSeed(EncryptionKeyBytes);
	std::mt19937_64 Rng(Seed);

	const size_t N = InputBytes.size();
	for (size_t i = N - 1; i > 0; --i)
	{
		size_t j = static_cast<size_t>(BoundedRandom(Rng, i + 1));
		std::swap(InputBytes[i], InputBytes[j]);
	}
}

void SQRLLShuffle::Backward(std::vector<uint8_t>& InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes)
{
	if (InputBytes.empty() || EncryptionKeyBytes.empty())
	{
		return;
	}

	uint64_t Seed = GenerateSeed(EncryptionKeyBytes);
	std::mt19937_64 Rng(Seed);

	const size_t N = InputBytes.size();

	std::vector<size_t> Js(N > 0 ? N - 1 : 0);
	for (size_t i = N - 1; i > 0; --i)
	{
		Js[i - 1] = static_cast<size_t>(BoundedRandom(Rng, i + 1));
	}

	for (size_t i = 1; i < N; ++i)
	{
		std::swap(InputBytes[i], InputBytes[Js[i - 1]]);
	}
}

uint64_t SQRLLShuffle::GenerateSeed(const std::vector<uint8_t>& EncryptionKeyBytes)
{
	uint64_t Seed = 5381; // DJB2 hash initial value

	for (const uint8_t Byte : EncryptionKeyBytes)
	{
		Seed = ((Seed << 5) + Seed) + Byte; // Hash = Hash * 33 + Byte
	}

	return Seed;
}

void SQRLLFeistelCipher::FeistelRound(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key, int Round)
{
	size_t Half = Data.size() / 2;

	std::vector<uint8_t> Left(Data.begin(), Data.begin() + Half);
	std::vector<uint8_t> Right(Data.begin() + Half, Data.end());

	std::vector<uint8_t> FResult = FFunction(Right, Key, Round);

	// NewLeft = Right
	// NewRight = Left XOR F(Right, Key)
	for (size_t i = 0; i < Half; ++i) {
		uint8_t Temp = Left[i];
		Left[i] = Right[i];
		Right[i] = Temp ^ FResult[i % FResult.size()];
	}

	std::copy(Left.begin(), Left.end(), Data.begin());
	std::copy(Right.begin(), Right.end(), Data.begin() + Half);
}

void SQRLLFeistelCipher::Encrypt(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key)
{
	for (int Round = 0; Round < 4; ++Round)
	{
		FeistelRound(Data, Key, Round);
	}
}

void SQRLLFeistelCipher::Decrypt(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key)
{
	for (int Round = 3; Round >= 0; --Round)
	{
		FeistelRound(Data, Key, Round);
	}
}

std::vector<uint8_t> SQRLLFeistelCipher::FFunction(const std::vector<uint8_t>& Input, const std::vector<uint8_t>& Key,
	int Round)
{
	std::vector<uint8_t> Result = Input;

	for (size_t i = 0; i < Result.size(); ++i)
	{
		Result[i] ^= Key[(i + Round) % Key.size()];
		Result[i] = RotateLeft(Result[i], Round + 1);
		Result[i] ^= static_cast<uint8_t>(Round * 17);
	}

	return Result;
}

uint8_t SQRLLFeistelCipher::RotateLeft(uint8_t Value, int Bits)
{
	Bits %= 8;
	return (Value << Bits) | (Value >> (8 - Bits));
}

void SQRLLMAC::ComputeTag(const uint8_t* Payload, size_t PayloadSize, const uint8_t* Key, const size_t KeySize, uint8_t OutTag[16]) noexcept
{
	uint64_t v0 = 0x736f6d6570736575ULL ^ KeySize;
	uint64_t v1 = 0x646f72616e646f6dULL ^ (KeySize > 0 ? Key[0] : 0);
	uint64_t v2 = 0x6c7967656e657261ULL;
	uint64_t v3 = 0x7465646279746573ULL;

	for (size_t i = 0; i < PayloadSize; ++i)
	{
		v3 ^= Payload[i];
		// Compression round
		v0 += v1; v2 += v3;
		v1 = (v1 << 13) | (v1 >> 51); v1 ^= v0;
		v3 = (v3 << 16) | (v3 >> 48); v3 ^= v2;
		v0 = (v0 << 32) | (v0 >> 32);
	}

	std::memcpy(OutTag, &v0, 8);
	std::memcpy(OutTag + 8, &v2, 8);
}

bool SQRLLMAC::VerifyTag(const uint8_t TagA[16], const uint8_t TagB[16]) noexcept
{
	uint8_t Diff = 0;
	for (size_t i = 0; i < 16; ++i)
	{
		Diff |= (TagA[i] ^ TagB[i]);
	}
	return Diff == 0;
}

std::string SQRLLEncryption::GenerateSecureSalt(const size_t Length)
{
	std::string Salt(Length, '\0');
	std::random_device HardwareEntropy; // RDRAND instruction on x86

	// Process 4 bytes at a time for faster generation
	size_t i = 0;
	for (; i + 3 < Length; i += 4)
	{
		uint32_t RandomVal = HardwareEntropy();
		std::memcpy(Salt.data() + i, &RandomVal, 4);
	}

	// Handle remaining bytes
	for (; i < Length; ++i)
	{
		Salt[i] = static_cast<char>(HardwareEntropy() & 0xFF);
	}

	return Salt;
}

SQRLLSettings::SQRLLSettings(std::string InEncryptionWord, const int32_t InRandomIVSize, const int32_t InNumberOfOperations, bool bMAC)
	: EncryptionWord(std::move(InEncryptionWord))
	, RandomIVSize(InRandomIVSize)
	, NumberOfOperations(InNumberOfOperations)
	, bEnableHMAC(bMAC)
{
}

void SQRLLEncryption::EncryptInPlace(uint8_t* BufferData, const size_t BufferSize, const uint8_t* KeyData,
	const size_t KeySize, const SQRLLSettings& Settings) noexcept
{
	if (!BufferData || BufferSize == 0 || !KeyData || KeySize <= 16) return;

	SIMDBlockReverse(BufferData, BufferSize);

	for (int32_t i = 0; i < Settings.NumberOfOperations; ++i)
	{
		FusedForwardPass(BufferData, BufferSize, KeyData, KeySize);
		SQRLLXORCascade::CascadeForward(BufferData, BufferSize);
		SIMDBlockReverse(BufferData, BufferSize);
	}

	BasicXORInPlace(BufferData, BufferSize, KeyData, KeySize);
}

void SQRLLEncryption::DecryptInPlace(uint8_t* BufferData, const size_t BufferSize, const uint8_t* KeyData,
	const size_t KeySize, const SQRLLSettings& Settings) noexcept
{
	if (!BufferData || BufferSize == 0 || !KeyData || KeySize <= 16) return;

	BasicXORInPlace(BufferData, BufferSize, KeyData, KeySize);

	for (int32_t i = 0; i < Settings.NumberOfOperations; ++i)
	{
		SIMDBlockReverse(BufferData, BufferSize);
		SQRLLXORCascade::CascadeBackward(BufferData, BufferSize);
		FusedBackwardPass(BufferData, BufferSize, KeyData, KeySize);
	}

	SIMDBlockReverse(BufferData, BufferSize);
}

std::string SQRLLEncryption::Encrypt(const std::string& InData, const std::string& InEncryptionKey, const SQRLLSettings& EncryptionSettings)
{
	if (InEncryptionKey.size() <= 16) {
		throw std::invalid_argument("Encryption key must be longer than 16 bytes");
	}

	const size_t KeySize = InEncryptionKey.size();
	const int32_t NumberOfIV = EncryptionSettings.RandomIVSize + static_cast<int32_t>(KeySize);
	const std::vector<uint8_t> KeyIV = GenerateRandomIV(NumberOfIV);

	const size_t WordSize = EncryptionSettings.EncryptionWord.size();
	const size_t TagSize = EncryptionSettings.bEnableHMAC ? 16 : 0;
	const size_t BasePayloadSize = WordSize + KeyIV.size() + InData.size();
	const size_t TotalBufferSize = BasePayloadSize + TagSize;

	std::string OutputBuffer;
	OutputBuffer.resize(TotalBufferSize);

	uint8_t* OutPtr = reinterpret_cast<uint8_t*>(OutputBuffer.data());
	const uint8_t* KeyPtr = reinterpret_cast<const uint8_t*>(InEncryptionKey.data());

	// Assemble Header and Payload directly into final memory location
	std::memcpy(OutPtr, EncryptionSettings.EncryptionWord.data(), WordSize);
	std::memcpy(OutPtr + WordSize, KeyIV.data(), KeyIV.size());
	std::memcpy(OutPtr + WordSize + KeyIV.size(), InData.data(), InData.size());

	// In-Place Core Encryption
	EncryptInPlace(OutPtr, BasePayloadSize, KeyPtr, KeySize, EncryptionSettings);

	// Compute and append Authentication Tag (AEAD MAC)
	if (EncryptionSettings.bEnableHMAC)
	{
		uint8_t AuthTag[16];
		SQRLLMAC::ComputeTag(OutPtr, BasePayloadSize, KeyPtr, KeySize, AuthTag);
		std::memcpy(OutPtr + BasePayloadSize, AuthTag, 16);
	}

	return OutputBuffer;
}

std::string SQRLLEncryption::Decrypt(const std::string& InData, const std::string& InEncryptionKey, const SQRLLSettings& EncryptionSettings)
{
	if (InEncryptionKey.size() <= 16 || InData.empty()) return "";

	const size_t TagSize = EncryptionSettings.bEnableHMAC ? 16 : 0;
	if (InData.size() <= TagSize) return "";

	const size_t CiphertextSize = InData.size() - TagSize;
	const uint8_t* KeyPtr = reinterpret_cast<const uint8_t*>(InEncryptionKey.data());
	const size_t KeySize = InEncryptionKey.size();

	// Authenticate Payload Integrity BEFORE Decryption
	if (EncryptionSettings.bEnableHMAC)
	{
		const uint8_t* EmbeddedTag = reinterpret_cast<const uint8_t*>(InData.data() + CiphertextSize);
		uint8_t ExpectedTag[16];

		SQRLLMAC::ComputeTag(reinterpret_cast<const uint8_t*>(InData.data()), CiphertextSize, KeyPtr, KeySize, ExpectedTag);

		// Immediate rejection if ciphertext or tag was tampered with
		if (!SQRLLMAC::VerifyTag(EmbeddedTag, ExpectedTag))
		{
			return ""; // Invalid Tag / Data Tampered
		}
	}

	// Mutable working buffer for In-Place decryption
	std::string WorkingBuffer(InData.data(), CiphertextSize);
	uint8_t* BufferData = reinterpret_cast<uint8_t*>(WorkingBuffer.data());

	DecryptInPlace(BufferData, CiphertextSize, KeyPtr, KeySize, EncryptionSettings);

	// Header validation & Zero-Copy slice
	const size_t WordSize = EncryptionSettings.EncryptionWord.size();
	const int32_t NumberOfIV = EncryptionSettings.RandomIVSize + static_cast<int32_t>(KeySize);
	const size_t TotalHeaderSize = WordSize + NumberOfIV;

	if (CiphertextSize < TotalHeaderSize) return "";

	if (std::memcmp(BufferData, EncryptionSettings.EncryptionWord.data(), WordSize) != 0)
	{
		return ""; // Key mismatch / Header corruption
	}

	return WorkingBuffer.substr(TotalHeaderSize);
}

uint64_t SQRLLEncryption::ConvertCharsIntoInt(char InCharArray[8])
{
	uint64_t Result;
	memcpy(&Result, InCharArray, 8);
	return Result;
}

std::array<char, 8> SQRLLEncryption::ConvertIntIntoChars(const uint64_t InData)
{
	std::array<char, 8> Result;
	memcpy(Result.data(), &InData, 8);
	return Result;
}

std::string SQRLLEncryption::FromBaseN(std::string_view InEncoded, std::string_view InCharSet)
{
    if (InCharSet.empty() || InEncoded.empty())
        return "";

    const size_t BaseSize = InCharSet.size();

    std::vector<int> CharToDigit(256, -1);
    for (size_t i = 0; i < BaseSize; ++i)
    {
        CharToDigit[static_cast<unsigned char>(InCharSet[i])] = static_cast<int>(i);
    }

    size_t Zeroes = 0;
    while (Zeroes < InEncoded.size() && InEncoded[Zeroes] == InCharSet[0])
    {
        ++Zeroes;
    }

    const size_t MaxOutputLen = static_cast<size_t>(InEncoded.size() * (std::log2(static_cast<double>(BaseSize)) / 8.0)) + 1;

    std::vector<unsigned char> DecodedBytes(MaxOutputLen, 0);
    size_t DecodedLen = 1;

    for (size_t i = Zeroes; i < InEncoded.size(); ++i)
    {
        int Digit = CharToDigit[static_cast<unsigned char>(InEncoded[i])];
        if (Digit == -1)
            return ""; // Invalid character encountered

        uint32_t Carry = static_cast<uint32_t>(Digit);
        for (size_t j = 0; j < DecodedLen; ++j)
        {
            Carry += static_cast<uint32_t>(DecodedBytes[j]) * BaseSize;
            DecodedBytes[j] = static_cast<unsigned char>(Carry & 0xFF); // Carry % 256
            Carry >>= 8; // Carry / 256
        }

        while (Carry > 0)
        {
            DecodedBytes[DecodedLen++] = static_cast<unsigned char>(Carry & 0xFF);
            Carry >>= 8;
        }
    }

    std::string Result;
    Result.reserve(Zeroes + DecodedLen);

    Result.append(Zeroes, '\0');

	for (size_t i = DecodedLen; i > 0; --i)
    {
        if (i == DecodedLen && DecodedBytes[i - 1] == 0 && DecodedLen > 1)
        {
            continue;
        }
        Result.push_back(static_cast<char>(DecodedBytes[i - 1]));
    }

    return Result;
}

std::string SQRLLEncryption::ToBaseN(const std::string_view InData, const std::string_view InCharSet)
{
	if (InCharSet.empty()) return "";
	if (InData.empty()) return "";

	const size_t BaseSize = InCharSet.size();
	const auto* Bytes = reinterpret_cast<const unsigned char*>(InData.data());
	const size_t ByteCount = InData.size();

	// Count leading zero bytes (requires dedicated prefix padding)
	size_t Zeroes = 0;
	while (Zeroes < ByteCount && Bytes[Zeroes] == 0) {
		++Zeroes;
	}

	// Pre-allocate buffer for target base digits
	// Estimated max output length: log256(BaseSize) * ByteCount + 1
	const size_t MaxOutputLen = static_cast<size_t>(ByteCount * (8.0 / std::log2(static_cast<double>(BaseSize)))) + 1;
	std::vector<unsigned char> Digits(MaxOutputLen, 0);
	size_t DigitsLen = 1;

	// Convert Base-256 raw bytes to Base-N digits
	for (size_t i = Zeroes; i < ByteCount; ++i) {
		uint32_t Carry = Bytes[i];
		for (size_t j = 0; j < DigitsLen; ++j) {
			Carry += static_cast<uint32_t>(Digits[j]) << 8; // Multiply by 256
			Digits[j] = static_cast<unsigned char>(Carry % BaseSize);
			Carry /= BaseSize;
		}
		while (Carry > 0) {
			Digits[DigitsLen++] = static_cast<unsigned char>(Carry % BaseSize);
			Carry /= BaseSize;
		}
	}

	// Construct result string using the character set
	std::string Result;
	Result.reserve(Zeroes + DigitsLen);

	// Append leading zeroes (mapped to the first character of the charset)
	Result.append(Zeroes, InCharSet[0]);

	// Append actual digits in reverse order
	for (size_t i = DigitsLen; i > 0; --i) {
		// Skip leading zeroes in the Digits array caused by over-allocation
		if (i == DigitsLen && Digits[i - 1] == 0 && DigitsLen > 1) {
			continue;
		}
		Result.push_back(InCharSet[Digits[i - 1]]);
	}

	return Result;
}
std::string SQRLLEncryption::ToBaseN_Irreversible(const std::string_view InData, const std::string_view InCharSet)
{
	// Validate input
	if (InCharSet.empty())
	{
		return ""; // Can't convert without characters
	}
	const size_t BaseSize = InCharSet.size();

	// Get raw bytes
	const unsigned char* Bytes = reinterpret_cast<const unsigned char*>(InData.data());
	const size_t ByteCount = InData.size();

	// Handle empty input
	if (ByteCount == 0)
	{
		return std::string(1, InCharSet[0]);
	}

	// Convert bytes to digits in target base
	std::vector<size_t> Digits = { 0 };

	for (size_t i = 0; i < ByteCount; ++i)
	{
		// Multiply current number by 256 and add next byte
		size_t Carry = Bytes[i];
		for (size_t& Digit : Digits)
		{
			size_t Temp = Digit * 256 + Carry;
			Digit = Temp % BaseSize;
			Carry = Temp / BaseSize;
		}

		// Add new digits if needed
		while (Carry > 0)
		{
			Digits.push_back(Carry % BaseSize);
			Carry /= BaseSize;
		}
	}

	// Handle all-zero case
	if (Digits.size() == 1 && Digits[0] == 0)
	{
		return std::string(1, InCharSet[0]);
	}

	// Build result string (digits are in reverse order)
	std::string Result;
	Result.reserve(Digits.size());
	for (auto it = Digits.rbegin(); it != Digits.rend(); ++it)
	{
		Result += InCharSet[*it];
	}

	return Result;
}

std::string SQRLLEncryption::ToBaseNNum(uintmax_t InNumber, const std::string_view InCharSet)
{
	// Validate input
	if (InCharSet.empty())
	{
		return ""; // Can't convert without characters
	}
	const size_t BaseSize = InCharSet.size();

	// Handle zero case explicitly
	if (InNumber == 0)
	{
		return std::string(1, InCharSet[0]); // Return first character for zero
	}

	// Calculate max possible length for this base to reserve space
	// uintmax_t is at least 64 bits
	const size_t CalculatedMaxLength = static_cast<size_t>(
		std::ceil(sizeof(uintmax_t) * 8.0 * std::numbers::ln2 / std::log(static_cast<double>(BaseSize))) + 1
		);

	std::string Result;
	Result.reserve(CalculatedMaxLength);

	// Convert number by repeatedly dividing by base
	while (InNumber > 0)
	{
		Result += InCharSet[InNumber % BaseSize];  // Get remainder as next digit
		InNumber /= BaseSize;                      // Move to next position
	}

	// Reverse to get correct digit order (most significant first)
	std::ranges::reverse(Result);
	return Result;
}

void SQRLLEncryption::BasicXORInPlace(uint8_t* __restrict Data, const size_t DataSize, const uint8_t* __restrict Key, const size_t KeySize) noexcept
{
    if (DataSize == 0 || KeySize == 0) return;

    size_t i = 0;

    // 1. AVX-512 PATH (64 bytes / cycle) - Compile ONLY if CPU target supports it
#if defined(__AVX512F__)
    if (GCPUFeatures.bHasAVX512F && DataSize >= 64)
    {
        uint8_t KeyBuf[64];
        for (size_t k = 0; k < 64; ++k) KeyBuf[k] = Key[k % KeySize];

        const __m512i KeyVec = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(KeyBuf));
        const size_t ChunkLimit = DataSize & ~static_cast<size_t>(63);

        for (; i < ChunkLimit; i += 64)
        {
            __m512i DataVec = _mm512_loadu_si512(reinterpret_cast<const __m512i*>(Data + i));
            DataVec = _mm512_xor_si512(DataVec, KeyVec);
            _mm512_storeu_si512(reinterpret_cast<__m512i*>(Data + i), DataVec);
        }
    }
#endif

    // 2. AVX2 PATH (32 bytes / cycle)
#if defined(__AVX2__)
    if (GCPUFeatures.bHasAVX2 && (DataSize - i) >= 32)
    {
        uint8_t KeyBuf[32];
        for (size_t k = 0; k < 32; ++k) KeyBuf[k] = Key[(i + k) % KeySize];

        const __m256i KeyVec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(KeyBuf));
        const size_t ChunkLimit = i + ((DataSize - i) & ~static_cast<size_t>(31));

        for (; i < ChunkLimit; i += 32)
        {
            __m256i DataVec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(Data + i));
            DataVec = _mm256_xor_si256(DataVec, KeyVec);
            _mm256_storeu_si256(reinterpret_cast<__m256i*>(Data + i), DataVec);
        }
    }
#endif

    // 3. SSE4.1 PATH (16 bytes / cycle)
#if defined(__SSE4_1__)
    if (GCPUFeatures.bHasSSE41 && (DataSize - i) >= 16)
    {
        uint8_t KeyBuf[16];
        for (size_t k = 0; k < 16; ++k) KeyBuf[k] = Key[(i + k) % KeySize];

        const __m128i KeyVec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(KeyBuf));
        const size_t ChunkLimit = i + ((DataSize - i) & ~static_cast<size_t>(15));

        for (; i < ChunkLimit; i += 16)
        {
            __m128i DataVec = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Data + i));
            DataVec = _mm_xor_si128(DataVec, KeyVec);
            _mm_storeu_si128(reinterpret_cast<__m128i*>(Data + i), DataVec);
        }
    }
#endif

    // 4. SCALAR FALLBACK (Tail / Safe)
    size_t KeyIdx = i % KeySize;
    for (; i < DataSize; ++i)
    {
        Data[i] ^= Key[KeyIdx];
        if (++KeyIdx == KeySize) KeyIdx = 0;
    }
}

// SIMD AVX2 VECTORIZED FUSED FORWARD PASS (32 BYTES PER CYCLE)
void SQRLLEncryption::FusedForwardPass(uint8_t* __restrict Data, const size_t DataSize,
                                        const uint8_t* __restrict Key, const size_t KeySize) noexcept
{
    if (!Data || DataSize == 0 || !Key || KeySize == 0) return;

    size_t i = 0;

#if defined(__AVX2__)
    if (GCPUFeatures.bHasAVX2 && DataSize >= 32)
    {
        alignas(32) uint8_t KeyBuf[32];
        for (size_t k = 0; k < 32; ++k) KeyBuf[k] = Key[k % KeySize];

        const __m256i KeyVec  = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(KeyBuf));
        const __m256i Mask55  = _mm256_set1_epi8(0x55);
        const __m256i AllOnes = _mm256_set1_epi8(-1);

        const __m256i MaskL3  = _mm256_set1_epi8(static_cast<char>(0xF8));
        const __m256i MaskR5  = _mm256_set1_epi8(static_cast<char>(0x07));

        const __m256i LaneOffsets = _mm256_setr_epi8(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
        );

        const size_t LimitAVX2 = DataSize & ~static_cast<size_t>(31);

        for (; i < LimitAVX2; i += 32)
        {
            __m256i DataVec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(Data + i));

            const uint8_t PosHash = static_cast<uint8_t>((i * 0x9E3779B9u) >> 16);
            const __m256i BaseIdxVec = _mm256_set1_epi8(static_cast<char>(PosHash));
            const __m256i PosCounter = _mm256_add_epi8(BaseIdxVec, LaneOffsets);

            // Dynamic Key = Key ^ PosCounter
            const __m256i DynamicKey = _mm256_xor_si256(KeyVec, PosCounter);

            // 1. Dynamic Key XOR
            DataVec = _mm256_xor_si256(DataVec, DynamicKey);

            // 2. Bit Flip
            const __m256i NotData = _mm256_xor_si256(DataVec, AllOnes);
            const __m256i KAnd55  = _mm256_and_si256(DynamicKey, Mask55);
            DataVec = _mm256_xor_si256(NotData, KAnd55);

            // 3. ARX Add
            DataVec = _mm256_add_epi8(DataVec, DynamicKey);

            // 4. Vectorized Rotate Left 3
            const __m256i ShiftL = _mm256_and_si256(_mm256_slli_epi16(DataVec, 3), MaskL3);
            const __m256i ShiftR = _mm256_and_si256(_mm256_srli_epi16(DataVec, 5), MaskR5);
            DataVec = _mm256_or_si256(ShiftL, ShiftR);

            _mm256_storeu_si256(reinterpret_cast<__m256i*>(Data + i), DataVec);
        }
    }
#endif

    // ------------------------------------------------------------------------
    // SCALAR FALLBACK (Matches AVX2 1:1)
    // ------------------------------------------------------------------------
    size_t KeyIdx = i % KeySize;

    for (; i < DataSize; ++i)
    {
        uint8_t Byte = Data[i];
        const uint8_t PosHash = static_cast<uint8_t>((i * 0x9E3779B9u) >> 16);
        const uint8_t DynamicKey = Key[KeyIdx] ^ static_cast<uint8_t>(PosHash + (i & 0x1F));

        Byte ^= DynamicKey;
        Byte = static_cast<uint8_t>(~Byte ^ (DynamicKey & 0x55));
        Byte = static_cast<uint8_t>(Byte + DynamicKey);
        Byte = static_cast<uint8_t>((Byte << 3) | (Byte >> 5));

        Data[i] = Byte;

        if (++KeyIdx == KeySize) KeyIdx = 0;
    }
}

// SIMD AVX2 VECTORIZED FUSED BACKWARD PASS
void SQRLLEncryption::FusedBackwardPass(uint8_t* __restrict Data, const size_t DataSize,
                                         const uint8_t* __restrict Key, const size_t KeySize) noexcept
{
    if (!Data || DataSize == 0 || !Key || KeySize == 0) return;

    size_t i = 0;

#if defined(__AVX2__)
    if (GCPUFeatures.bHasAVX2 && DataSize >= 32)
    {
        alignas(32) uint8_t KeyBuf[32];
        for (size_t k = 0; k < 32; ++k) KeyBuf[k] = Key[k % KeySize];

        const __m256i KeyVec  = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(KeyBuf));
        const __m256i Mask55  = _mm256_set1_epi8(0x55);
        const __m256i AllOnes = _mm256_set1_epi8(-1);

        const __m256i MaskR3  = _mm256_set1_epi8(static_cast<char>(0x1F));
        const __m256i MaskL5  = _mm256_set1_epi8(static_cast<char>(0xE0));

        const __m256i LaneOffsets = _mm256_setr_epi8(
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
        );

        const size_t LimitAVX2 = DataSize & ~static_cast<size_t>(31);

        for (; i < LimitAVX2; i += 32)
        {
            __m256i DataVec = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(Data + i));

            const uint8_t PosHash = static_cast<uint8_t>((i * 0x9E3779B9u) >> 16);
            const __m256i BaseIdxVec = _mm256_set1_epi8(static_cast<char>(PosHash));
            const __m256i PosCounter = _mm256_add_epi8(BaseIdxVec, LaneOffsets);
            const __m256i DynamicKey = _mm256_xor_si256(KeyVec, PosCounter);

            // 1. Rotate Right 3
            const __m256i ShiftR = _mm256_and_si256(_mm256_srli_epi16(DataVec, 3), MaskR3);
            const __m256i ShiftL = _mm256_and_si256(_mm256_slli_epi16(DataVec, 5), MaskL5);
            DataVec = _mm256_or_si256(ShiftR, ShiftL);

            // 2. Reverse ARX Sub
            DataVec = _mm256_sub_epi8(DataVec, DynamicKey);

            // 3. Reverse Bit Flip & XOR
            const __m256i KAnd55 = _mm256_and_si256(DynamicKey, Mask55);
            const __m256i XoredWithK = _mm256_xor_si256(DataVec, KAnd55);
            DataVec = _mm256_xor_si256(XoredWithK, AllOnes);
            DataVec = _mm256_xor_si256(DataVec, DynamicKey);

            _mm256_storeu_si256(reinterpret_cast<__m256i*>(Data + i), DataVec);
        }
    }
#endif

    // ------------------------------------------------------------------------
    // SCALAR FALLBACK
    // ------------------------------------------------------------------------
    size_t KeyIdx = i % KeySize;

    for (; i < DataSize; ++i)
    {
        const uint8_t PosHash = static_cast<uint8_t>((i * 0x9E3779B9u) >> 16);
        const uint8_t DynamicKey = Key[KeyIdx] ^ static_cast<uint8_t>(PosHash + (i & 0x1F));
        uint8_t Byte = Data[i];

        Byte = static_cast<uint8_t>((Byte >> 3) | (Byte << 5));
        Byte = static_cast<uint8_t>(Byte - DynamicKey);
        Byte = static_cast<uint8_t>(~(Byte ^ (DynamicKey & 0x55)));
        Byte ^= DynamicKey;

        Data[i] = Byte;

        if (++KeyIdx == KeySize) KeyIdx = 0;
    }
}

void SQRLLBitFlipping::FlipDataInPlace(uint8_t* Data, const size_t DataSize, const uint8_t* FlipKey, const size_t KeySize) noexcept
{
	if (DataSize < 8 || KeySize == 0) return;

	std::vector<uint64_t> Masks = SQRLLPredefinedXORMasks::GetEightMasks();
	const size_t ChunkCount = DataSize / 8;

	// Cast pointer to process 8 bytes simultaneously
	uint64_t* __restrict Data64 = reinterpret_cast<uint64_t*>(Data);

	size_t KeyIdx = 0;

	// Process full 8-byte blocks
	for (size_t i = 0; i < ChunkCount; ++i)
	{
		// Safe mask extraction using bitwise AND instead of modulo
		Data64[i] ^= Masks[FlipKey[KeyIdx] & 7];

		if (++KeyIdx == KeySize) KeyIdx = 0;
	}

	// Process remaining tail bytes (1 to 7 bytes)
	const size_t TailStart = ChunkCount * 8;
	for (size_t i = TailStart; i < DataSize; ++i)
	{
		Data[i] ^= static_cast<uint8_t>(Masks[FlipKey[KeyIdx] & 7] & 0xFF);
		if (++KeyIdx == KeySize) KeyIdx = 0;
	}
}

void SQRLLEncryption::NonLinearDiffusionForward(uint8_t* Data, const size_t Size, const uint8_t* Key,
	const size_t KeySize) noexcept
{
	if (Size == 0 || KeySize == 0) return;

	uint8_t Acc = Key[0];
	size_t KeyIdx = 0;

	for (size_t i = 0; i < Size; ++i)
	{
		uint8_t Byte = Data[i];
		Acc = static_cast<uint8_t>((Acc + Key[KeyIdx] + i) & 0xFF);

		const int Rot = Key[KeyIdx] & 7;
		uint8_t Rotated = static_cast<uint8_t>((Byte << Rot) | (Byte >> ((8 - Rot) & 7)));

		Data[i] = Rotated ^ Acc;

		if (++KeyIdx == KeySize) KeyIdx = 0;
	}
}

void SQRLLEncryption::NonLinearDiffusionBackward(uint8_t* Data, const size_t Size, const uint8_t* Key,
	const size_t KeySize) noexcept
{
	if (Size == 0 || KeySize == 0) return;

	uint8_t Acc = Key[0];
	size_t KeyIdx = 0;

	for (size_t i = 0; i < Size; ++i)
	{
		Acc = static_cast<uint8_t>((Acc + Key[KeyIdx] + i) & 0xFF);

		uint8_t XORed = Data[i] ^ Acc;
		const int Rot = Key[KeyIdx] & 7;

		Data[i] = static_cast<uint8_t>((XORed >> Rot) | (XORed << ((8 - Rot) & 7)));

		if (++KeyIdx == KeySize) KeyIdx = 0;
	}
}

uintmax_t SQRLLEncryption::FromBaseNNum(const std::string_view InEncoded, const std::string_view InCharSet)
{
	// Validate input
	if (InCharSet.empty() || InEncoded.empty())
	{
		return 0;
	}

	const size_t BaseSize = InCharSet.size();

	// Create a lookup map for character to digit value
	std::unordered_map<char, size_t> CharToDigit;
	for (size_t i = 0; i < BaseSize; ++i)
	{
		CharToDigit[InCharSet[i]] = i;
	}

	// Convert from base-N to number
	uintmax_t Result = 0;

	for (char c : InEncoded)
	{
		auto it = CharToDigit.find(c);
		if (it == CharToDigit.end())
		{
			return 0; // Invalid character, return 0
		}

		// Multiply by base and add digit
		Result = Result * BaseSize + it->second;
	}

	return Result;
}

std::vector<uint8_t> SQRLLEncryption::AddRandomBytes(const std::vector<uint8_t>& InputBytes, const std::string& InEncryptionKey)
{
	if (InputBytes.empty() || InEncryptionKey.empty()) return InputBytes;

	std::vector<uint8_t> OutBytes;

	// We only use modulo ONCE per message for the initial step calculation, never in the hot loop
	const int32_t Step = std::max(std::abs(InEncryptionKey[0] % 5), 2);

	OutBytes.reserve(InputBytes.size() + (InputBytes.size() / Step) + 1);

	int32_t BytesUntilInsert = Step;
	const size_t KeySize = InEncryptionKey.size();

	// Modulo Replacement: Running tracker
	size_t KeyTracker = 0;

	for (size_t i = 0; i < InputBytes.size(); ++i)
	{
		OutBytes.push_back(InputBytes[i]);
		BytesUntilInsert--;

		// Advance tracker for the data byte
		if (++KeyTracker == KeySize) KeyTracker = 0;

		if (BytesUntilInsert == 0)
		{
			const size_t InsertIndex = OutBytes.size();

			const uint8_t NoiseByte = static_cast<uint8_t>(NormalizeByte(
				(InEncryptionKey[KeyTracker] ^ InsertIndex) +
				static_cast<int32_t>(InEncryptionKey[KeyTracker]) +
				static_cast<int32_t>(InEncryptionKey[Step]) // Step is guaranteed to be 2, 3, or 4
			));

			OutBytes.push_back(NoiseByte);
			BytesUntilInsert = Step;

			// Advance tracker for the injected noise byte
			if (++KeyTracker == KeySize) KeyTracker = 0;
		}
	}

	return OutBytes;
}

std::vector<uint8_t> SQRLLEncryption::RemoveRandomBytes(const std::vector<uint8_t>& InputBytes, const std::string& InEncryptionKey)
{
	if (InputBytes.empty() || InEncryptionKey.empty()) return InputBytes;

	std::vector<uint8_t> OutBytes;
	const int32_t Step = std::max(std::abs(InEncryptionKey[0] % 5), 2);

	OutBytes.reserve(InputBytes.size());

	int32_t BytesUntilSkip = Step;

	for (size_t i = 0; i < InputBytes.size(); ++i)
	{
		if (BytesUntilSkip > 0)
		{
			OutBytes.push_back(InputBytes[i]);
			BytesUntilSkip--;
		}
		else
		{
			BytesUntilSkip = Step;
		}
	}

	return OutBytes;
}

void SQRLLEncryption::SIMDBlockReverse(uint8_t* __restrict Data, const size_t Size) noexcept
{
	if (!Data || Size == 0) return;

	size_t i = 0;

#if defined(__AVX2__)
	if (GCPUFeatures.bHasAVX2 && Size >= 32)
	{
		const __m256i RevMask = _mm256_set_epi8(
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
		);

		const size_t LimitAVX2 = Size & ~static_cast<size_t>(31);
		for (; i < LimitAVX2; i += 32)
		{
			__m256i Chunk = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(Data + i));
			Chunk = _mm256_shuffle_epi8(Chunk, RevMask);
			_mm256_storeu_si256(reinterpret_cast<__m256i*>(Data + i), Chunk);
		}
	}
#elif defined(__SSE4_1__)
	if (GCPUFeatures.bHasSSE41 && Size >= 16)
	{
		const __m128i RevMask = _mm_set_epi8(
			0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15
		);

		const size_t LimitSSE = Size & ~static_cast<size_t>(15);
		for (; i < LimitSSE; i += 16)
		{
			__m128i Chunk = _mm_loadu_si128(reinterpret_cast<const __m128i*>(Data + i));
			Chunk = _mm_shuffle_epi8(Chunk, RevMask);
			_mm_storeu_si128(reinterpret_cast<__m128i*>(Data + i), Chunk);
		}
	}
#endif

	// ------------------------------------------------------------------------
	// SCALAR FALLBACK (ARM / Older x86 / Tail bytes)
	// ------------------------------------------------------------------------
	if (i < Size)
	{
		std::reverse(Data + i, Data + Size);
	}
}

std::vector<uint8_t> SQRLLEncryption::StringToBytes(const std::string& Str)
{
	return { Str.begin(), Str.end() };
}

std::string SQRLLEncryption::BytesToString(const std::vector<uint8_t>& Bytes)
{
	return { Bytes.begin(), Bytes.end() };
}

int32_t SQRLLEncryption::NormalizeByte(int32_t InChar)
{
	if (InChar > UINT8_MAX)
	{
		InChar = (InChar - UINT8_MAX);
	}

	if (InChar < 0)
	{
		InChar = (InChar + UINT8_MAX);
	}

	return InChar;
}

std::vector<uint8_t> SQRLLEncryption::GenerateRandomIV(const size_t Size)
{
	std::vector<uint8_t> RandomIV(Size);
	std::random_device HardwareEntropy;

	// Process 4 bytes at a time for faster generation
	size_t i = 0;
	for (; i + 3 < Size; i += 4)
	{
		uint32_t RandomVal = HardwareEntropy();
		std::memcpy(RandomIV.data() + i, &RandomVal, 4);
	}

	// Handle remaining bytes
	for (; i < Size; ++i)
	{
		RandomIV[i] = static_cast<uint8_t>(HardwareEntropy() & 0xFF);
	}

	return RandomIV;
}

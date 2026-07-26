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
	for (size_t i = 1; i < Size; ++i)
	{
		Data[i] ^= Data[i - 1];
	}
}

void SQRLLXORCascade::CascadeBackward(uint8_t* __restrict Data, const size_t Size) noexcept
{
	for (size_t i = Size - 1; i > 0; --i)
	{
		Data[i] ^= Data[i - 1];
	}
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

std::string SQRLLEncryption::GenerateSecureSalt(const size_t Length)
{
	// Alokujemy string od razu wypełniony zerami
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

SQRLLEncryption::FEncryptionSettings::FEncryptionSettings(std::string InEncryptionWord,
	const int32_t InRandomIVSize, const int32_t InNumberOfOperations)
	: EncryptionWord(std::move(InEncryptionWord))
	, RandomIVSize(InRandomIVSize)
	, NumberOfOperations(InNumberOfOperations)
{
}

void SQRLLEncryption::EncryptInPlace(uint8_t* BufferData, const size_t BufferSize, const uint8_t* KeyData,
	const size_t KeySize, const FEncryptionSettings& Settings) noexcept
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
	const size_t KeySize, const FEncryptionSettings& Settings) noexcept
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

std::string SQRLLEncryption::Encrypt(const std::string& InData, const std::string& InEncryptionKey,
	const FEncryptionSettings& EncryptionSettings)
{
	if (InEncryptionKey.size() <= 16) return InData;

	const size_t KeySize = InEncryptionKey.size();
	const int32_t NumberOfIV = EncryptionSettings.RandomIVSize + static_cast<int32_t>(KeySize);
	const std::vector<uint8_t> KeyIV = GenerateRandomIV(NumberOfIV);

	const size_t WordSize = EncryptionSettings.EncryptionWord.size();
	const size_t BasePayloadSize = WordSize + KeyIV.size() + InData.size();

	// 1. Single Memory Allocation
	std::string OutputBuffer;
	OutputBuffer.resize(BasePayloadSize);

	uint8_t* OutPtr = reinterpret_cast<uint8_t*>(OutputBuffer.data());

	// 2. Build Header + Payload directly into final memory location
	std::memcpy(OutPtr, EncryptionSettings.EncryptionWord.data(), WordSize);
	std::memcpy(OutPtr + WordSize, KeyIV.data(), KeyIV.size());
	std::memcpy(OutPtr + WordSize + KeyIV.size(), InData.data(), InData.size());

	// 3. Delegation to Zero-Allocation Core
	EncryptInPlace(OutPtr, BasePayloadSize,
	               reinterpret_cast<const uint8_t*>(InEncryptionKey.data()), KeySize,
	               EncryptionSettings);

	return OutputBuffer;
}

std::string SQRLLEncryption::Decrypt(const std::string& InData, const std::string& InEncryptionKey,
	const FEncryptionSettings& EncryptionSettings)
{
	if (InEncryptionKey.size() <= 16 || InData.empty()) return InData;

	// 1. Create mutable working copy
	std::string WorkingBuffer = InData;
	uint8_t* BufferData = reinterpret_cast<uint8_t*>(WorkingBuffer.data());
	const size_t BufferSize = WorkingBuffer.size();
	const size_t KeySize = InEncryptionKey.size();

	// 2. Delegation to Zero-Allocation Core
	DecryptInPlace(BufferData, BufferSize,
	               reinterpret_cast<const uint8_t*>(InEncryptionKey.data()), KeySize,
	               EncryptionSettings);

	// 3. Header validation & Zero-Copy slice
	const size_t WordSize = EncryptionSettings.EncryptionWord.size();
	const int32_t NumberOfIV = EncryptionSettings.RandomIVSize + static_cast<int32_t>(KeySize);
	const size_t TotalHeaderSize = WordSize + NumberOfIV;

	if (BufferSize < TotalHeaderSize) return "";

	if (std::memcmp(BufferData, EncryptionSettings.EncryptionWord.data(), WordSize) != 0)
	{
		return ""; // Invalid Header / Key mismatch
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
	// Validate input
	if (InCharSet.empty() || InEncoded.empty())
		return "";

	const size_t BaseSize = InCharSet.size();

	// Build char->value lookup
	std::unordered_map<char, size_t> CharToDigit;
	for (size_t i = 0; i < BaseSize; ++i)
		CharToDigit[InCharSet[i]] = i;

	// Result as big-endian bytes (most significant first)
	std::vector<uint8_t> Result = { 0 };

	// Process each digit: Result = Result * Base + Digit
	for (char Ch : InEncoded)
	{
		auto It = CharToDigit.find(Ch);
		if (It == CharToDigit.end())
			return ""; // Invalid character

		size_t Digit = It->second;

		// Multiply entire Result by BaseSize
		size_t Carry = 0;
		for (int i = Result.size() - 1; i >= 0; --i) // Right-to-left
		{
			size_t Temp = Result[i] * BaseSize + Carry;
			Result[i] = static_cast<uint8_t>(Temp & 0xFF);
			Carry = Temp >> 8;
		}
		while (Carry > 0)
		{
			Result.insert(Result.begin(), static_cast<uint8_t>(Carry & 0xFF));
			Carry >>= 8;
		}

		// Add Digit to Result
		Carry = Digit;
		for (int i = Result.size() - 1; i >= 0 && Carry > 0; --i)
		{
			size_t Temp = Result[i] + Carry;
			Result[i] = static_cast<uint8_t>(Temp & 0xFF);
			Carry = Temp >> 8;
		}
		while (Carry > 0)
		{
			Result.insert(Result.begin(), static_cast<uint8_t>(Carry & 0xFF));
			Carry >>= 8;
		}
	}

	return std::string(reinterpret_cast<const char*>(Result.data()), Result.size());
}

std::string SQRLLEncryption::ToBaseN(const std::string_view InData, const std::string_view InCharSet)
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

	// Calculate minimum length to preserve all data
	const size_t MinDigitsPerByte = static_cast<size_t>(
		std::ceil(8.0 * std::numbers::ln2 / std::log(static_cast<double>(BaseSize)))
	);
	const size_t MinOutputLength = ByteCount * MinDigitsPerByte;

	// Pad with leading zeros to ensure all data is represented
	while (Digits.size() < MinOutputLength)
	{
		Digits.push_back(0);
	}

	// Build result string (digits are in reverse order)
	std::string Result;
	Result.reserve(Digits.size());
	for (const unsigned long & Digit : std::ranges::reverse_view(Digits))
	{
		Result += InCharSet[Digit];
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

void SQRLLEncryption::FusedForwardPass(uint8_t* Data, const size_t DataSize, const uint8_t* Key,
	const size_t KeySize) noexcept
{
	if (DataSize == 0 || KeySize == 0) return;

	uint8_t Acc = Key[0];
	size_t KeyIdx = 0;

	for (size_t i = 0; i < DataSize; ++i)
	{
		uint8_t Byte = Data[i];
		const uint8_t K = Key[KeyIdx];

		// 1. In-place XOR & Bit Flip
		Byte ^= K;
		Byte = static_cast<uint8_t>(~Byte ^ (K & 0x55));

		// 2. Non-Linear ARX Diffusion (Add-Rotate-XOR)
		Acc = static_cast<uint8_t>((Acc + K + i) & 0xFF);
		const int Rot = K & 7;
		const uint8_t Rotated = static_cast<uint8_t>((Byte << Rot) | (Byte >> ((8 - Rot) & 7)));

		Data[i] = Rotated ^ Acc;

		if (++KeyIdx == KeySize) KeyIdx = 0;
	}
}

void SQRLLEncryption::FusedBackwardPass(uint8_t* Data, const size_t DataSize, const uint8_t* Key, const size_t KeySize) noexcept
{
	if (DataSize == 0 || KeySize == 0) return;

	uint8_t Acc = Key[0];
	size_t KeyIdx = 0;

	for (size_t i = 0; i < DataSize; ++i)
	{
		const uint8_t K = Key[KeyIdx];
		Acc = static_cast<uint8_t>((Acc + K + i) & 0xFF);

		// 1. Reverse Non-Linear ARX Diffusion
		const uint8_t XORed = Data[i] ^ Acc;
		const int Rot = K & 7;
		uint8_t Byte = static_cast<uint8_t>((XORed >> Rot) | (XORed << ((8 - Rot) & 7)));

		// 2. Reverse Bit Flip & XOR
		Byte = static_cast<uint8_t>(~(Byte ^ (K & 0x55)));
		Data[i] = Byte ^ K;

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

		// Rotacja bitowa zależna od klucza + nieliniowy akumulator
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

		// Odwrotna rotacja bitowa
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

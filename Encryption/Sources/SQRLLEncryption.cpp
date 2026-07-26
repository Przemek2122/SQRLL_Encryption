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

void SQRLLBitFlipping::FlipDataInPlace(uint8_t* Data, const size_t DataSize, const uint8_t* FlipKey,
	const size_t KeySize) noexcept
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

std::string SQRLLEncryption::EncryptDataCustom(const std::string& InData, const std::string& InEncryptionKey, const FEncryptionSettings& EncryptionSettings)
{
    // Fast path: skip encryption if key is too short
    if (InEncryptionKey.size() <= 16)
    {
       return InData;
    }

    const size_t KeySize = InEncryptionKey.size();
    const int32_t NumberOfIV = EncryptionSettings.RandomIVSize + static_cast<int32_t>(KeySize);
    const std::vector<uint8_t> KeyIV = GenerateRandomIV(NumberOfIV);

    // Preallocate exact memory to prevent any reallocations
    std::vector<uint8_t> InputBytes;
    const size_t BasePayloadSize = EncryptionSettings.EncryptionWord.size() + KeyIV.size() + InData.size();
    const int32_t Step = std::max(std::abs(InEncryptionKey[0] % 5), 2);

    // Reserve enough memory for the payload + random noise + 1 safe byte
    InputBytes.reserve(BasePayloadSize + (BasePayloadSize / Step) + 1);

    // Construct payload directly in the vector (Zero string concatenations)
    InputBytes.insert(InputBytes.end(), EncryptionSettings.EncryptionWord.begin(), EncryptionSettings.EncryptionWord.end());
    InputBytes.insert(InputBytes.end(), KeyIV.begin(), KeyIV.end());
    InputBytes.insert(InputBytes.end(), InData.begin(), InData.end());

    const std::vector<uint8_t> EncryptionKeyBytes(InEncryptionKey.begin(), InEncryptionKey.end());

    // 1. Reverse
    std::ranges::reverse(InputBytes.begin(), InputBytes.end());

    // 2. Add random bytes
    InputBytes = AddRandomBytes(InputBytes, InEncryptionKey);

    // 3. Shuffle
    SQRLLShuffle::Forward(InputBytes, EncryptionKeyBytes);

    // =====================================================================
    // HFT HOT PATH: Zero-Allocation Block
    // =====================================================================
    uint8_t* __restrict BufferData = InputBytes.data();
    const size_t BufferSize = InputBytes.size();
    const uint8_t* __restrict KeyData = EncryptionKeyBytes.data();

    // XOR Operations Loop
    for (int32_t i = 0; i < EncryptionSettings.NumberOfOperations; i++)
    {
       BasicXORInPlace(BufferData, BufferSize, KeyData, KeySize);
       SQRLLBitFlipping::FlipDataInPlace(BufferData, BufferSize, KeyData, KeySize);
       SQRLLXORCascade::CascadeForward(BufferData, BufferSize);
       std::reverse(BufferData, BufferData + BufferSize);
    }

    // Final Base Encryption
    BasicXORInPlace(BufferData, BufferSize, KeyData, KeySize);
    // =====================================================================

    return std::string(InputBytes.begin(), InputBytes.end());
}

std::string SQRLLEncryption::DecryptDataCustom(const std::string& InData, const std::string& InEncryptionKey, const FEncryptionSettings& EncryptionSettings)
{
    if (InEncryptionKey.size() <= 16)
    {
       return InData;
    }

    std::vector<uint8_t> InputBytes(InData.begin(), InData.end());
    const std::vector<uint8_t> EncryptionKeyBytes(InEncryptionKey.begin(), InEncryptionKey.end());
    const size_t KeySize = EncryptionKeyBytes.size();

    // =====================================================================
    // HFT HOT PATH: Zero-Allocation Block
    // =====================================================================
    uint8_t* __restrict BufferData = InputBytes.data();
    const size_t BufferSize = InputBytes.size();
    const uint8_t* __restrict KeyData = EncryptionKeyBytes.data();

    // Reverse of the Final Base Encryption
    BasicXORInPlace(BufferData, BufferSize, KeyData, KeySize);

    // Cascade XOR backward
    for (int32_t i = 0; i < EncryptionSettings.NumberOfOperations; i++)
    {
       std::reverse(BufferData, BufferData + BufferSize);
       SQRLLXORCascade::CascadeBackward(BufferData, BufferSize);
       SQRLLBitFlipping::FlipDataInPlace(BufferData, BufferSize, KeyData, KeySize);
       BasicXORInPlace(BufferData, BufferSize, KeyData, KeySize);
    }
    // =====================================================================

    // 3. Undo shuffle
    SQRLLShuffle::Backward(InputBytes, EncryptionKeyBytes);

    // 2. Remove random bytes
    InputBytes = RemoveRandomBytes(InputBytes, InEncryptionKey);

    // 1. Undo reverse
    std::ranges::reverse(InputBytes.begin(), InputBytes.end());

    // 0. Check and remove EncryptionWord and IV without mutating memory (No erase calls)
    const size_t WordSize = EncryptionSettings.EncryptionWord.size();
    const int32_t NumberOfIV = EncryptionSettings.RandomIVSize + static_cast<int32_t>(KeySize);
    const size_t TotalHeaderSize = WordSize + NumberOfIV;

    // Check if buffer is even large enough to contain headers
    if (InputBytes.size() < TotalHeaderSize)
    {
       return "";
    }

    // Verify EncryptionWord without creating substrings
    bool bIsWordValid = true;
    for (size_t i = 0; i < WordSize; ++i)
    {
       if (InputBytes[i] != static_cast<uint8_t>(EncryptionSettings.EncryptionWord[i]))
       {
          bIsWordValid = false;
          break;
       }
    }

    if (!bIsWordValid)
    {
       return "";
    }

    // Skip the header directly during string construction (O(N) instead of O(N^2))
    return std::string(InputBytes.begin() + TotalHeaderSize, InputBytes.end());
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

void SQRLLEncryption::BasicXORInPlace(uint8_t* Data, const size_t DataSize, const uint8_t* Key, const size_t KeySize)
{
	if (DataSize == 0 || KeySize == 0) return;

	size_t KeyIndex = 0;
	for (size_t i = 0; i < DataSize; ++i)
	{
		Data[i] ^= Key[KeyIndex];

		// Branchless wrap-around instead of slow modulo (%)
		if (++KeyIndex == KeySize)
		{
			KeyIndex = 0;
		}
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

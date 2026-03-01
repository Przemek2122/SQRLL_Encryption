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

void SQRLLXORCascade::CascadeForward(std::vector<uint8_t>& Data)
{
	for (size_t i = 1; i < Data.size(); ++i)
	{
		Data[i] ^= Data[i - 1];
	}
}

void SQRLLXORCascade::CascadeBackward(std::vector<uint8_t>& Data)
{
	for (size_t i = Data.size() - 1; i > 0; --i)
	{
		Data[i] ^= Data[i - 1];
	}
}

void SQRLLXORCascade::FullDiffusion(std::vector<uint8_t>& Data, int Rounds)
{
	for (int Round = 0; Round < Rounds; ++Round)
	{
		// W prawo
		CascadeForward(Data);

		// Rotate
		std::rotate(Data.begin(), Data.begin() + 1, Data.end());

		// W lewo  
		CascadeBackward(Data);

		// Rotate z powrotem
		std::rotate(Data.rbegin(), Data.rbegin() + 1, Data.rend());
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

void SQRLLShuffle::Forward(std::vector<uint8_t>& InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes)
{
	if (InputBytes.empty() || EncryptionKeyBytes.empty())
	{
		return;
	}

	// Generate seed from key
	uint64_t Seed = GenerateSeed(EncryptionKeyBytes);

	// Shuffle bytes deterministically
	std::mt19937_64 Rng(Seed);
	std::shuffle(InputBytes.begin(), InputBytes.end(), Rng);
}

void SQRLLShuffle::Backward(std::vector<uint8_t>& InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes)
{
	if (InputBytes.empty() || EncryptionKeyBytes.empty())
	{
		return;
	}

	// Generate same seed from key
	uint64_t Seed = GenerateSeed(EncryptionKeyBytes);

	// Recreate the shuffle permutation
	std::vector<size_t> Indices(InputBytes.size());
	std::iota(Indices.begin(), Indices.end(), 0);

	std::mt19937_64 Rng(Seed);
	std::shuffle(Indices.begin(), Indices.end(), Rng);

	// Create inverse permutation
	std::vector<size_t> InverseIndices(InputBytes.size());
	for (size_t i = 0; i < Indices.size(); ++i)
	{
		InverseIndices[Indices[i]] = i;
	}

	// Apply inverse permutation to restore original order
	std::vector<uint8_t> Result(InputBytes.size());
	for (size_t i = 0; i < InputBytes.size(); ++i)
	{
		Result[i] = InputBytes[InverseIndices[i]];
	}

	InputBytes = Result;
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
	std::random_device rd;  // Hardware entropy
	std::mt19937 gen(rd()); // Seed with hardware randomness
	std::uniform_int_distribution<int> dis(0, UINT8_MAX);

	std::string salt(Length, '\0');
	for (size_t i = 0; i < Length; ++i) {
		salt[i] = static_cast<char>(dis(gen));
	}

	return salt;
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
	std::string Out = InData;

	if (InEncryptionKey.size() > 16)
	{
		const int32_t NumberOfIV = EncryptionSettings.RandomIVSize + static_cast<int32_t>(InEncryptionKey.size());
		const std::vector<uint8_t> KeyIV = GenerateRandomIV(NumberOfIV);

		// 0 Add EncryptionWord and IV
		Out = EncryptionSettings.EncryptionWord + BytesToString(KeyIV) + Out;

		std::vector<uint8_t> InputBytes = StringToBytes(Out);
		const std::vector<uint8_t> EncryptionKeyBytes = StringToBytes(InEncryptionKey);

		// 1. Reverse
		std::ranges::reverse(InputBytes.begin(), InputBytes.end());

		// 2. Add random bytes
		InputBytes = AddRandomBytes(InputBytes, InEncryptionKey);

		// 3. Let's do some shuffle
		SQRLLShuffle::Forward(InputBytes, EncryptionKeyBytes);

		// XOR Operations
		for (int32_t i = 0; i < EncryptionSettings.NumberOfOperations; i++)
		{
			// Base encryption
			InputBytes = BasicEncryptionWork(InputBytes, EncryptionKeyBytes);

			SQRLLBitFlipping::FlipData(InputBytes, EncryptionKeyBytes);
			SQRLLXORCascade::CascadeForward(InputBytes);
			std::ranges::reverse(InputBytes.begin(), InputBytes.end());
		}

		InputBytes = BasicEncryptionWork(InputBytes, EncryptionKeyBytes);

		Out = BytesToString(InputBytes);
	}

	return Out;
}

std::string SQRLLEncryption::DecryptDataCustom(const std::string& InData, const std::string& InEncryptionKey, const FEncryptionSettings& EncryptionSettings)
{
	std::string Out = InData;

	if (InEncryptionKey.size() > 16)
	{
		std::vector<uint8_t> InputBytes = StringToBytes(Out);
		const std::vector<uint8_t> EncryptionKeyBytes = StringToBytes(InEncryptionKey);

		// Cascade XOR backward
		for (int32_t i = 0; i < EncryptionSettings.NumberOfOperations; i++)
		{
			std::ranges::reverse(InputBytes.begin(), InputBytes.end());
			SQRLLXORCascade::CascadeBackward(InputBytes);
			SQRLLBitFlipping::FlipData(InputBytes, EncryptionKeyBytes);

			// Base decryption
			InputBytes = BasicDecryptionWork(InputBytes, EncryptionKeyBytes);
		}

		// 3. Let's undo shuffle
		SQRLLShuffle::Backward(InputBytes, EncryptionKeyBytes);

		// 2. Remove random bytes
		InputBytes = RemoveRandomBytes(InputBytes, InEncryptionKey);

		// 1. Reverse
		std::ranges::reverse(InputBytes.begin(), InputBytes.end());

		// 0. Check and remove EncryptionWord and IV
		Out = BytesToString(InputBytes);
		size_t SearchResult = Out.find(EncryptionSettings.EncryptionWord);
		if (SearchResult != std::string::npos)
		{
			const std::string PotentialEncryptionWord = Out.substr(SearchResult, EncryptionSettings.EncryptionWord.size());
			Out.erase(SearchResult, EncryptionSettings.EncryptionWord.size());
			if (PotentialEncryptionWord == EncryptionSettings.EncryptionWord)
			{
				const int32_t NumberOfIV = EncryptionSettings.RandomIVSize + static_cast<int32_t>(InEncryptionKey.size());

				// Remove IV
				Out.erase(0, NumberOfIV);
			}
			else
			{
				Out = "";
			}
		}
		else
		{
			Out = "";
		}
	}

	return Out;
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

std::vector<uint8_t> SQRLLEncryption::BasicEncryptionWork(const std::vector<uint8_t>& InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes)
{
	std::vector<uint8_t> OutBytes;

	for (int32_t InputBytesIndex = 0; InputBytesIndex < static_cast<int32_t>(InputBytes.size()); InputBytesIndex++)
	{
		const int32_t EncryptionBytesIndex = InputBytesIndex % static_cast<int32_t>(EncryptionKeyBytes.size());

		int32_t Result = static_cast<int32_t>(InputBytes[InputBytesIndex]);

		Result = Result ^ static_cast<int32_t>(EncryptionKeyBytes[EncryptionBytesIndex]);

		OutBytes.push_back(static_cast<uint8_t>(InputBytes[InputBytesIndex]));
	}

	return OutBytes;
}

std::vector<uint8_t> SQRLLEncryption::BasicDecryptionWork(std::vector<uint8_t> InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes)
{
	std::vector<uint8_t> OutBytes;

	for (int32_t InputBytesIndex = 0; InputBytesIndex < static_cast<int32_t>(InputBytes.size()); InputBytesIndex++)
	{
		const int32_t EncryptionBytesIndex = InputBytesIndex % static_cast<int32_t>(EncryptionKeyBytes.size());

		int32_t Result = static_cast<int32_t>(InputBytes[InputBytesIndex]);

		Result = Result ^ static_cast<int32_t>(EncryptionKeyBytes[EncryptionBytesIndex]);

		OutBytes.push_back(static_cast<uint8_t>(InputBytes[InputBytesIndex]));
	}

	return OutBytes;
}

std::vector<uint8_t> SQRLLEncryption::AddRandomBytes(const std::vector<uint8_t>& InputBytes, const std::string& InEncryptionKey)
{
	std::vector<uint8_t> OutBytes = InputBytes;

	const int32_t WhereAddRandom = std::max(abs(InEncryptionKey[0] % 5), 2);
	for (int32_t i = WhereAddRandom; i < static_cast<int32_t>(OutBytes.size()); i += WhereAddRandom + 1)
	{
		const uint8_t RandomInt = static_cast<uint8_t>(NormalizeByte((InEncryptionKey[i % InEncryptionKey.size()] ^ i) + static_cast<int32_t>(InEncryptionKey[i % InEncryptionKey.size()]) + static_cast<int32_t>(InEncryptionKey[WhereAddRandom])));
		OutBytes.insert(OutBytes.begin() + i, RandomInt);
	}

	return OutBytes;
}

std::vector<uint8_t> SQRLLEncryption::RemoveRandomBytes(const std::vector<uint8_t>& InputBytes, const std::string& InEncryptionKey)
{
	std::vector<uint8_t> OutBytes = InputBytes;

	const int32_t WhereAddRandom = std::max(abs(InEncryptionKey[0] % 5), 2);
	for (int32_t i = WhereAddRandom; i < static_cast<int32_t>(OutBytes.size()); i += WhereAddRandom)
	{
		OutBytes.erase(OutBytes.begin() + i);
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

std::vector<uint8_t> SQRLLEncryption::GenerateRandomIV(size_t Size)
{
	std::vector<uint8_t> RandomIV(Size);
	std::random_device Rd;
	std::mt19937 Gen(Rd());
	std::uniform_int_distribution<> Dist(0, 255);

	for (uint8_t& Byte : RandomIV)
	{
		Byte = static_cast<uint8_t>(Dist(Gen));
	}
	return RandomIV;
}

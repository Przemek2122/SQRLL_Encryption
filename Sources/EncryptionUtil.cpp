// Created by https://www.linkedin.com/in/przemek2122/ 2026

#include "EncryptionUtil.h"
#include <unordered_set>
#include <algorithm>

FHuffmanNode::FHuffmanNode(uint8_t D, uint32_t F)
	: Data(D)
	, Frequency(F)
	, Left(nullptr)
	, Right(nullptr)
{
}

FHuffmanNode::~FHuffmanNode()
{
	delete Left;
	delete Right;
}

std::vector<uint8_t> FHuffmanCompressor::Compress(const std::vector<uint8_t>& Input)
{
	if (Input.empty()) return {};

	std::map<uint8_t, uint32_t> Frequencies;
	for (uint8_t Byte : Input)
	{
		Frequencies[Byte]++;
	}

	auto Compare = [](FHuffmanNode* A, FHuffmanNode* B)
	{
		return A->Frequency > B->Frequency;
	};
	std::priority_queue<FHuffmanNode*, std::vector<FHuffmanNode*>, decltype(Compare)> Queue(Compare);

	for (auto& Pair : Frequencies)
	{
		Queue.push(new FHuffmanNode(Pair.first, Pair.second));
	}

	while (Queue.size() > 1)
	{
		FHuffmanNode* Left = Queue.top(); Queue.pop();
		FHuffmanNode* Right = Queue.top(); Queue.pop();

		FHuffmanNode* Parent = new FHuffmanNode(0, Left->Frequency + Right->Frequency);
		Parent->Left = Left;
		Parent->Right = Right;
		Queue.push(Parent);
	}

	FHuffmanNode* Root = Queue.top();

	std::map<uint8_t, std::string> Codes;
	FHuffmanCompressor::GenerateCodes(Root, "", Codes);

	std::string BitString;
	for (uint8_t Byte : Input)
	{
		BitString += Codes[Byte];
	}

	std::vector<uint8_t> Compressed;

	Compressed.push_back(static_cast<uint8_t>(Frequencies.size()));
	for (auto& Pair : Frequencies)
	{
		Compressed.push_back(Pair.first);

		for (int i = 0; i < 4; ++i) {
			Compressed.push_back((Pair.second >> (i * 8)) & 0xFF);
		}
	}

	uint32_t BitCount = BitString.size();
	for (int i = 0; i < 4; ++i)
	{
		Compressed.push_back((BitCount >> (i * 8)) & 0xFF);
	}

	for (size_t i = 0; i < BitString.size(); i += 8)
	{
		uint8_t Byte = 0;
		for (int j = 0; j < 8 && i + j < BitString.size(); ++j)
		{
			if (BitString[i + j] == '1')
			{
				Byte |= (1 << (7 - j));
			}
		}
		Compressed.push_back(Byte);
	}

	delete Root;
	return Compressed;
}

std::vector<uint8_t> FHuffmanCompressor::Decompress(const std::vector<uint8_t>& Compressed)
{
	size_t Pos = 0;

	uint8_t TableSize = Compressed[Pos++];
	std::map<uint8_t, uint32_t> Frequencies;

	for (uint8_t i = 0; i < TableSize; ++i)
	{
		uint8_t Byte = Compressed[Pos++];
		uint32_t Freq = 0;
		for (int j = 0; j < 4; ++j)
		{
			Freq |= (static_cast<uint32_t>(Compressed[Pos++]) << (j * 8));
		}
		Frequencies[Byte] = Freq;
	}

	uint32_t BitCount = 0;
	for (int i = 0; i < 4; ++i)
	{
		BitCount |= (static_cast<uint32_t>(Compressed[Pos++]) << (i * 8));
	}

	auto Compare = [](FHuffmanNode* A, FHuffmanNode* B)
	{
		return A->Frequency > B->Frequency;
	};
	std::priority_queue<FHuffmanNode*, std::vector<FHuffmanNode*>, decltype(Compare)> Queue(Compare);

	for (auto& Pair : Frequencies)
	{
		Queue.push(new FHuffmanNode(Pair.first, Pair.second));
	}

	while (Queue.size() > 1)
	{
		FHuffmanNode* Left = Queue.top(); Queue.pop();
		FHuffmanNode* Right = Queue.top(); Queue.pop();

		FHuffmanNode* Parent = new FHuffmanNode(0, Left->Frequency + Right->Frequency);
		Parent->Left = Left;
		Parent->Right = Right;
		Queue.push(Parent);
	}

	FHuffmanNode* Root = Queue.top();

	std::vector<uint8_t> Decompressed;
	FHuffmanNode* Current = Root;
	uint32_t BitIndex = 0;

	while (BitIndex < BitCount)
	{
		uint8_t Byte = Compressed[Pos + BitIndex / 8];
		bool Bit = (Byte >> (7 - (BitIndex % 8))) & 1;

		Current = Bit ? Current->Right : Current->Left;

		if (!Current->Left && !Current->Right)
		{
			Decompressed.push_back(Current->Data);
			Current = Root;
		}

		BitIndex++;
	}

	delete Root;
	return Decompressed;
}

void FHuffmanCompressor::GenerateCodes(FHuffmanNode* Node, std::string Code, std::map<uint8_t, std::string>& Codes)
{
	if (!Node) return;

	if (!Node->Left && !Node->Right)
	{
		Codes[Node->Data] = Code.empty() ? "0" : Code;
		return;
	}

	GenerateCodes(Node->Left, Code + "0", Codes);
	GenerateCodes(Node->Right, Code + "1", Codes);
}

void FXORCascade::CascadeForward(std::vector<uint8_t>& Data)
{
	for (size_t i = 1; i < Data.size(); ++i)
	{
		Data[i] ^= Data[i - 1];
	}
}

void FXORCascade::CascadeBackward(std::vector<uint8_t>& Data)
{
	for (size_t i = Data.size() - 1; i > 0; --i)
	{
		Data[i] ^= Data[i - 1];
	}
}

void FXORCascade::FullDiffusion(std::vector<uint8_t>& Data, int Rounds)
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

uint8_t FBitRotation::RotateLeft(uint8_t Value, int Bits)
{
	return (Value << Bits) | (Value >> (8 - Bits));
}

uint8_t FBitRotation::RotateRight(uint8_t Value, int Bits)
{
	return (Value >> Bits) | (Value << (8 - Bits));
}

void FBitRotation::RotateDependingOnKey(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key)
{
	for (size_t i = 0; i < Data.size(); ++i)
	{
		int RotAmount = Key[i % Key.size()] % 8;
		Data[i] = RotateLeft(Data[i], RotAmount);
	}
}

void FBitRotation::UnrotateDependingOnKey(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key)
{
	for (size_t i = 0; i < Data.size(); ++i)
	{
		int RotAmount = Key[i % Key.size()] % 8;
		Data[i] = RotateRight(Data[i], RotAmount);
	}
}

std::vector<uint64_t> FPredefinedXORMasks::GetEightMasks()
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

Uint64 FBitFlipping::FlipBits(uint64_t InValue, const Uint64 FlipMask)
{
	// XOR mask: alternating bit pattern for reproducible flipping
	return InValue ^ FlipMask;
}

std::vector<uint8_t> FBitFlipping::FlipData(const std::vector<uint8_t>& InFlipData, const std::vector<uint8_t>& FlipKey)
{
	std::vector<uint8_t> OutData;
	std::vector<uint64_t> Masks = FPredefinedXORMasks::GetEightMasks();

	std::vector<uint64_t> InFlipData64Array = FChunkConverter::BytesToChunks(InFlipData);
	std::vector<uint64_t> FlipKey64Array = FChunkConverter::BytesToChunks(FlipKey);

	if (Masks.size() == 8)
	{
		for (uint32 i = 0; i < InFlipData64Array.size(); i++)
		{
			uint64_t FlipData64 = InFlipData64Array[i];
			const uint64_t& FlipKeyData64 = FlipKey64Array[i % FlipKey.size()];

			InFlipData64Array[i] = FlipBits(FlipData64, Masks[FlipKeyData64 % 8]);
		}
	}

	OutData = FChunkConverter::ChunksToBytes(InFlipData64Array, InFlipData.size());

	return OutData;
}

void FShuffle::Forward(std::vector<uint8_t>& InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes)
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

void FShuffle::Backward(std::vector<uint8_t>& InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes)
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

uint64_t FShuffle::GenerateSeed(const std::vector<uint8_t>& EncryptionKeyBytes)
{
	uint64_t Seed = 5381; // DJB2 hash initial value

	for (uint8_t Byte : EncryptionKeyBytes)
	{
		Seed = ((Seed << 5) + Seed) + Byte; // Hash = Hash * 33 + Byte
	}

	return Seed;
}

void FFeistelCipher::FeistelRound(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key, int Round)
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

void FFeistelCipher::Encrypt(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key)
{
	for (int Round = 0; Round < 4; ++Round)
	{
		FeistelRound(Data, Key, Round);
	}
}

void FFeistelCipher::Decrypt(std::vector<uint8_t>& Data, const std::vector<uint8_t>& Key)
{
	for (int Round = 3; Round >= 0; --Round)
	{
		FeistelRound(Data, Key, Round);
	}
}

std::vector<uint8_t> FFeistelCipher::FFunction(const std::vector<uint8_t>& Input, const std::vector<uint8_t>& Key,
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

uint8_t FFeistelCipher::RotateLeft(uint8_t Value, int Bits)
{
	Bits %= 8;
	return (Value << Bits) | (Value >> (8 - Bits));
}

std::string FEncryptionUtil::GenerateSecureSalt(const size_t Length)
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

std::string FEncryptionUtil::EncryptDataCustom(const std::string& InData, const std::string& InEncryptionKey, const FEncryptionSettings& EncryptionSettings)
{
	std::string Out = InData;

	if (InEncryptionKey.size() > 16)
	{
		const int32 NumberOfIV = EncryptionSettings.RandomIVSize + static_cast<int32>(InEncryptionKey.size());
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
		FShuffle::Forward(InputBytes, EncryptionKeyBytes);

		// XOR Operations
		for (int32 i = 0; i < EncryptionSettings.NumberOfOperations; i++)
		{
			// Base encryption
			InputBytes = BasicEncryptionWork(InputBytes, EncryptionKeyBytes);

			FBitFlipping::FlipData(InputBytes, EncryptionKeyBytes);
			FXORCascade::CascadeForward(InputBytes);
			std::ranges::reverse(InputBytes.begin(), InputBytes.end());
		}

		InputBytes = BasicEncryptionWork(InputBytes, EncryptionKeyBytes);

		Out = BytesToString(InputBytes);
	}

	return Out;
}

std::string FEncryptionUtil::DecryptDataCustom(const std::string& InData, const std::string& InEncryptionKey, const FEncryptionSettings& EncryptionSettings)
{
	std::string Out = InData;

	if (InEncryptionKey.size() > 16)
	{
		std::vector<uint8_t> InputBytes = StringToBytes(Out);
		const std::vector<uint8_t> EncryptionKeyBytes = StringToBytes(InEncryptionKey);

		// Cascade XOR backward
		for (int32 i = 0; i < EncryptionSettings.NumberOfOperations; i++)
		{
			std::ranges::reverse(InputBytes.begin(), InputBytes.end());
			FXORCascade::CascadeBackward(InputBytes);
			FBitFlipping::FlipData(InputBytes, EncryptionKeyBytes);

			// Base decryption
			InputBytes = BasicDecryptionWork(InputBytes, EncryptionKeyBytes);
		}

		// 3. Let's undo shuffle
		FShuffle::Backward(InputBytes, EncryptionKeyBytes);

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
				const int32 NumberOfIV = EncryptionSettings.RandomIVSize + static_cast<int32>(InEncryptionKey.size());

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

Uint64 FEncryptionUtil::ConvertCharsIntoInt(char InCharArray[8])
{
	Uint64 Result;
	memcpy(&Result, InCharArray, 8);
	return Result;
}

std::array<char, 8> FEncryptionUtil::ConvertIntIntoChars(const Uint64 InData)
{
	std::array<char, 8> Result;
	memcpy(Result.data(), &InData, 8);
	return Result;
}

std::string FEncryptionUtil::FromBaseN(std::string_view InEncoded, std::string_view InCharSet)
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

std::string FEncryptionUtil::ToBaseN(const std::string_view InData, const std::string_view InCharSet)
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
	for (auto it = Digits.rbegin(); it != Digits.rend(); ++it)
	{
		Result += InCharSet[*it];
	}

	return Result;
}

std::string FEncryptionUtil::ToBaseN_Irreversible(const std::string_view InData, const std::string_view InCharSet)
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

std::string FEncryptionUtil::ToBaseNNum(uintmax_t InNumber, const std::string_view InCharSet)
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

uintmax_t FEncryptionUtil::FromBaseNNum(const std::string_view InEncoded, const std::string_view InCharSet)
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

std::vector<uint8_t> FEncryptionUtil::BasicEncryptionWork(std::vector<uint8_t> InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes)
{
	std::vector<uint8_t> OutBytes;

	for (int32 InputBytesIndex = 0; InputBytesIndex < static_cast<int32>(InputBytes.size()); InputBytesIndex++)
	{
		const int32 EncryptionBytesIndex = InputBytesIndex % static_cast<int32>(EncryptionKeyBytes.size());

		int32 Result = static_cast<int32>(InputBytes[InputBytesIndex]);

		Result = Result ^ static_cast<int32>(EncryptionKeyBytes[EncryptionBytesIndex]);

		OutBytes.push_back(static_cast<uint8_t>(InputBytes[InputBytesIndex]));
	}

	return OutBytes;
}

std::vector<uint8_t> FEncryptionUtil::BasicDecryptionWork(std::vector<uint8_t> InputBytes, const std::vector<uint8_t>& EncryptionKeyBytes)
{
	std::vector<uint8_t> OutBytes;

	for (int32 InputBytesIndex = 0; InputBytesIndex < static_cast<int32>(InputBytes.size()); InputBytesIndex++)
	{
		const int32 EncryptionBytesIndex = InputBytesIndex % static_cast<int32>(EncryptionKeyBytes.size());

		int32 Result = static_cast<int32>(InputBytes[InputBytesIndex]);

		Result = Result ^ static_cast<int32>(EncryptionKeyBytes[EncryptionBytesIndex]);

		OutBytes.push_back(static_cast<uint8_t>(InputBytes[InputBytesIndex]));
	}

	return OutBytes;
}

std::vector<uint8_t> FEncryptionUtil::AddRandomBytes(const std::vector<uint8_t>& InputBytes, const std::string& InEncryptionKey)
{
	std::vector<uint8_t> OutBytes = InputBytes;

	const int32 WhereAddRandom = FMath::Max(FMath::Abs(InEncryptionKey[0] % 5), 2);
	for (int32 i = WhereAddRandom; i < static_cast<int32>(OutBytes.size()); i += WhereAddRandom + 1)
	{
		const uint8_t RandomInt = static_cast<uint8_t>(NormalizeByte((InEncryptionKey[i % InEncryptionKey.size()] ^ i) + static_cast<int32>(InEncryptionKey[i % InEncryptionKey.size()]) + static_cast<int32>(InEncryptionKey[WhereAddRandom])));
		OutBytes.insert(OutBytes.begin() + i, RandomInt);
	}

	return OutBytes;
}

std::vector<uint8_t> FEncryptionUtil::RemoveRandomBytes(const std::vector<uint8_t>& InputBytes, const std::string& InEncryptionKey)
{
	std::vector<uint8_t> OutBytes = InputBytes;

	const int32 WhereAddRandom = FMath::Max(FMath::Abs(InEncryptionKey[0] % 5), 2);
	for (int32 i = WhereAddRandom; i < static_cast<int32>(OutBytes.size()); i += WhereAddRandom)
	{
		OutBytes.erase(OutBytes.begin() + i);
	}

	return OutBytes;
}

std::vector<uint8_t> FEncryptionUtil::StringToBytes(const std::string& Str)
{
	return { Str.begin(), Str.end() };
}

std::string FEncryptionUtil::BytesToString(const std::vector<uint8_t>& Bytes)
{
	return { Bytes.begin(), Bytes.end() };
}

int32 FEncryptionUtil::NormalizeByte(int32 InChar)
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

std::vector<uint8_t> FEncryptionUtil::GenerateRandomIV(size_t Size)
{
	std::vector<uint8_t> RandomIV(Size);
	std::random_device Rd;
	std::mt19937 Gen(Rd());
	std::uniform_int_distribution<> Dist(0, 255);

	for (auto& Byte : RandomIV)
	{
		Byte = static_cast<uint8_t>(Dist(Gen));
	}
	return RandomIV;
}

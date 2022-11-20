#include <set>
#include <vector>
#include <algorithm>  
#include <map>
#include <random>

#include <time.h>
#include <Zydis/Zydis.h>
#include "xPE/xPE.h"

// I've to define _NO_CVCONST_H to be able to access 
// various declarations from DbgHelp.h, which are not available by default 
#define _NO_CVCONST_H
#include <dbghelp.h>
#pragma comment(lib, "dbghelp.lib")

// supported CodeView tables
// for pdb parsing
struct _RSDSI {
	// RSDSI table
	DWORD   dwSig;
	GUID    guidSig;
	DWORD   age;
	char    szPdb[_MAX_PATH * 3];
};
struct _NB10I {
	// NB10I table
	DWORD   dwSig;
	DWORD   dwOffset;
	DWORD   sig;
	DWORD   age;
	char    szPdb[_MAX_PATH];
};

// pdb function symbols array
std::vector<ZyanU64> PdbFunVAs;

std::vector<std::pair<ZyanU64, std::pair<BOOL,
	std::vector<std::pair<ZyanU64, DWORD>>>>> Branches;
//map_of:
//	- branch_base_address
//	- pair_of:
//		- is_branch_finished
//		- map_of:
//			- instruction_address
//			- decoding_key_if_exists

std::vector<BYTE> xObfSectionData;
//holds the whole data of the new section

struct _LastReturn {
	BOOL HasValue;			// if LastValue/LastValueOffset are valid
	DWORD LastValue;		// the return address of the previous instruction
	DWORD LastValueOffset;		// the offset where this address is stored
};
//the decoding key for each instruction is actually the return address
//of the previous instruction block, and it will be written once the previous
//instruction is executed, so all of the hooked instructions should be
//executed in a pre-defined path, like a hook chain, you cannot set the R/E/IP
//to point to some instruction without executing the previous instructions
//in its chain

struct _HookState {
	_LastReturn DecodeKey;			// the key that will be used globally
									// for all of the instruction in case
	_HookState()
	{
		DecodeKey.HasValue = FALSE;
		DecodeKey.LastValue = 0;
		DecodeKey.LastValueOffset = 0;
	};
};
//the concept of the hook chain is not applicable for all of the instructions
//because in so many cases (like branching) one instruction can be accessed
//from within two paths (like a node), so in this case the chain is broken
//and a global decoding key is used and its value will be the return of
//the last instruction at the root-chain (tls-callbacks/entrypoint)

INT main(INT argc, PCHAR* argv)
{
	// initialization of colors/std(out/err) handles
	if (!Utils::InitUtils())
	{
		Utils::Printf::Fail("Cannot initialize properly");
		return FALSE;
	};

	if (argc < 3)
	{
		// printing the usage
		Utils::Printf::Info(
			"xObf v0.0 (https://github.com/d35ha/xObf)\n"
			"A basic instruction level obfuscator\n"
			"Usage: xObf <Options> -i [PE_File] -o [Out_PE_File]\n"
			"Options:\n"
			"    -v: verbous mode\n"
			"Examples:\n"
			"    xObf -v -i evil_exe.exe -o obf_evil_exe.exe\n"
			"    xObf -v -i evil_dll.dll -o obf_evil_dll.dll\n"
		);
		return FALSE;
	};

	// definition of global parameters
	LPCSTR InPE = NULL, OutPE = NULL;
	BOOL IsVerbous = FALSE;
	// seeding
	std::random_device dev;
	std::mt19937 rng(dev());
	std::uniform_int_distribution<std::mt19937::result_type> dist(0, 0xffffffff);

	// parsing the arguments
	for (DWORD dwParamIndex = 1; dwParamIndex < (DWORD)argc; dwParamIndex++)
	{
		if (!strcmp(argv[dwParamIndex], "-i")) {
			// input PE switch
			if (InPE) {
				Utils::Printf::Fail("PE_File switch already used with '%s'", InPE);
				return FALSE;
			}
			if (++dwParamIndex == argc) {
				Utils::Printf::Fail("Switch -c needs a valid path");
				return FALSE;
			};
			InPE = argv[dwParamIndex];
		}
		else if (!strcmp(argv[dwParamIndex], "-o")) {
			// output PE switch
			if (OutPE) {
				Utils::Printf::Fail("Out_PE_File switch already used with '%s'", OutPE);
				return FALSE;
			};
			if (++dwParamIndex == argc) {
				Utils::Printf::Fail("Switch -o needs a valid path");
				return FALSE;
			};
			OutPE = argv[dwParamIndex];
		}
		else if (!strcmp(argv[dwParamIndex], "-v"))
		{
			// verbose mode switch
			if (IsVerbous) {
				Utils::Printf::Fail("Verbous switch already used");
				return FALSE;
			};
			IsVerbous = TRUE;
		}
		else {
			Utils::Printf::Fail("Unknown switch %s", argv[dwParamIndex]);
			return FALSE;
		};
	};

	// checking if the parameters are valid and enough
	if (!OutPE || !InPE) {
		Utils::Printf::Fail("The input PE file and the Output PE file should be supplied");
		return FALSE;
	};

	// holds a pointer to the PE buffer,
	// its length, path and a file handle
	RAW_FILE_INFO RawPE = { 0 };
	if (!Load::File::Load(
		InPE,
		&RawPE,
		sizeof(RAW_FILE_INFO)
	))
	{
		Utils::Printf::Fail("Cannot load this PE");
		return FALSE;
	};

	DWORD dwArch = x32;
	if (!Load::PE::GetArch(
		&RawPE,
		&dwArch
	))
	{
		Utils::Printf::Fail("Unable to get the architecture of this PE file");
		return FALSE;
	};

	// Change the target CPU to build for both architectures
#if defined(_M_X64) || defined(__amd64__)
	if (dwArch == x32)
	{
		Utils::Printf::Fail("Use the x32 binary to handle this PE file");
		return FALSE;
	};
#else
	if (dwArch == x64)
	{
		Utils::Printf::Fail("Use the x64 binary to handle this PE file");
		return FALSE;
	};
#endif

	// creating a new rwx section to hold the blocks that will build/execute the
	// real instructions
	BYTE bNtHeaders[sizeof(IMAGE_NT_HEADERS)] = { 0 };
	PIMAGE_NT_HEADERS lpNtHeader = (PIMAGE_NT_HEADERS)bNtHeaders;
	if (!Load::PE::GetNtHeader(
		&RawPE,
		&lpNtHeader
	))
	{
		Utils::Printf::Fail("Cannot read the NT headers");
		return FALSE;
	};

	PIMAGE_SECTION_HEADER lpImageSectionHeader = IMAGE_FIRST_SECTION(lpNtHeader);
	PIMAGE_SECTION_HEADER lpNewSectionHeader = &lpImageSectionHeader[lpNtHeader->FileHeader.NumberOfSections];

	if ((DWORD)((DWORD_PTR)lpNewSectionHeader + sizeof(IMAGE_SECTION_HEADER) - (DWORD_PTR)RawPE.lpDataBuffer)
	> lpImageSectionHeader->PointerToRawData)
	{
		// in this case there's no way to create it
		// you may change the headers size while compiling the PE
		Utils::Printf::Fail("No enough space at the headers for the new section");
		return FALSE;
	};

	ZeroMemory(
		lpNewSectionHeader,
		sizeof(IMAGE_SECTION_HEADER)
	);

	lpNewSectionHeader->VirtualAddress = lpNtHeader->OptionalHeader.SizeOfImage;
	lpNewSectionHeader->PointerToRawData = lpImageSectionHeader[lpNtHeader->FileHeader.NumberOfSections - 1].PointerToRawData
		+ lpImageSectionHeader[lpNtHeader->FileHeader.NumberOfSections - 1].SizeOfRawData;
	lpNtHeader->FileHeader.NumberOfSections++;

	// the new section should be rwx because the instructions' blocks will
	// write the decoded instruction at the same section and execute it
	lpNewSectionHeader->Characteristics =
		IMAGE_SCN_MEM_EXECUTE |
		IMAGE_SCN_MEM_READ |
		IMAGE_SCN_MEM_WRITE;

	// the new section name is ".xObf" to help recognizing the obfuscator
	// you may change it as you want
	memmove(
		lpNewSectionHeader->Name,
		".xObf",
		sizeof(".xObf")
	);

	// initializing the disassembler
	// zydis is the most perfect one for me, it's fast, reliable and is
	// used at my favorite tool ever x64dbg
	ZydisDecoder ZyDecoder;
#if defined(_M_X64) || defined(__amd64__)
	ZydisDecoderInit(
		&ZyDecoder,
		ZYDIS_MACHINE_MODE_LONG_64,
		ZYDIS_ADDRESS_WIDTH_64
	);
#else
	ZydisDecoderInit(
		&ZyDecoder,
		ZYDIS_MACHINE_MODE_LEGACY_32,
		ZYDIS_ADDRESS_WIDTH_32
	);
#endif

	// of course not all of the instructions are obfuscated
	// only instructions that is long enough to hold a relative
	// call instruction, so if the length is bigger than 4, the
	// instruction is replaced by a call to its block at the new
	// section to be decoded and executed
	// if the length is bigger than 5 the call instruction is padded
	// with junk bytes (this really misses up with any static analysis engines)
	BYTE CallInst[] = {
		0xE8, 0x00, 0x00, 0x00, 0x00,
		0x90, 0x90, 0x90, 0x90, 0x90,
		0x90, 0x90, 0x90, 0x90, 0x90
	};
	
#if defined(_M_X64) || defined(__amd64__)
	// when the call instruction is padded with junk bytes, its return
	// address will point to an invalid instruction, so the return address
	// should be modified so the block will return properly to the real next instruction
	// a lea instruction is used to do so
	// this also exploits the "step over" at any debugger, that because the debugger
	// when invoking "step over" uses a bp at the next instruction to stop the execution
	// but in our case the next instruction is just junk bytes and the block will
	// return to the real next instruction by increasing the return address
	// and the bp will be never hit so a "step over" will be converted to "run" which is really bad
	BYTE LeaInstruction[] = {
		0x48, 0x8D, 0x40, 0x00 // lea rax, [rax + length_difference]
	};
	// the outside block that represents each hooked instruction
	// it will save the return address by moving it to be
	// mov rax, return_address
	// at this offset the return address is used as a key to decode the next
	// hooked instruction, so the current instruction has to be executed to
	// decode the next instruction
	BYTE ObfuscatedBlock[] = {
		0x8F, 0x05,
#define RET_ADDRESS_OFFSET 2 // the offset will be increased by the size of the inside block
		0x02, 0x00, 0x00, 0x00, // pop [RANDOM_BYTES_OFFSET]
#define OBF_INSTRUCTION_OFFSET 6 // the inside block will be inserted here
#define	OBF_VALUE_OFFSET 7 // offset of the key getting instruction inside the inside block
		0x48, 0xb8,
#define RANDOM_BYTES_OFFSET 8 // will be filled with the return address after the instruction 
		// is executed and will be used as a key_ptr for the next instruction
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, // mov rax, random_qword
#define LENGTH_DIFF_OFFSET 16 // lea instruction may be added here if the real instruction size > 5
		0x48, 0x87, 0x04, 0x24, // xchg rax, [rsp]
		0xC3 // ret
	};
#else
	BYTE LeaInstruction[] = {
		0x8D, 0x40, 0x00 // lea eax, [eax + length_difference]
	};
	BYTE ObfuscatedBlock[] = {
		0x8F, 0x05,
#define RET_ADDRESS_OFFSET 2
		0x00, 0x00, 0x00, 0x00, // pop [RANDOM_BYTES_OFFSET]
#define OBF_INSTRUCTION_OFFSET 6
#define	OBF_VALUE_OFFSET 7
		0xb8,
#define RANDOM_BYTES_OFFSET 7
		0x00, 0x00, 0x00, 0x00, // mov eax, random_dword
#define LENGTH_DIFF_OFFSET 11
		0x87, 0x04, 0x24, // xchg eax, [esp]
		0xC3 // ret
	};
#endif

	// the tool is basically a recursive disassembler
	auto DisassembleBranch = [&](
		ZyanUSize Rva, // branch base address rva
		auto& DisassembleBranch // to be recursively called
		) -> VOID
	{

		// the rva is taken from the virtual image base
		ZyanU64 InstrAddress = (ZyanU64)lpNtHeader->OptionalHeader.ImageBase + Rva;
		if (IsVerbous) Utils::Printf::Info("Disassembling branch at 0x%llx",
			InstrAddress);
		// inserting the branch to the Branches array and getting the index
		auto BranchIndex = Branches.size();
		Branches.push_back({ InstrAddress, {FALSE, {}} });
		// the remaining length of the whole buffer
		ZyanUSize Length;
		// to determine if the branch is reached and end or not
		BOOL bContinueInBranch = TRUE,
			// to determine if the instruction is longer than 5
			// to determine if the branch destination address is valid
			IsLongEnough, ValidAddr;
		// the destination address for a branch
		ZyanU64 DestAddr;
		PIMAGE_SECTION_HEADER lpHeaderSection;
		_HookState HookState;

		// getting the raw offset of the branch
		DWORD Offset;
		if (!Utils::RvaToOffset(
			lpNtHeader,
			(DWORD)Rva,
			&Offset
		))
		{
			Utils::Printf::Fail("Cannot get offset for the branch at 0x%llx",
				InstrAddress);
			return;
		};

		// to get the destination of a branch instruction
		// if the branch has immediate/memory it will get the destination
		// if the branch is undefined like "jmp rax" or the destination
		// is not valid it will return 0
		auto GetBranchDestination = [&](
			ZydisDecodedInstruction* lpZyInstruction,
			ZyanU64 InstrAddress
			) -> ZyanU64
		{
			ZydisDecodedOperand Op0 = *lpZyInstruction->operands;
			if ((Op0.imm.is_relative && !Op0.imm.is_signed) ||
				(!Op0.imm.is_relative && Op0.imm.is_signed)) return 0;

			ZyanU64 AbsAddress = 0;
			if (!ZYAN_SUCCESS(
				ZydisCalcAbsoluteAddress(
					lpZyInstruction,
					&Op0,
					InstrAddress,
					&AbsAddress
				)
			)) return 0;

			if (Op0.type == ZYDIS_OPERAND_TYPE_MEMORY)
			{
				// like jmp [rip+offset] or jmp [addr_ptr]
				DWORD dwMemOffset = 0;
				if (!Utils::RvaToOffset(
					lpNtHeader,
					(DWORD)(AbsAddress - lpNtHeader->OptionalHeader.ImageBase),
					&dwMemOffset
				)) return 0;

				// the operand size should represent the arch
				// because you cannot make "jmp dword ptr [rip+offset]"
				if (Op0.size == 64) AbsAddress = (ZyanU64) * (ZyanU64*)(
					(DWORD_PTR)RawPE.lpDataBuffer + dwMemOffset);
				if (Op0.size == 32) AbsAddress = (ZyanU64) * (ZyanU32*)(
					(DWORD_PTR)RawPE.lpDataBuffer + dwMemOffset);
				else return 0;
			};

			// if the address is in the virtual range
			if (AbsAddress < (ZyanU64)lpNtHeader->OptionalHeader.ImageBase ||
				AbsAddress >= (ZyanU64)lpNtHeader->OptionalHeader.ImageBase + (ZyanU64)lpNtHeader->OptionalHeader.SizeOfImage
				) return 0;

			return AbsAddress;
		};

		// make sure the destination rva lies in one of the sections
		// and its offset lies in the raw range of the same section
		// that's because some section has zero raw size and a normal virtual size
		auto CheckValidAddress = [&](ZyanU64 Address) -> BOOL {
			lpHeaderSection = IMAGE_FIRST_SECTION(lpNtHeader);
			for (DWORD dwIndex = 0; dwIndex < lpNtHeader->FileHeader.NumberOfSections; dwIndex++) {
				if (Address >= (ZyanU64)lpHeaderSection[dwIndex].VirtualAddress + (ZyanU64)lpNtHeader->OptionalHeader.ImageBase
					&& Address < (ZyanU64)lpHeaderSection[dwIndex].VirtualAddress + (ZyanU64)lpNtHeader->OptionalHeader.ImageBase
					+ (ZyanU64)lpHeaderSection[dwIndex].Misc.VirtualSize) {
					if (Address - lpHeaderSection[dwIndex].VirtualAddress - lpNtHeader->OptionalHeader.ImageBase >
						lpHeaderSection[dwIndex].SizeOfRawData) return FALSE;
					return TRUE;
				};
			};
			return FALSE;
		};

		// loop on all of the instructions at the same branch
		while (bContinueInBranch)
		{
			// vector of the block that will decode/execute the hooked instruction
			std::vector<BYTE> ObfuscatedBlockVec(ObfuscatedBlock,
				ObfuscatedBlock + sizeof(ObfuscatedBlock));
			// vector of the lea instruction that will be appended in case of there
			// is length difference between the instruction length and the call length
			std::vector<BYTE> LeaInstructionVec(LeaInstruction,
				LeaInstruction + sizeof(LeaInstruction));
			// the inside block vector
			std::vector<BYTE> InterpretedInst;
			// the real decoded instruction offset from the base of the inside block
			ZyanI8 RealOffset = 0;

			// the absolute address of branch
			InstrAddress = (ZyanU64)lpNtHeader->OptionalHeader.ImageBase + Rva;
			Length = (ZyanUSize)RawPE.dwSize - Offset;
			if (!Length)
			{
				if (IsVerbous) Utils::Printf::Info("No more instructions at 0x%llx",
					InstrAddress);
				break;
			};

			// the raw offset of a branch to be used while looping
			DWORD InstrOffset;
			// if the current instruction is already disassembled
			BOOL IsDisassembled = FALSE;
			// iterator to a branch to be used while looping
			std::vector<std::pair<ZyanU64, std::pair<BOOL,
				std::vector<std::pair<ZyanU64, DWORD>>>>>::iterator DisBranch;
			// checking if the current is already disassembled
			for (DisBranch = Branches.begin();
				DisBranch != Branches.end();
				DisBranch++)
			{
				std::vector<std::pair<ZyanU64, DWORD>>::iterator DisInstruction =
				std::find_if(DisBranch->second.second.begin(), DisBranch->second.second.end(), [InstrAddress](auto& iter)
					{
						return iter.first == InstrAddress;
					});
				if (DisInstruction == DisBranch->second.second.end())
					continue;

				// if the instruction is disassembled this means that there are more than one
				// path to the same instruction, so the current instruction is a
				// node between two branches, so I've to unhook the first hooked instruction
				// at the other path it exists at
				IsDisassembled = TRUE;
				// if the other path branch is not fully disassembled, I'm not going to unhook
				// that's because the fact that that branch will eventually lead to the current
				// branch so It's confirmed that that instruction is already executed
				if (!DisBranch->second.first)
					break;

				// unhooking the first hooked instruction from DisBranch
				for (; DisInstruction != DisBranch->second.second.end();
					DisInstruction++) {

					// check if the instruction is hooked
					if (!DisInstruction->second)
						continue;
					// check if the instruction is unhooked
					else if (DisInstruction->second == -1)
						break;

					// getting the raw offset of the instruction
					if (!Utils::RvaToOffset(
						lpNtHeader,
						(DWORD)(DisInstruction->first -
							lpNtHeader->OptionalHeader.ImageBase),
						&InstrOffset
					)) {
						Utils::Printf::Fail("Cannot convert address 0x%llx to offset",
							DisInstruction->first);
						break;
					};

					// unhooking the instruction by changing the key getting mechanism
					// to directly mov the key to the eax
					// from "mov eax, [key_mem_ptr]" to "nop; mov eax, key"
					if (IsVerbous) Utils::Printf::Info("Unhooking the instruction at 0x%llx",
						InstrOffset + lpNtHeader->OptionalHeader.ImageBase);
					InstrOffset = *(PDWORD)((DWORD_PTR)RawPE.lpDataBuffer + InstrOffset + 1) + 5 +
						(DWORD)(DisInstruction->first - lpNtHeader->OptionalHeader.ImageBase) -
						lpNewSectionHeader->VirtualAddress;
					xObfSectionData.at((SIZE_T)InstrOffset + OBF_VALUE_OFFSET) = 0x90; // nop
					xObfSectionData.at((SIZE_T)InstrOffset + OBF_VALUE_OFFSET + 1) = 0xB8;
					*(PDWORD)& xObfSectionData.at((SIZE_T)InstrOffset + 9) =
						DisInstruction->second; // mov eax, key_value
					DisInstruction->second = -1; // flag the the instruction as unhooked
					break;
				};
				break;
			};

			// break the branch if it's already disassembled
			if (IsDisassembled) {
				if (IsVerbous) Utils::Printf::Info("Branch at 0x%llx is already disassembled",
					InstrAddress);
				break;
			};

			// decoding the current instruction
			ZydisDecodedInstruction ZyInstruction = { 0 };
			if (!ZYAN_SUCCESS(
				ZydisDecoderDecodeBuffer(
					&ZyDecoder,
					(LPVOID)((DWORD_PTR)RawPE.lpDataBuffer + Offset),
					Length,
					&ZyInstruction
				)
			))
			{
				Utils::Printf::Fail("Found an invalid instruction at 0x%llx",
					InstrAddress);
				break;
			};

			// insert the current instruction at the branch vector and
			// get the index of it, setting the key to be 0
			auto BranchInstructionIndex = Branches[BranchIndex].second.second.size();
			Branches[BranchIndex].second.second.push_back({ InstrAddress, 0 });
			IsLongEnough = (ZyInstruction.length >= 5);

			// determining whether to get the key as the return address
			// of the previous instruction or mov it directly to the eax
			// this will create a difference in the real instruction offset by 1
#if defined(_M_X64) || defined(__amd64__)
			if (!HookState.DecodeKey.HasValue)
				RealOffset = 22;
			else RealOffset = 23;
#else
			if (!HookState.DecodeKey.HasValue)
				RealOffset = 21;
			else RealOffset = 22;
#endif

			// hook the current instruction
			auto ObfuscateInstr = [&]() -> VOID
			{
				// moving random bytes to the current return address offset
				// after executing the instruction this will be filled with
				// the return address so it can be used as a key_ptr
				for (DWORD dwIndex = 0;
					dwIndex < sizeof(PVOID);
					dwIndex++) ObfuscatedBlockVec.at(RANDOM_BYTES_OFFSET +
					(SIZE_T)dwIndex) = (BYTE)dist(rng);

#if defined(_M_X64) || defined(__amd64__)
				// make sure all of the relative memory operands are relocated
				// to fit the new address at which the instruction will be written
				// and executed, relative memory operands are only available at
				// x64 in the form of "mov rax, qword [rip + offset]"
				for (DWORD dwIndex = 0;
					dwIndex < ZyInstruction.operand_count;
					dwIndex++)
				{
					if (ZyInstruction.operands[dwIndex].type == ZYDIS_OPERAND_TYPE_MEMORY &&
						ZyInstruction.operands[dwIndex].mem.disp.has_displacement &&
						ZyInstruction.operands[dwIndex].mem.base == ZYDIS_REGISTER_RIP)
					{
						// relocating the offset
						*(PDWORD)((DWORD_PTR)RawPE.lpDataBuffer + Offset +
							(SIZE_T)ZyInstruction.raw.disp.offset) =
							(DWORD)(ZyInstruction.operands[dwIndex].mem.disp.value +
								InstrAddress - lpNewSectionHeader->VirtualAddress - OBF_INSTRUCTION_OFFSET - RealOffset -
								lpNtHeader->OptionalHeader.ImageBase - xObfSectionData.size());
						break;
					};
				};
#endif

				// not all of the instruction is encoded, but only the first four bytes
				// and because I know already that the minimum length will be 5, so it
				// will be so enough to obfuscate the whole instruction
				// the decoding is just a simple adding between two values
				// and the result will be the instruction four bytes
				// the first value is the key which will be gotten from the return address
				// ptr of the previous instruction or it will be directly move to eax
				// and the other value is ObfValue that will be calculated as below
				// the KeyPtr will be taken as the last return ptr or zero
				DWORD ObfValue = 0, KeyPtr = (HookState.DecodeKey.HasValue ?
					HookState.DecodeKey.LastValueOffset : 0),
					// the key is the last return value or it will be some random value
					Key = (HookState.DecodeKey.HasValue ? HookState.DecodeKey.LastValue :
					(DWORD)((dist(rng) << 16) + dist(rng)));
				ObfValue = *(PDWORD)((DWORD_PTR)RawPE.lpDataBuffer + Offset) - Key;

#if defined(_M_X64) || defined(__amd64__)
				// in case of x64 the the KeyPtr is an offset from the current address
				KeyPtr -= (DWORD)xObfSectionData.size() +
					OBF_INSTRUCTION_OFFSET + OBF_VALUE_OFFSET;
				// the inner block, it will process at four phases
				// 1) decode, decoding the first four bytes of the instruction
				// 2) write, writing the first four bytes to restore the original instruction
				// 3) execute, the instruction is executed
				// 4) remove, the decoded instruction will be overwritten by a jump back to
				//		the first phase
				// the jump back is placed after the instruction is executed so it can be used
				// again from any other thread and the whole phases are done again
				InterpretedInst = {
					0x50, // push eax
#define KEY_OFFSET 1 // the key getting mechanism is put here
					// it may be "mov eax, key" or "mov eax, [key_ptr]"
					0x67, 0x8D, 0x80,
					((PBYTE) & (ObfValue))[0],
					((PBYTE) & (ObfValue))[1],
					((PBYTE) & (ObfValue))[2],
					((PBYTE) & (ObfValue))[3],	// lea eax, [eax + ObfValue]
					// after executing this the eax
					// will contain the original 4 bytes
					0x87, 0x05, 0x03, 0x00, 0x00, 0x00, // xchg dword [instr_ptr], eax
					0x58, // pop eax
					0xF3, 0x90, // pause
					(BYTE)dist(rng), (BYTE)dist(rng),	// first 4 bytes of the instruction
					(BYTE)dist(rng), (BYTE)dist(rng)  // now it will be random bytes
					// at runtime it will be overwritten
					// with the original bytes
					// after executing it will be overwritten
					// with a jump to the "push eax"
				};
#else
				// at x86_32 the KeyPtr is an absolute address
				KeyPtr += lpNtHeader->OptionalHeader.ImageBase +
					lpNewSectionHeader->VirtualAddress;
				DWORD dwInstr = 0; // absolute address of the real instruction
				InterpretedInst = {
					0x50, // push eax
#define KEY_OFFSET 1
					0x8D, 0x80,
					((PBYTE) & (ObfValue))[0],
					((PBYTE) & (ObfValue))[1],
					((PBYTE) & (ObfValue))[2],
					((PBYTE) & (ObfValue))[3], // lea eax, [eax + ObfValue]
					0x87, 0x05,
#define REAL_INSTRUCTION_OFFSET 9 // at x86_32 memory can only be accessed with absolute addressing
					0x00, 0x00, 0x00, 0x00,
					0x58,
					0xF3, 0x90,
					(BYTE)dist(rng), (BYTE)dist(rng),
					(BYTE)dist(rng), (BYTE)dist(rng)
				};
				// again "pop [RANDOM_BYTES_OFFSET]" is accessed by absolute RANDOM_BYTES_OFFSET
				*(PDWORD)& (ObfuscatedBlockVec.at(RET_ADDRESS_OFFSET)) =
					lpNtHeader->OptionalHeader.ImageBase + lpNewSectionHeader->VirtualAddress +
					xObfSectionData.size() + RANDOM_BYTES_OFFSET;
				// setting the REAL_INSTRUCTION_OFFSET with the address of the real instruction
				*(PDWORD)& (InterpretedInst.at(REAL_INSTRUCTION_OFFSET)) =
					(dwInstr = lpNtHeader->OptionalHeader.ImageBase + lpNewSectionHeader->VirtualAddress +
						xObfSectionData.size() + OBF_INSTRUCTION_OFFSET + REAL_INSTRUCTION_OFFSET +
						OBF_VALUE_OFFSET + sizeof(DWORD) + 2);
#endif
				// the size of the instruction
				// "mov eax, Key" or "mov eax, [KeyPtr]"
				DWORD bKeySize;
				if (!HookState.DecodeKey.HasValue) {
					// directly mov the key to eax
					BYTE bKey[] = {
						0xB8,
						((PBYTE) & (Key))[0],
						((PBYTE) & (Key))[1],
						((PBYTE) & (Key))[2],
						((PBYTE) & (Key))[3] // mov eax, Key
					};
#ifdef REAL_INSTRUCTION_OFFSET
					// the address of the instruction should be decreased by 1
					* (PDWORD)& (InterpretedInst.at(REAL_INSTRUCTION_OFFSET)) -= 1;
					dwInstr -= 1;
#endif
					// inserting the key getting instruction
					InterpretedInst.insert(InterpretedInst.begin() + KEY_OFFSET,
						bKey, bKey + sizeof(bKey));
					bKeySize = sizeof(bKey);
				}
				else {
					BYTE bKey[] = {
						0x8B, 0x05,
						((PBYTE) & (KeyPtr))[0],
						((PBYTE) & (KeyPtr))[1],
						((PBYTE) & (KeyPtr))[2],
						((PBYTE) & (KeyPtr))[3] // mov eax, [KeyPtr]
					};
					// inserting the key getting instruction
					InterpretedInst.insert(InterpretedInst.begin() + KEY_OFFSET, bKey,
						bKey + sizeof(bKey));
					// in this case the instruction is a part of a hook chain
					// so it has to be flagged as so
					Branches[BranchIndex].second.second[BranchInstructionIndex].second = Key;
					bKeySize = sizeof(bKey);
				};

				// inserting the rest of the instruction to the inner block
				// all the remaining bytes after the first 4 bytes
				for (DWORD dwIndex = 4;
					dwIndex < ZyInstruction.length;
					dwIndex++) InterpretedInst.push_back(*(PBYTE)((DWORD_PTR)RawPE.lpDataBuffer +
						Offset + dwIndex));

				// moving the back jump instruction to AX
				InterpretedInst.push_back(0x50); // push eax
				InterpretedInst.push_back(0x66);
				InterpretedInst.push_back(0xB8);
				InterpretedInst.push_back(0xEB);
				InterpretedInst.push_back((BYTE)(2 + ZyInstruction.length
					- InterpretedInst.size()));  // mov ax, jmp_back_intruction

// moving the AX to replace the instruction
// this will make the instruction overwritten with "jmp" to
// the start of the decoding phase so it process the 4 phases
				InterpretedInst.push_back(0x66);
				InterpretedInst.push_back(0x87);
				InterpretedInst.push_back(0x05);
#if defined(_M_X64) || defined(__amd64__)
				// the offset of the real instruction
				InterpretedInst.push_back((BYTE)(0 - ZyInstruction.length - 12));
				InterpretedInst.push_back(0xFF);
				InterpretedInst.push_back(0xFF);
				InterpretedInst.push_back(0xFF);
				// xchg ax, [rip - (length + 12)]
#else
				// the address of the real instruction
				InterpretedInst.push_back(((PBYTE)& dwInstr)[0]);
				InterpretedInst.push_back(((PBYTE)& dwInstr)[1]);
				InterpretedInst.push_back(((PBYTE)& dwInstr)[2]);
				InterpretedInst.push_back(((PBYTE)& dwInstr)[3]);
				// xchg ax, [dwInstr]
#endif
				// inserting the inner block
				ObfuscatedBlockVec.insert(ObfuscatedBlockVec.begin() + OBF_INSTRUCTION_OFFSET,
					InterpretedInst.begin(), InterpretedInst.end());

				// inserting the lea instruction in case the instruction length > 5
				// the lea instruction will modify the return address
				if (ZyInstruction.length > 5) {
					LeaInstructionVec.back() = (BYTE)(ZyInstruction.length - 5);
					ObfuscatedBlockVec.insert(ObfuscatedBlockVec.begin() + InterpretedInst.size() +
						(SIZE_T)LENGTH_DIFF_OFFSET, LeaInstructionVec.begin(), LeaInstructionVec.end());
				};

				// re-aligning the offset at which the return address is stored
				*(PDWORD)& (ObfuscatedBlockVec.at(RET_ADDRESS_OFFSET)) +=
					(DWORD)InterpretedInst.size();

				// building up the call instruction
				*(PDWORD)& (CallInst[1]) = (DWORD)(lpNewSectionHeader->VirtualAddress +
					xObfSectionData.size() + lpNtHeader->OptionalHeader.ImageBase -
					InstrAddress - 5);

				// padding it with random bytes
				for (ZyanI8 zyIndex = 0;
					zyIndex < ZyInstruction.length - 5;
					zyIndex++)* (CallInst + 5 + zyIndex) = dist(rng) & 0xff;

				// inserting the call instruction instead of the original one
				memmove(
					(LPVOID)((DWORD_PTR)RawPE.lpDataBuffer + Offset),
					CallInst,
					ZyInstruction.length
				);

				// update the current Key with the return address of the current instruction
				// every instruction will depend on the key that is the return of the previous one
				HookState.DecodeKey.HasValue = TRUE;
				HookState.DecodeKey.LastValue = (DWORD)(InstrAddress + 5);
				HookState.DecodeKey.LastValueOffset = (DWORD)xObfSectionData.size() + RANDOM_BYTES_OFFSET
					+ (DWORD)InterpretedInst.size();

				// appending the whole block to the new section data
				xObfSectionData.insert(xObfSectionData.end(),
					ObfuscatedBlockVec.begin(), ObfuscatedBlockVec.end());
				if (IsVerbous) Utils::Printf::Info("Obfuscated the instruction at 0x%llx",
					InstrAddress);
			};

			if (ZyInstruction.meta.branch_type ==
				ZYDIS_BRANCH_TYPE_NONE)
			{
				// directly hook the instruction if it's not a branch
				switch (ZyInstruction.mnemonic)
				{
				case ZYDIS_MNEMONIC_INT3:
				case ZYDIS_MNEMONIC_SYSRET:
				case ZYDIS_MNEMONIC_SYSEXIT:
				case ZYDIS_MNEMONIC_IRET:
				case ZYDIS_MNEMONIC_IRETD:
				case ZYDIS_MNEMONIC_IRETQ:
				case ZYDIS_MNEMONIC_XABORT:
				case ZYDIS_MNEMONIC_RSM:
					// all of ret-like instructions
					bContinueInBranch = FALSE;
					if (IsVerbous) Utils::Printf::Info("Found ret-like instruction at 0x%llx",
						InstrAddress);
				};
				if (IsLongEnough)
					ObfuscateInstr();
				goto NEXT_INSTRUCTION;
			};

			// in case the instruction is a branch instruction,
			// try to get the destination address and check its validity
			DestAddr = GetBranchDestination(
				&ZyInstruction,
				InstrAddress
			);
			ValidAddr = CheckValidAddress(DestAddr);

			if (IsLongEnough)
			{
				// if the branch address is immediate and relative
				// we have to relocate it to fit in the new address
				if (ZyInstruction.raw.imm[0].is_relative)
				{
					*(PDWORD)((DWORD_PTR)RawPE.lpDataBuffer + Offset + ZyInstruction.raw.imm[0].offset) =
						(DWORD)(DestAddr - lpNewSectionHeader->VirtualAddress - OBF_INSTRUCTION_OFFSET - RealOffset
							- lpNtHeader->OptionalHeader.ImageBase - xObfSectionData.size() - ZyInstruction.length);
				};
				ObfuscateInstr();
			};

			switch (ZyInstruction.mnemonic)
			{
			case ZYDIS_MNEMONIC_RET:
				// this represents a normal branch end
				bContinueInBranch = FALSE;
				if (IsVerbous) Utils::Printf::Info("Found ret instruction at 0x%llx",
					InstrAddress);
				break;
			case ZYDIS_MNEMONIC_CALL:
				// a call instruction shouldn't break the hook chain
				// because there's no "two possible" thing
				if (IsVerbous) Utils::Printf::Info("Found call instruction at 0x%llx",
					InstrAddress);
				if (!DestAddr) {
					if (IsVerbous) Utils::Printf::Info("Cannot get the call address at 0x%llx",
						InstrAddress);
				}
				else if (ValidAddr)
				{
					// start a new branch recursively
					DisassembleBranch(
						(ZyanUSize)(DestAddr - lpNtHeader->OptionalHeader.ImageBase),
						DisassembleBranch
					);
				};
				break;
			case ZYDIS_MNEMONIC_JMP:
				// the same thing here, the jmp instruction shouldn't break the chain
				if (IsVerbous) Utils::Printf::Info("Found jmp instruction at 0x%llx",
					InstrAddress);
				if (!DestAddr)
				{
					// at this point the branch itself is broken
					bContinueInBranch = FALSE;
					if (IsVerbous) Utils::Printf::Info("Cannot get the jmp address at 0x%llx",
						InstrAddress);
					break;
				};

				if (ValidAddr)
				{
					// continuing the branch by changing the offset/rva to the next instruction
					Rva = (ZyanUSize)(DestAddr -
						lpNtHeader->OptionalHeader.ImageBase);
					if (!Utils::RvaToOffset(
						lpNtHeader,
						(DWORD)Rva,
						&Offset
					))
					{
						bContinueInBranch = FALSE;
						Utils::Printf::Fail("Cannot get offset for the branch at 0x%llx",
							DestAddr);
						break;
					};
				};

				continue;
			case ZYDIS_MNEMONIC_JB:
			case ZYDIS_MNEMONIC_JBE:
			case ZYDIS_MNEMONIC_JCXZ:
			case ZYDIS_MNEMONIC_JECXZ:
			case ZYDIS_MNEMONIC_JKNZD:
			case ZYDIS_MNEMONIC_JKZD:
			case ZYDIS_MNEMONIC_JL:
			case ZYDIS_MNEMONIC_JLE:
			case ZYDIS_MNEMONIC_JNB:
			case ZYDIS_MNEMONIC_JNBE:
			case ZYDIS_MNEMONIC_JNL:
			case ZYDIS_MNEMONIC_JNLE:
			case ZYDIS_MNEMONIC_JNO:
			case ZYDIS_MNEMONIC_JNP:
			case ZYDIS_MNEMONIC_JNS:
			case ZYDIS_MNEMONIC_JNZ:
			case ZYDIS_MNEMONIC_JO:
			case ZYDIS_MNEMONIC_JP:
			case ZYDIS_MNEMONIC_JRCXZ:
			case ZYDIS_MNEMONIC_JS:
			case ZYDIS_MNEMONIC_JZ:
				// in this case the hook chain should be broken
				// because there is two possible paths can be
				// taken from this point, and it's impossible
				// to determine which one will be taken
				if (IsVerbous) Utils::Printf::Info("Found conditional jmp instruction at 0x%llx",
					InstrAddress);
				if (!DestAddr) {
					if (IsVerbous) Utils::Printf::Info("Cannot get the conditional jmp address");
				}
				else if (ValidAddr)
				{
					// start a new branch recursively
					DisassembleBranch(
						(ZyanUSize)(DestAddr - lpNtHeader->OptionalHeader.ImageBase),
						DisassembleBranch
					);
				};
				break;
			default:
				// unknown branch type, break the branch
				bContinueInBranch = FALSE;
				Utils::Printf::Fail("Undefined branch instruction at 0x%llx",
					InstrAddress);
				break;
			};
		NEXT_INSTRUCTION:
			// move to the next instruction
			Offset += ZyInstruction.length;
			Rva += ZyInstruction.length;
		};

		Branches[BranchIndex].second.first = TRUE;
		if (IsVerbous) Utils::Printf::Info("Reached the end of a branch at 0x%llx",
			InstrAddress);
		return;
	};

	if (IsVerbous) Utils::Printf::Info("Obfuscating the tls callbacks");
	// at this point we need to pass any branch base to DisassembleBranch
	BOOL IsTlsExist;
	DWORD dwTlsDirAddr = 0;
	// and tls call backs also
	// actually any callbacks should be treated like this
	if (!Load::PE::IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_TLS, &IsTlsExist))
	{
		Utils::Printf::Fail("Cannot check if IMAGE_DIRECTORY_ENTRY_TLS table exists");
		return FALSE;
	};

	if (IsTlsExist)
	{
		// getting the offset of the tls directory
		dwTlsDirAddr = GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_TLS);
		if (!Utils::RvaToOffset(
			lpNtHeader,
			dwTlsDirAddr,
			&dwTlsDirAddr))
		{
			Utils::Printf::Fail("Cannot get offset for the rva at 0x%lx",
				dwTlsDirAddr);
			return FALSE;
		};

		PIMAGE_TLS_DIRECTORY lpTlsDir = (PIMAGE_TLS_DIRECTORY)((DWORD_PTR)RawPE.lpDataBuffer +
			dwTlsDirAddr);
		// offset of the callbacks array
		DWORD dwCallbacksOffset = 0;
		if (!Utils::RvaToOffset(
			lpNtHeader,
			(DWORD)(lpTlsDir->AddressOfCallBacks - lpNtHeader->OptionalHeader.ImageBase),
			&dwCallbacksOffset
		))
		{
			Utils::Printf::Fail("Cannot get offset for the rva at 0x%lx",
				(DWORD)(lpTlsDir->AddressOfCallBacks - lpNtHeader->OptionalHeader.ImageBase));
			return FALSE;
		};

		// callbacks array
		LPVOID* lpCallBack = (LPVOID*)((DWORD_PTR)RawPE.lpDataBuffer +
			dwCallbacksOffset);
		for (; *lpCallBack != 0; lpCallBack++) {
			// looping on all of the callbacks
			// and for each one reset the hook chain
			// that's because each one must be executed separately
			_HookState HookState;
			DisassembleBranch(
				(ZyanUSize)((uintptr_t)* lpCallBack -
					lpNtHeader->OptionalHeader.ImageBase),
				DisassembleBranch
			);
		};
	};

	if (IsVerbous) Utils::Printf::Info("Obfuscating the entry subroutine");
	// passing the entry point
	ZyanUSize EntryOffset = lpNtHeader->OptionalHeader.AddressOfEntryPoint;
	DisassembleBranch(
		EntryOffset,
		DisassembleBranch
	);

	// used to determine if debug symbols exist
	BOOL bSymbolsExists = FALSE;

	if (lpNtHeader->FileHeader.PointerToSymbolTable)
	{
		if (IsVerbous) Utils::Printf::Info("Obfuscating the COFF subroutine symbols");
		PIMAGE_SYMBOL lpCOFFSymbol = (PIMAGE_SYMBOL)((DWORD_PTR)RawPE.lpDataBuffer +
			lpNtHeader->FileHeader.PointerToSymbolTable);
		LPVOID lpCOFFString = (LPVOID)((DWORD_PTR)lpCOFFSymbol + lpNtHeader->FileHeader.NumberOfSymbols * sizeof(IMAGE_SYMBOL));

		// check if the symbol table is valid
		if (!Utils::IsValidWritePtr(
			lpCOFFSymbol,
			*(PDWORD)lpCOFFString + lpNtHeader->FileHeader.NumberOfSymbols * sizeof(IMAGE_SYMBOL)
		))
		{
			Utils::Printf::Fail("Invalid COFF symbol table");
			return FALSE;
		};
		
		// pointer to the section array
		PIMAGE_SECTION_HEADER lpHeaderSection = IMAGE_FIRST_SECTION(lpNtHeader);
		if (IsVerbous) Utils::Printf::Info("Obfuscating the COFF subroutine");

		// looping on all of the symbols
		for (DWORD dwSymIndex = 0;
			dwSymIndex < lpNtHeader->FileHeader.NumberOfSymbols;
			dwSymIndex++)
		{
			// searching for valid subroutines
			if ((lpCOFFSymbol[dwSymIndex].Type >> 4) !=
				IMAGE_SYM_DTYPE_FUNCTION ||
				!lpCOFFSymbol[dwSymIndex].SectionNumber
				) goto NEXT_SYMBOL;

			DisassembleBranch(
				(ZyanUSize)lpHeaderSection[lpCOFFSymbol[dwSymIndex].SectionNumber - 1].VirtualAddress +
				(ZyanUSize)lpCOFFSymbol[dwSymIndex].Value,
				DisassembleBranch
			);
			
			// every symbol record is followed by NumberOfAuxSymbols of auxiliary symbol records
			// size of auxiliary symbol record equals size of symbol record
		NEXT_SYMBOL:
			dwSymIndex += lpCOFFSymbol[dwSymIndex].NumberOfAuxSymbols;
		};

		// resetting its whole memory
		ZeroMemory(
			lpCOFFSymbol,
			*(PDWORD)lpCOFFString + lpNtHeader->FileHeader.NumberOfSymbols * sizeof(IMAGE_SYMBOL)
		);

		lpNtHeader->FileHeader.PointerToSymbolTable = 0;
		lpNtHeader->FileHeader.NumberOfSymbols = 0;
		bSymbolsExists = TRUE;
	};

	// check if debug table exists
	BOOL IsDebugExists = FALSE;
	if (!Load::PE::IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_DEBUG, &IsDebugExists))
	{
		Utils::Printf::Fail("Cannot check if IMAGE_DIRECTORY_ENTRY_DEBUG table exists");
		return FALSE;
	};
	if (IsDebugExists && !bSymbolsExists)
	{
		if (IsVerbous) Utils::Printf::Info("Obfuscating the debug table subroutine symbols");
		DWORD dwDebugBaseOffset = 0;
		DWORD dwDebugSize = 0;
		if (!Load::PE::GetDirectoryInfo(
			lpNtHeader,
			IMAGE_DIRECTORY_ENTRY_DEBUG,
			&dwDebugBaseOffset,
			&dwDebugSize,
			FALSE
		))
		{
			Utils::Printf::Fail("Unable to get the IMAGE_DIRECTORY_ENTRY_DEBUG table information");
			return FALSE;
		};

		PIMAGE_DEBUG_DIRECTORY lpDebugTable = (PIMAGE_DEBUG_DIRECTORY)((DWORD_PTR)RawPE.lpDataBuffer + dwDebugBaseOffset);
		if (lpDebugTable->Type != IMAGE_DEBUG_TYPE_CODEVIEW)
		{
			// only CV is supported for now
			Utils::Printf::Fail("Unsupported debug table type");
			return FALSE;
		};

		// removing the debug table
		// because it may help recognizing the original subroutines
		if (!Utils::IsValidReadPtr(
			lpDebugTable,
			sizeof(IMAGE_DEBUG_DIRECTORY)
		))
		{
			Utils::Printf::Fail("Invalid debug directory");
			return FALSE;
		};

		// check if the debug data is valid
		LPVOID lpDebugData = (LPVOID)((DWORD_PTR)RawPE.lpDataBuffer +
			lpDebugTable->PointerToRawData);
		if (!Utils::IsValidReadPtr(
			lpDebugTable,
			lpDebugTable->SizeOfData
		) || lpDebugTable->SizeOfData < sizeof(DWORD))
		{
			Utils::Printf::Fail("Invalid debug data");
			return FALSE;
		};

		// getting the pdb file path
		std::string PdbPath;
		switch (*(PDWORD)lpDebugData)
		{
			// checking the signature
		case 'SDSR':
			if (!Utils::IsValidReadPtr(
				lpDebugData,
				sizeof(_RSDSI)
			))
			{
				Utils::Printf::Fail("Invalid RSDSI table");
				return FALSE;
			};
			((PBYTE)lpDebugData)[sizeof(_RSDSI) - 1] = NULL;
			PdbPath = (*(_RSDSI*)lpDebugData).szPdb;
			break;
		case '01BN':
			if (!Utils::IsValidReadPtr(
				lpDebugData,
				sizeof(_NB10I)
			))
			{
				Utils::Printf::Fail("Invalid NB10I table");
				return FALSE;
			};
			((PBYTE)lpDebugData)[sizeof(_NB10I) - 1] = NULL;
			PdbPath = (*(_NB10I*)lpDebugData).szPdb;
			break;
		default:
			Utils::Printf::Fail("Invalid debug CV signature %d", *(PDWORD)lpDebugData);
			return FALSE;
		};

		// initialization of dbghelp symbol server
		if (!SymInitialize(
			GetCurrentProcess(),
			NULL,
			FALSE
		)) {
			Utils::Reportf::ApiError("SymInitialize", "Error while initializing dbghelp");
			return FALSE;
		};

		// definitions of pdb related stuff
		IMAGEHLP_MODULE64 PdbInfo = { 0 };
		DWORD64 dwPdbBase = 0;
		DWORD dwPdbSize = 0;
		HANDLE hPdb = NULL;

		// opening the pdb file 
		if (!(hPdb = CreateFileA(
			PdbPath.c_str(),
			GENERIC_READ,
			FILE_SHARE_READ,
			NULL,
			OPEN_EXISTING,
			0,
			NULL
		)) || hPdb == INVALID_HANDLE_VALUE) {
			if (GetLastError() == ERROR_FILE_NOT_FOUND)
				goto PDB_NOT_FOUND;
			Utils::Reportf::ApiError("CreateFileA", "cannot open the pdb file");
			return FALSE;
		};

		// getting the its size
		if (!(dwPdbSize = GetFileSize(
			hPdb,
			NULL
		))) {
			Utils::Reportf::ApiError("GetFileSize", "cannot get the size the pdb file");
			return FALSE;
		};

		// we don't need the handle anymore
		if (!CloseHandle(
			hPdb
		)) {
			Utils::Reportf::ApiError("CloseHandle", "cannot close the pdb file handle");
			return FALSE;
		};

		// loading the pdb file
		if (!(dwPdbBase = SymLoadModule64(
			GetCurrentProcess(),
			NULL,
			PdbPath.c_str(),
			NULL,
			lpNtHeader->OptionalHeader.ImageBase,
			dwPdbSize
		))) {
			Utils::Reportf::ApiError("SymLoadModuleEx", "cannot load the pdb file");
			return FALSE;
		};

		// loading the pdb symbols
		PdbInfo.SizeOfStruct = sizeof(PdbInfo);
		if (!SymGetModuleInfo64(
			GetCurrentProcess(),
			dwPdbBase,
			&PdbInfo
		)) {
			Utils::Reportf::ApiError("SymGetModuleInfo64", "cannot load the pdb module info");
			return FALSE;
		};

		// enumerating all of the symbols
		if (!SymEnumSymbols(
			GetCurrentProcess(),
			dwPdbBase,
			NULL,
			[](PSYMBOL_INFO pSymInfo,
				ULONG SymbolSize,
				PVOID UserContext) -> BOOL {
					if (pSymInfo &&
						pSymInfo->Tag == SymTagFunction)
						// process only the functions
						PdbFunVAs.push_back(pSymInfo->Address);
					// return TRUE to continue the loop
					return TRUE;
			},
			NULL
		))
		{
			Utils::Reportf::ApiError("SymEnumSymbols", "cannot enumerate the pdb symbols");
			return FALSE;
		};

		// unloading the symbols
		if (!SymUnloadModule64(
			GetCurrentProcess(),
			dwPdbBase
		)) {
			Utils::Reportf::ApiError("SymUnloadModule64", "cannot unload the pdb module info");
			return FALSE;
		};

		// obfuscating the collect entries
		std::for_each(PdbFunVAs.begin(), PdbFunVAs.end(), [&](ZyanU64 AbsAddr) -> VOID {
			return DisassembleBranch(
				(ZyanUSize)(AbsAddr - (ZyanU64)lpNtHeader->OptionalHeader.ImageBase),
				DisassembleBranch
			);
			});
		bSymbolsExists = TRUE;

	PDB_NOT_FOUND:

		// cleaning up dbghelp
		if (!SymCleanup(
			GetCurrentProcess()
		)) {
			Utils::Reportf::ApiError("SymCleanup", "error while cleanup dbghelp");
			return FALSE;
		};

		// resetting its whole memory
		ZeroMemory(
			lpDebugTable,
			sizeof(IMAGE_DEBUG_DIRECTORY)
		);

		GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_DEBUG) = 0;
		GET_DIRECTORY_SIZE(lpNtHeader, IMAGE_DIRECTORY_ENTRY_DEBUG) = 0;
	};

	// again the exception table is a good container for valid subroutines
	BOOL IsExceptionExist;
	DWORD dwExceptionDirAddr = 0, dwExceptionDirSize = 0;
	if (!Load::PE::IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_EXCEPTION, &IsExceptionExist))
	{
		Utils::Printf::Fail("Cannot check if IMAGE_DIRECTORY_ENTRY_EXCEPTION table exists");
		return FALSE;
	};

	if (IsExceptionExist && !bSymbolsExists)
	{
		if (IsVerbous) Utils::Printf::Info("Obfuscating the exception table subroutines");
		// getting an offset for the exception table
		dwExceptionDirAddr = GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
		dwExceptionDirSize = GET_DIRECTORY_SIZE(lpNtHeader, IMAGE_DIRECTORY_ENTRY_EXCEPTION);
		if (!Utils::RvaToOffset(
			lpNtHeader,
			dwExceptionDirAddr,
			&dwExceptionDirAddr))
		{
			Utils::Printf::Fail("Cannot get offset for the rva at 0x%lx",
				dwExceptionDirAddr);
			return FALSE;
		};
		PIMAGE_RUNTIME_FUNCTION_ENTRY lpExceptionTable = (PIMAGE_RUNTIME_FUNCTION_ENTRY)((DWORD_PTR)RawPE.lpDataBuffer +
			dwExceptionDirAddr);
		if (!Utils::IsValidWritePtr(
			lpExceptionTable,
			dwExceptionDirSize
		))
		{
			Utils::Printf::Fail("Invalid exception table");
			return FALSE;
		};

		for (; dwExceptionDirSize >= sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY);
			dwExceptionDirSize -= sizeof(IMAGE_RUNTIME_FUNCTION_ENTRY),
			lpExceptionTable++)
		{
			// looping on all of the subroutines and for each one
			// I'm not going to reset the chain
			// because the (tls callbacks/entry point) should be executed first
			DisassembleBranch(
				(ZyanUSize)(lpExceptionTable->BeginAddress),
				DisassembleBranch
			);
		};
		bSymbolsExists = TRUE;
	};

	// again the export table is a good container for valid entries
	BOOL IsExportExist;
	DWORD dwExportDirAddr = 0;
	if (!Load::PE::IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_EXPORT, &IsExportExist))
	{
		Utils::Printf::Fail("Cannot check if IMAGE_DIRECTORY_ENTRY_EXPORT table exists");
		return FALSE;
	};

	if (IsExportExist && !bSymbolsExists)
	{
		if (IsVerbous) Utils::Printf::Info("Obfuscating the exported entries");
		// getting an offset for the export table
		dwExportDirAddr = GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_EXPORT);
		if (!Utils::RvaToOffset(
			lpNtHeader,
			dwExportDirAddr,
			&dwExportDirAddr))
		{
			Utils::Printf::Fail("Cannot get offset for the rva at 0x%lx",
				dwExportDirAddr);
			return FALSE;
		};
		PIMAGE_EXPORT_DIRECTORY lpExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)RawPE.lpDataBuffer +
			dwExportDirAddr);

		if (!Utils::IsValidWritePtr(
			lpExportTable,
			sizeof(IMAGE_EXPORT_DIRECTORY)
		))
		{
			Utils::Printf::Fail("Invalid export directory");
			return FALSE;
		};

		// getting the offset of the functions array
		DWORD dwFunctionsOffset;
		if (!Utils::RvaToOffset(
			lpNtHeader,
			lpExportTable->AddressOfFunctions,
			&dwFunctionsOffset
		))
		{
			Utils::Printf::Fail("Cannot get offset for the rva at 0x%lx",
				lpExportTable->AddressOfFunctions);
			return FALSE;
		};

		LPDWORD lpFunctions = (LPDWORD)((DWORD_PTR)RawPE.lpDataBuffer +
			dwFunctionsOffset);
		if (!Utils::IsValidWritePtr(
			lpFunctions,
			lpExportTable->NumberOfFunctions * sizeof(DWORD)
		))
		{
			Utils::Printf::Fail("Invalid exported functions");
			return FALSE;
		};

		for (DWORD dwIndex = 0;
			dwIndex < lpExportTable->NumberOfFunctions;
			dwIndex++)
		{
			// looping on all of the functions and for each one
			// I'm not going to reset the chain
			// because the (tls callbacks/entry point) should be executed first
			DisassembleBranch(
				(ZyanUSize)(lpFunctions[dwIndex]),
				DisassembleBranch
			);
		};
	};

	BOOL IsRelocExists;
	if (!Load::PE::IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC, &IsRelocExists))
	{
		Utils::Printf::Fail("Cannot check if IMAGE_DIRECTORY_ENTRY_BASERELOC table exists");
		return FALSE;
	};
	if (IsRelocExists)
	{
		// removing the relocation table
		// because if it's exists, some instructions will be changed at runtime
		// like "mov eax, [0x404000]" will be relocated to "mov eax, [0x7404000]"
		// based on the new image base
		// so if the instruction is hooked, it will make the call instruction invalid
		DWORD dwRelocBaseOffset;
		DWORD dwRelocSize;
		if (!Load::PE::GetDirectoryInfo(
			lpNtHeader,
			IMAGE_DIRECTORY_ENTRY_BASERELOC,
			&dwRelocBaseOffset,
			&dwRelocSize,
			FALSE
		))
		{
			Utils::Printf::Fail("Unable to get the IMAGE_DIRECTORY_ENTRY_BASERELOC table information");
			return FALSE;
		};

		if (!Utils::IsValidWritePtr(
			(LPVOID)((DWORD_PTR)RawPE.lpDataBuffer + dwRelocBaseOffset),
			dwRelocSize
		))
		{
			Utils::Printf::Fail("Invalid reloc directory");
			return FALSE;
		};

		ZeroMemory(
			(LPVOID)((DWORD_PTR)RawPE.lpDataBuffer + dwRelocBaseOffset),
			dwRelocSize
		);

		// deleting the relocation information
		GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC) = 0;
		GET_DIRECTORY_SIZE(lpNtHeader, IMAGE_DIRECTORY_ENTRY_BASERELOC) = 0;
		lpNtHeader->FileHeader.Characteristics |= IMAGE_FILE_RELOCS_STRIPPED;
	};

	// setting the information of the new section
	lpNewSectionHeader->Misc.VirtualSize =
		(DWORD)xObfSectionData.size();
	// padding the new section data by zeros
	xObfSectionData.resize((SIZE_T)Utils::AlignUp(
		(DWORD)xObfSectionData.size(),
		lpNtHeader->OptionalHeader.FileAlignment
	), NULL);
	lpNewSectionHeader->SizeOfRawData = (DWORD)xObfSectionData.size();
	// resizing the image based on the size of the new section
	lpNtHeader->OptionalHeader.SizeOfImage += Utils::AlignUp(
		lpNewSectionHeader->Misc.VirtualSize,
		lpNtHeader->OptionalHeader.SectionAlignment
	);

	BOOL IsSecurityExists;
	if (!Load::PE::IsDirExists(lpNtHeader, IMAGE_DIRECTORY_ENTRY_SECURITY, &IsSecurityExists))
	{
		Utils::Printf::Fail("Cannot check if IMAGE_DIRECTORY_ENTRY_SECURITY table exists");
		return FALSE;
	};
	if (IsSecurityExists)
	{
		DWORD dwSecurityBaseOffset;
		DWORD dwSecuritySize;
		if (!Load::PE::GetDirectoryInfo(
			lpNtHeader,
			IMAGE_DIRECTORY_ENTRY_SECURITY,
			&dwSecurityBaseOffset,
			&dwSecuritySize,
			FALSE
		))
		{
			Utils::Printf::Fail("Unable to get the IMAGE_DIRECTORY_ENTRY_SECURITY table information");
			return FALSE;
		};

		PBYTE bSecTable = (PBYTE)((DWORD_PTR)RawPE.lpDataBuffer + dwSecurityBaseOffset);
		if (!Utils::IsValidReadPtr(
			bSecTable,
			dwSecuritySize
		))
		{
			Utils::Printf::Fail("Invalid security directory");
			return FALSE;
		};

		// security directory table has raw address at the optional header
		// and it can be placed beyond the virtual size, so I'm going to relocate it
		if (dwSecurityBaseOffset >= lpNewSectionHeader->PointerToRawData)
		{
			GET_DIRECTORY_ENTRY(lpNtHeader, IMAGE_DIRECTORY_ENTRY_SECURITY) =
				lpNewSectionHeader->PointerToRawData + (DWORD)xObfSectionData.size();
			while (dwSecuritySize--)
				xObfSectionData.push_back(*bSecTable++);
		};
	};

	// creating the Out PE file to write to
	HANDLE hFile = NULL;
	if (!(hFile = CreateFileA(
		OutPE,
		GENERIC_WRITE,
		0,
		NULL,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		NULL
	)) || hFile == INVALID_HANDLE_VALUE)
	{
		Utils::Reportf::ApiError("CreateFileA", "Error while creating the file %s",
			OutPE);
		return FALSE;
	};

	// allocating for the whole new PE
	LPVOID RawObfuscatedPE = NULL;
	if (!(RawObfuscatedPE = VirtualAlloc(
		NULL,
		(SIZE_T)lpNewSectionHeader->PointerToRawData + xObfSectionData.size(),
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE
	)))
	{
		Utils::Reportf::ApiError("VirtualAlloc", "Error while allocating for the obfuscated instructions");
		return FALSE;
	};

	// writing the the first part of the PE raw buffer
	if (!Utils::SafeMemoryCopy(
		RawObfuscatedPE,
		(DWORD)((SIZE_T)lpNewSectionHeader->PointerToRawData + xObfSectionData.size()),
		RawPE.lpDataBuffer,
		lpNewSectionHeader->PointerToRawData
	))
	{
		Utils::Printf::Fail("Unable to write the first part of the PE raw buffer");
		return FALSE;
	};

	// writing the new section
	if (!Utils::SafeMemoryCopy(
		(LPVOID)((DWORD_PTR)RawObfuscatedPE + lpNewSectionHeader->PointerToRawData),
		(DWORD)xObfSectionData.size(),
		xObfSectionData.data(),
		(DWORD)xObfSectionData.size()
	))
	{
		Utils::Printf::Fail("Unable to write the new section");
		return FALSE;
	};

	DWORD dwWrittenSize;
	if (!WriteFile( // writing to the new PE
		hFile,
		RawObfuscatedPE,
		(DWORD)((SIZE_T)lpNewSectionHeader->PointerToRawData + xObfSectionData.size()),
		&dwWrittenSize,
		NULL
	) || dwWrittenSize != (DWORD)((SIZE_T)lpNewSectionHeader->PointerToRawData + 
		xObfSectionData.size()))
	{
		Utils::Reportf::ApiError("WriteFile", "Error while writing to the file %s",
			OutPE);
		return FALSE;
	};

	if (!VirtualFree( // freeing the allocated memory
		RawObfuscatedPE,
		0,
		MEM_RELEASE
	))
	{
		Utils::Reportf::ApiError("VirtualFree", "Error while freeing the region made for the PE");
		return FALSE;
	};

	if (!Load::File::UnLoad( // unloading the RawPE
		&RawPE,
		sizeof(RAW_FILE_INFO)
	))
	{
		Utils::Printf::Fail("Cannot unload this PE");
		return FALSE;
	};
};

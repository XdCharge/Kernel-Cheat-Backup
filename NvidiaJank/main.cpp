#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <string_view>
#include <cstdint>
#include <vector>
#include <winnt.h>
#include <winternl.h>
#include <WinUser.h>

#define QWORD unsigned __int64

#define decrypt_INDEX_ARRAY_OFFSET 0x1219F4D0

#define decrypt_NAME_ARRAY_OFFSET 0x13F53708
#define decrypt_NAME_LIST_OFFSET 0x4C70

#define decrypt_REFDEF_1 0x13F47D48
#define decrypt_REFDEF_2 0x13F47D40
#define decrypt_REFDEF_3 0x13F47D44

#define decrypt_client_CAMERA_POS 0x16F2C
#define decrypt_CAMER_OBJ 0x1135A900

#define decrypt_client_STRUCT_SIZE 0x3A20
#define decrypt_client_BASE_OFFSET 0x97B48
#define decrypt_client_LOCAL_INDEX_OFFSET 0x1270
#define decrypt_client_local_index_data_offset 0x1F4

#define decrypt_client_Team 0x39CC
#define decrypt_client_PosInfo 0x1480
#define decrypt_client_angle 0xF2C

#define decrypt_Visible_FunctionDisTribute 0x7C62DA0
#define decrypt_Visible_AboutVisibleFunction 0x3DE46F0
#define decrypt_Visible_ListHead 0x108

#define decrypt_client_ENCRYPT_PTR_OFFSET 0x13F45FE8


typedef struct _NULL_MEMORY
{
	void* buffer_address;
	UINT_PTR address;
	ULONGLONG size;
	ULONG pid;
	BOOLEAN peb;
	BOOLEAN write;
	BOOLEAN read;
	BOOLEAN req_base;
	void* output;
	const char* module_name;
	ULONG64 base_address;
}NULL_MEMORY;

uintptr_t base_address = 0;
std::uint32_t process_id = 0;

template<typename ... Arg>
uint64_t call_hook(const Arg ... args)
{
	LoadLibrary("user32.dll");

	void* hooked_func = GetProcAddress(LoadLibrary("win32u.dll"), "NtQueryCompositionSurfaceStatistics");

	auto func = static_cast<uint64_t(_stdcall*)(Arg...)>(hooked_func);

	return func(args ...);
}

struct HandleDisposer
{
	using pointer = HANDLE;
	void operator()(HANDLE handle) const
	{
		if (handle != NULL || handle != INVALID_HANDLE_VALUE)
		{
			CloseHandle(handle);
		}
	}
};

using unique_handle = std::unique_ptr<HANDLE, HandleDisposer>;

std::uint32_t get_process_id(std::string_view process_name)
{
	PROCESSENTRY32 processentry;
	const unique_handle snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));

	if (snapshot_handle.get() == INVALID_HANDLE_VALUE)
		return NULL;

	processentry.dwSize = sizeof(MODULEENTRY32);

	while (Process32Next(snapshot_handle.get(), &processentry) == TRUE)
	{
		if (process_name.compare(processentry.szExeFile) == NULL)
		{
			return processentry.th32ProcessID;
		}
	}
	return NULL;
}

static ULONG64 get_module_base_address(const char* module_name)
{
	NULL_MEMORY instructions = { 0 };
	instructions.pid = process_id;
	instructions.req_base = TRUE;
	instructions.read = FALSE;
	instructions.write = FALSE;
	instructions.module_name = module_name;

	call_hook(&instructions);
	
	ULONG64 base = NULL;
	base = instructions.base_address;
	return base;
}

template <class T>
T Read(UINT_PTR read_address)
{
	T response{};
	NULL_MEMORY instructions;
	instructions.pid = process_id;
	instructions.size = sizeof(T);
	instructions.address = read_address;
	instructions.peb = FALSE;
	instructions.read = TRUE;
	instructions.write = FALSE;
	instructions.req_base = FALSE;
	instructions.output = &response;
	call_hook(&instructions);

	return response;
}

bool write_memory(UINT_PTR write_address, UINT_PTR source_address, SIZE_T write_size)
{
	NULL_MEMORY instructions;
	instructions.address = write_address;
	instructions.pid = process_id;
	instructions.peb = FALSE;
	instructions.write = TRUE;
	instructions.read = FALSE;
	instructions.req_base = FALSE;
	instructions.buffer_address = (void*)source_address;
	instructions.size = write_size;

	call_hook(&instructions);

	return true;
}

DWORD64 getPeb() {
	NULL_MEMORY instructions;
	instructions.pid = process_id;
	instructions.peb = TRUE;
	instructions.write = FALSE;
	instructions.read = FALSE;
	instructions.req_base = FALSE;

	call_hook(&instructions);
	
	return (DWORD64)instructions.output;
}

template<typename S>
bool write(UINT_PTR write_address, const S& value)
{
	return write_memory(write_address, (UINT_PTR)&value, sizeof(S));
}


DWORD64 ClientInfo_Dec(DWORD64 BaseAddr)
{
	DWORD64 encryptedPtr = NULL;
	DWORD64 peb = ~getPeb();

	encryptedPtr = Read<DWORD64>(BaseAddr + decrypt_client_ENCRYPT_PTR_OFFSET);
	if (encryptedPtr)
	{
		DWORD64 reversedAddr = Read<DWORD64>(BaseAddr + 0x4D050F5);
		reversedAddr = _byteswap_uint64(reversedAddr);
		DWORD64 LastKey = Read<DWORD64>((reversedAddr)+0xB);
		if (encryptedPtr && LastKey)
		{
			encryptedPtr ^= (encryptedPtr >> 0x1C);
			encryptedPtr ^= (encryptedPtr >> 0x38);
			encryptedPtr *= 0x14CE84CAA763234F;
			encryptedPtr -= 0x19A3006CC83AEC87;
			encryptedPtr *= LastKey;
			encryptedPtr ^= BaseAddr;
			encryptedPtr -= BaseAddr;

			return encryptedPtr;
		}
	}
	return 0;
}

DWORD64 ClientBase_Dec(DWORD64 BaseAddr, DWORD64 clientInfoDecAddr)
{
	DWORD64 encryptedPtr;
	DWORD64 peb = ~getPeb();

	encryptedPtr = Read<DWORD64>(clientInfoDecAddr + decrypt_client_BASE_OFFSET);
	if (encryptedPtr)
	{
		DWORD64 reversedAddr = Read<DWORD64>(BaseAddr + 0x4D0514E);
		reversedAddr = ~(reversedAddr);
		DWORD64 LastKey = Read<DWORD64>((reversedAddr)+0x11);
		if (encryptedPtr && LastKey)
		{
			encryptedPtr ^= (encryptedPtr >> 0x1C);
			encryptedPtr ^= (encryptedPtr >> 0x38);
			encryptedPtr *= 0x8A67FC71DA9B5945;
			encryptedPtr *= 0x8FDB76ABE18B3587;
			encryptedPtr += ((1 - (BaseAddr + 0xBC29)) * peb);
			encryptedPtr ^= peb;
			encryptedPtr ^= (BaseAddr + 0x5CEB7D3A);
			encryptedPtr *= LastKey;
			encryptedPtr -= (peb * (BaseAddr + 0x59DA));

			return encryptedPtr;
		}
	}
	return 0;
}

int main()
{
	process_id = get_process_id("ModernWarfare.exe");
	base_address = get_module_base_address("ModernWarfare.exe");

	if (!base_address)
	{
		std::cout << "It's Broken" << std::endl;
	}
	else
	{
		// DEBUG SCHNITZEL
		std::cout << "It Works" << std::endl;
		DWORD64 ClientInfo_t = ClientInfo_Dec(base_address); 
		std::cout << "ClientInfo_t: " << ClientInfo_t << std::endl;

		DWORD64 ClientBase_t = ClientBase_Dec(base_address, ClientInfo_t);
		std::cout << "ClientBase_t: " << ClientBase_t << std::endl;

	}

	Sleep(100000);
	return true;
}
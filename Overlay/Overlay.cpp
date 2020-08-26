#include <Dwmapi.h>
#include "Overlay.h"
#include "framework.h"
#include "paint.h"
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
#include <stdio.h>
#include <io.h>
#include <fstream>
#include <fcntl.h>
#include "structs.h"

#define QWORD unsigned __int64

#define decrypt_NAME_ARRAY_OFFSET 0x13F53708
#define decrypt_NAME_LIST_OFFSET 0x4C70

#define decrypt_REFDEF_1 0x13F47D48
#define decrypt_REFDEF_2 0x13F47D40
#define decrypt_REFDEF_3 0x13F47D44

#define client_CAMERA_POS 0x16F2C
#define CAMERA_OBJ 0x1135A900

#define CHARACTER_STRUCT_SIZE 0x3A20
#define decrypt_client_BASE_OFFSET 0x97B48
#define client_LOCAL_INDEX_OFFSET 0x1270
#define client_local_index_data_offset 0x1F4

#define decrypt_client_Team 0x39CC
#define decrypt_client_PosInfo 0x1480
#define decrypt_client_angle 0xF2C

#define decrypt_Visible_FunctionDisTribute 0x7C62DA0
#define decrypt_Visible_AboutVisibleFunction 0x3DE46F0
#define decrypt_Visible_ListHead 0x108

#define decrypt_client_ENCRYPT_PTR_OFFSET 0x13F45FE8

// Warzone globals
std::vector<characterInfo_t*> characterArray;
static DWORD64 clientDecryptKeys[4];
static DWORD64 refDefKey = 0;
static int RefreshInterval = 100 * 5; // Refresh list every 5 seconds 
int myIndexNum = 0;
int intervalCount = 0;
DWORD64 CameraPointer = 0;




//


// KERNEL STUFF


//





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




//


// DECRYPTION STUFF


//




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

// RefDef Decryption
class refdefKeyStruct {
public:
	DWORD ref0;      // 0x00
	DWORD ref1;      // 0x04
	DWORD ref2;		// 0x08
};

DWORD64 DecryptRefDef() {
	if (refDefKey != 0) {
		return refDefKey;
	}
	refdefKeyStruct crypt = Read<refdefKeyStruct>(base_address + decrypt_REFDEF_1);
	DWORD lower = crypt.ref0 ^ (crypt.ref2 ^ (unsigned __int64)(base_address + decrypt_REFDEF_1)) * ((crypt.ref2 ^ (unsigned __int64)(base_address + decrypt_REFDEF_1)) + 2);
	DWORD upper = crypt.ref1 ^ (crypt.ref2 ^ (unsigned __int64)(base_address + decrypt_REFDEF_1 + 0x4)) * ((crypt.ref2 ^ (unsigned __int64)(base_address + decrypt_REFDEF_1 + 0x4)) + 2);
	refDefKey = (DWORD64)upper << 32 | lower; // Merge Both DWORD into QWORD

	std::cout << "RefDef Key: " << refDefKey << std::endl;

	return refDefKey;
}




//


// OVERLAY STUFF


//




// Global Variables:

HINSTANCE hInst;                                // current instance
WCHAR overlayWindowName[100] = L"Overlay";  // main window class name & The title bar text
HWND overlayHWND;
int width = 1920, height = 1080;
Paint paint;

void CreateConsole() {
	AllocConsole();
	freopen_s((FILE**)stdin, "CONIN$", "r", stdin);
	freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);

	SetConsoleTitleA("Sooper Hax Debugger Console");
}

// Forward declarations of functions included in this code module:

ATOM                registerClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);

int APIENTRY wWinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPWSTR    lpCmdLine, _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    registerClass(hInstance);

    // Perform application initialization:

    if (!InitInstance(hInstance, SW_SHOW)) {
        return FALSE;
    }

	CreateConsole();

	process_id = get_process_id("ModernWarfare.exe");
	base_address = get_module_base_address("ModernWarfare.exe");

	addresses.ClientInfo_t = ClientInfo_Dec(base_address);
	addresses.ClientBase_t = ClientBase_Dec(base_address, addresses.ClientInfo_t);

	std::cout << "Base Address: " << base_address << std::endl;
	std::cout << "Client Info: " << addresses.ClientInfo_t  << std::endl;

	paint = Paint(overlayHWND, width, height);
    MSG msg;

    // Main message loop:

    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);

    }

    return (int)msg.wParam;
}

ATOM registerClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.cbClsExtra = 0;
    wcex.cbWndExtra = 0;
    wcex.hInstance = hInstance;
    wcex.hIcon = 0;
    wcex.hCursor = LoadCursor(nullptr, IDC_CROSS);
    wcex.hbrBackground = CreateSolidBrush(RGB(0, 0, 0));
    wcex.lpszMenuName = overlayWindowName;
    wcex.lpszClassName = overlayWindowName;
    wcex.hIconSm = 0;

    return RegisterClassExW(&wcex);
}

BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
    hInst = hInstance; // Store instance handle in our global variable

    overlayHWND = CreateWindowExW(WS_EX_TOPMOST | WS_EX_TRANSPARENT | WS_EX_LAYERED, overlayWindowName, overlayWindowName, WS_POPUP,
        1, 1, width, height, nullptr, nullptr, hInstance, nullptr);

    if (!overlayHWND) {
        return FALSE;
    }
    SetLayeredWindowAttributes(overlayHWND, RGB(0, 0, 0), 0, LWA_COLORKEY);

    ShowWindow(overlayHWND, nCmdShow);

    return TRUE;
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
    case WM_PAINT:
        paint.render();
        break;
    case WM_DESTROY:
        PostQuitMessage(0);
        break;
    default:
        return DefWindowProc(hWnd, message, wParam, lParam);
    }
    return 0;
}

int Paint::d3D9Init(HWND hWnd) {

	if (FAILED(Direct3DCreate9Ex(D3D_SDK_VERSION, &d3dObject))) {
		exit(1);
	}

	ZeroMemory(&d3dparams, sizeof(d3dparams));

	d3dparams.BackBufferWidth = width;
	d3dparams.BackBufferHeight = height;
	d3dparams.Windowed = TRUE;
	d3dparams.SwapEffect = D3DSWAPEFFECT_DISCARD;
	d3dparams.hDeviceWindow = hWnd;
	d3dparams.MultiSampleQuality = D3DMULTISAMPLE_NONE;
	d3dparams.BackBufferFormat = D3DFMT_A8R8G8B8;
	d3dparams.EnableAutoDepthStencil = TRUE;
	d3dparams.AutoDepthStencilFormat = D3DFMT_D16;

	HRESULT res = d3dObject->CreateDeviceEx(D3DADAPTER_DEFAULT, D3DDEVTYPE_HAL, hWnd, D3DCREATE_HARDWARE_VERTEXPROCESSING, &d3dparams, 0, &d3dDevice);

	D3DXCreateFont(d3dDevice, 40, 0, FW_BOLD, 1, false, DEFAULT_CHARSET, OUT_DEVICE_PRECIS, ANTIALIASED_QUALITY, DEFAULT_PITCH, "Comic Sans", &d3dFont);

	return 0;

}

Paint::Paint() {};

Paint::Paint(HWND hWnd, int width, int height) {
	this->width = width;
	this->height = height;
	d3D9Init(hWnd);
}

int Paint::render()
{
	if (d3dDevice == nullptr)
		return 1;
	d3dDevice->Clear(0, 0, D3DCLEAR_TARGET, 0, 1.0f, 0);
	d3dDevice->BeginScene();

	drawText("Sooper Hax", 25, 25, 255, 200, 40, 40);
	drawRect(width / 2 - 5, height / 2 - 5, 255, 0, 0);

	collectPlayersDrawRadar();

	d3dDevice->EndScene();
	d3dDevice->PresentEx(0, 0, 0, 0, 0);

	return 0;
}

void Paint::drawRectFromVector(ImVec2 startpos, ImVec2 endpos, ImVec4 color) {
	int r = (int)color.y, g = (int)color.z, b = (int)color.w;
	int x1 = (int)startpos.x, y1 = (int)startpos.y;
	int x2 = (int)endpos.x, y2 = (int)endpos.y;

	D3DCOLOR rectColor = D3DCOLOR_XRGB(r, g, b);

	D3DRECT BarRect = { x1, y1, x2 + 8, y2 + 8 };

	d3dDevice->Clear(1, &BarRect, D3DCLEAR_TARGET | D3DCLEAR_TARGET, rectColor, 0, 0);
}

void Paint::drawRect(int x, int y, unsigned char r, unsigned char g, unsigned char b)
{

   D3DCOLOR rectColor = D3DCOLOR_XRGB(r,g,b);

   D3DRECT BarRect = { x, y, x + 8, y + 8 }; 

   d3dDevice->Clear(1, &BarRect,  D3DCLEAR_TARGET | D3DCLEAR_TARGET, rectColor, 0, 0);

}

void Paint::drawTextFromVector(ImVec2 position, const char* String, ImVec4 color) {
	RECT FontPos;
	FontPos.left = (int)position.x;
	FontPos.top = (int)position.y;

	int a = (int)color.x;
	int r = (int)color.y;
	int g = (int)color.z;
	int b = (int)color.w;

	d3dFont->DrawTextA(0, String, strlen(String), &FontPos, DT_NOCLIP, D3DCOLOR_ARGB(a, r, g, b));
}

void Paint::drawText(LPCSTR String, int x, int y, int a, int r, int g, int b)
{
	RECT FontPos;
	FontPos.left = x;
	FontPos.top = y;
	d3dFont->DrawTextA(0, String, strlen(String), &FontPos, DT_NOCLIP, D3DCOLOR_ARGB(a, r, g, b));
}




//


// ESP STUFF


//





float deltaDistance(Vector3 start, Vector3 end) {
	float dist = sqrtf(pow(start.x - end.x, 2) + pow(start.y - end.y, 2) + pow(start.z - end.z, 2));
	return dist;
}

int dot(Vector3 vector_a, Vector3 vector_b) {
	int product = 0;

	product = product + vector_a.x * vector_b.x;
	product = product + vector_a.y * vector_b.y;
	product = product + vector_a.z * vector_b.z;

	return product;
}

// Draw Characters on screen to form BOX esp
void Paint::espDrawCharOverlay(Vector3 centerPos, Vector3 targetPos, refdef_t viewport) {
	float distance = deltaDistance(centerPos, targetPos);
	if (distance > 6000) {
		return; // To far
	}

	// Draw Box esp
	Vector2 positionFeet = WorldToScreen(
		targetPos,
		centerPos,
		viewport.width,
		viewport.height,
		viewport.view.tanHalfFov,
		viewport.view.axis
	);
	Vector3 targetPos2 = Vector3(targetPos.x, targetPos.y, targetPos.z + 66);
	Vector2 positionHead = WorldToScreen(
		targetPos2,
		centerPos,
		viewport.width,
		viewport.height,
		viewport.view.tanHalfFov,
		viewport.view.axis
	);

	float heightDiff = positionFeet.y - positionHead.y;

	//if (!(positionFeet.x < 1 || positionFeet.y < 1 || (positionFeet.x > viewport.width) || (positionFeet.y > viewport.height))) {
		// If not out of screen bounds DRAW
		drawRectFromVector(ImVec2(positionFeet.x - heightDiff / 4, positionFeet.y), ImVec2(positionFeet.x + heightDiff / 4, positionFeet.y - heightDiff), ImVec4(1, 255, 0, 1));
		int distMeters = (int)ceil(distance * .025);
		std::string displayString = "[" + std::to_string(distMeters) + "m]";
		drawTextFromVector(ImVec2(positionFeet.x - heightDiff / 4, positionFeet.y), displayString.c_str(), ImVec4(1.0f, 0, 0, 255.0f));
		drawText((LPCSTR)std::to_string(targetPos.x).c_str(), 25, 75, 1, 255, 0, 0);
	//}
}

Vector2 Paint::WorldToScreen(Vector3 worldLocation, Vector3 cameraPosition, int screenWidth, int screenHeight, Vector2 fieldOfView, Vector3* matrices)
{
	Vector3 local = (worldLocation - cameraPosition); // worldLocation - cameraPosition;
	Vector3 trans = Vector3(dot(local, matrices[1]), dot(local, matrices[2]), dot(local, matrices[0]));

	if (trans.z < 0.01f)
		return Vector2();

	float x = (((float)screenWidth / 2) * (1 - (trans.x / fieldOfView.x / trans.z)));
	float y = (((float)screenHeight / 2) * (1 - (trans.y / fieldOfView.y / trans.z)));
	return Vector2(x, y);
}

// Refresh all decrypted pointers on feature start or new game.
void Paint::refreshAllPointers() {
	intervalCount = RefreshInterval;
	characterArray.clear();
	clientDecryptKeys[0] = 0;
	refDefKey = 0;
	myIndexNum = 0;
	CameraPointer = 0;
}

std::vector<characterInfo_t*> GetMaxEntitys() {
	std::vector<characterInfo_t*> vEntityVec;
	auto Cg_Entities = addresses.ClientBase_t;
	int index = 0;
	characterInfo_t* pEntity = (characterInfo_t*)(Cg_Entities + CHARACTER_STRUCT_SIZE * index);
	while (pEntity)
	{
		index++;
		pEntity = (characterInfo_t*)(Cg_Entities + CHARACTER_STRUCT_SIZE * index);
		if (!pEntity)
			break;
		else if (pEntity->team == 1 && pEntity->infoValid & 1)
			vEntityVec.push_back(pEntity);
	}

	return vEntityVec;

}

// Decrypt all the pointers, Read in the Character array, Draw each player.
void Paint::collectPlayersDrawRadar() {
	intervalCount++;

	// Decrypt nessecary pointers, Refresh pointers every 5 seconds
	if (intervalCount > RefreshInterval) {
		intervalCount = 0;

		characterArray = GetMaxEntitys();
		
		/*DWORD64 clientInfoPtr = addresses.ClientInfo_t;
		if (clientInfoPtr) {
			DWORD64 characterArrayPtr = addresses.ClientBase_t;
			if (characterArrayPtr) {
				DWORD64 LocalInfo = Read<DWORD64>(clientInfoPtr + client_LOCAL_INDEX_OFFSET);
				myIndexNum = Read<DWORD64>(LocalInfo + client_local_index_data_offset); // Index of my Character info in Array
				CameraPointer = Read<DWORD64>(addresses.ClientInfo_t + client_CAMERA_POS);
				// Read in entire array of Characters, Equivalent to ReadRequest<characterInfo_t>(characterArrayPtr + (i * clientinfo_t_size))
				std::vector<characterInfo_t*> newArr;
				for (int i = 0; i < 155; i++) {
					characterInfo_t *character = Read<characterInfo_t*>(characterArrayPtr + (i * CHARACTER_STRUCT_SIZE));
					newArr.push_back(character);
				}
				characterArray = newArr;

				std::cout << newArr[0]->stance << std::endl;
				std::cout << newArr[1]->stance << std::endl;
				std::cout << newArr[2]->stance << std::endl;
				std::cout << newArr[3]->stance << std::endl;
				std::cout << newArr[4]->stance << std::endl;
				std::cout << newArr[5]->stance << std::endl;
				std::cout << newArr[6]->stance << std::endl;
				std::cout << newArr[7]->stance << std::endl;
				std::cout << newArr[8]->stance << std::endl;
				std::cout << newArr[9]->stance << std::endl;
				std::cout << newArr[10]->stance << std::endl;
				
			}
		}*/
	}

	// Loop through all the characters and Draw their Positions
	if (characterArray.size() > 1) {
		// Get camera
		refdef_t refDef = Read<refdef_t>(DecryptRefDef());
		Vector3 CameraLoc = Read<Vector3>(CameraPointer);

		for (auto const& ent_info : characterArray) {
			if (ent_info->infoValid == 1) {
				if (ent_info->entityNum != myIndexNum) {
					//if (ATree.origin.x != 0.0) {
					Vector3 origin = Read<Vector3>(ent_info->posPtr);
					//std::cout << "Character " << ent_info.entityNum << ": " << "Orign: X = " << origin.x << "; Y = " << origin.y << "; Z = " << origin.z << std::endl;
					espDrawCharOverlay(CameraLoc, origin, refDef);
					//}
				}
			}
		}
	}
}
#pragma once

#include <string> //save error
#include <Windows.h>
#include "structs.h"
#include <d3d9.h>
#include <d3dx9.h>
#pragma comment(lib, "d3d9.lib")
#pragma comment(lib, "d3dx9.lib")

#include <DxErr.h> //get error from error code
#pragma comment(lib, "dxerr.lib")
#pragma comment(lib, "legacy_stdio_definitions.lib")

class Paint {
private:
    IDirect3D9Ex* d3dObject = NULL; //used to create device
    IDirect3DDevice9Ex* d3dDevice = NULL; //contains functions like begin and end scene 
    D3DPRESENT_PARAMETERS d3dparams; //parameters for creating device
    ID3DXFont* d3dFont = 0; // font used when displaying text
    int width;
    int height;

    int d3D9Init(HWND hWnd);
    void drawText(LPCSTR String, int x, int y, int a, int r, int g, int b);
    void drawRect(int x, int y, unsigned char r, unsigned char g, unsigned char b);
    void drawRectFromVector(ImVec2 startpos, ImVec2 endpos, ImVec4 color);
    void drawTextFromVector(ImVec2 position, const char* String, ImVec4 color);

    Vector2 WorldToScreen(Vector3 worldLocation, Vector3 cameraPosition, int screenWidth, int screenHeight, Vector2 fieldOfView, Vector3* matrices);
    void espDrawCharOverlay(Vector3 centerPos, Vector3 targetPos, refdef_t viewport);
    void refreshAllPointers();
    void collectPlayersDrawRadar();
public:
    Paint();
    Paint(HWND hWnd, int width, int height);
    int render();
};
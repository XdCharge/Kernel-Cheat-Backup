#include "resource.h"
#include "structs.h"

#define QWORD unsigned __int64

class RefdefView {
public:
	Vector2 tanHalfFov;         // 0x00
	unsigned __int8 unk1[0xC];  // 0x08
	Vector3 axis[3];            // 0x14
};

class refdef_t {
public:
	int x;      // 0x00
	int y;      // 0x04
	int width;  // 0x08
	int height; // 0x0C
	RefdefView view;             // 0x10
};

enum class CharacterStance : unsigned char {
	Standing = 0,
	Crouching = 1,
	Crawling = 2,
	Downed = 3,
};

class characterInfo_t
{
public:
	unsigned __int8 unk1[0x3F4];    // 0x00
	unsigned short weaponIndex;     // 0x3F4
	unsigned __int8 unk2[0x3AA];    // 0x3F6
	int stance;                     // 0x7A0
	unsigned __int8 unk3[0x80C];    // 0x7A4
	int infoValid;                  // 0xFB0
	unsigned __int8 unk4[0x8];      // 0xFB4
	int entityNum;                  // 0xFBC
	unsigned __int8 unk5[0x458];    // 0xFC0
	int deathV2;                    // 0x1418
	unsigned __int8 unk6[0x58];     // 0x141C
	int deathV1;                    // 0x1474
	unsigned __int8 unk7[0x8];      // 0x1478
	QWORD posPtr;                   // 0x1480
	unsigned __int8 unk8[0x2544];   // 0x1488
	int team;                       // 0x39CC
	unsigned __int8 unk9[0x50];     // 0x39D0
};      // 0x3A20
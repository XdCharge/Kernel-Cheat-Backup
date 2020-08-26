#pragma once
#include <Windows.h>
#include <vector>
#include "sstream"

struct AddressStruct {
	DWORD64 ClientInfo_t;
	DWORD64 ClientBase_t;
	DWORD64 Entity_t;
} addresses;

#ifndef IM_ASSERT
#include <assert.h>
#define IM_ASSERT(_EXPR)            assert(_EXPR)                               // You can override the default assert handler by editing imconfig.h
#endif

struct ImVec2
{
    float     x, y;
    ImVec2() { x = y = 0.0f; }
    ImVec2(float _x, float _y) { x = _x; y = _y; }
    float  operator[] (size_t idx) const { IM_ASSERT(idx <= 1); return (&x)[idx]; }    // We very rarely use this [] operator, the assert overhead is fine.
    float& operator[] (size_t idx) { IM_ASSERT(idx <= 1); return (&x)[idx]; }    // We very rarely use this [] operator, the assert overhead is fine.
#ifdef IM_VEC2_CLASS_EXTRA
    IM_VEC2_CLASS_EXTRA     // Define additional constructors and implicit cast operators in imconfig.h to convert back and forth between your math types and ImVec2.
#endif
};

// 4D vector (often used to store floating-point colors)
struct ImVec4
{
    float     x, y, z, w;
    ImVec4() { x = y = z = w = 0.0f; }
    ImVec4(float _x, float _y, float _z, float _w) { x = _x; y = _y; z = _z; w = _w; }
#ifdef IM_VEC4_CLASS_EXTRA
    IM_VEC4_CLASS_EXTRA     // Define additional constructors and implicit cast operators in imconfig.h to convert back and forth between your math types and ImVec4.
#endif
};

class Vector2
{
public:
    Vector2() : x(0.f), y(0.f)
    {

    }

    Vector2(float _x, float _y) : x(_x), y(_y)
    {

    }
    ~Vector2()
    {

    }

    float x;
    float y;
};

//Vector3
class Vector3
{
public:
    Vector3() : x(0.f), y(0.f), z(0.f)
    {

    }

    Vector3(float _x, float _y, float _z) : x(_x), y(_y), z(_z)
    {

    }
    ~Vector3()
    {

    }

    float x;
    float y;
    float z;

    inline float Dot(Vector3 v)
    {
        return x * v.x + y * v.y + z * v.z;
    }

    inline float Distance(Vector3 v)
    {
        return float(sqrtf(powf(v.x - x, 2.0) + powf(v.y - y, 2.0) + powf(v.z - z, 2.0)));
    }
    inline float Length()
    {
        float ls = x * x + y * y + z * z;
        return sqrt(ls);
    }

    Vector3 operator+(Vector3 v)
    {
        return Vector3(x + v.x, y + v.y, z + v.z);
    }

    Vector3 operator-(Vector3 v)
    {
        return Vector3(x - v.x, y - v.y, z - v.z);
    }

    Vector3 operator*(float number) const {
        return Vector3(x * number, y * number, z * number);
    }

    Vector3& operator-=(const Vector3& v)
    {
        x -= v.x;
        y -= v.y;
        z -= v.z;

        return *this;
    }

    Vector3 operator-(const Vector3& v) const
    {
        return Vector3(x - v.x, y - v.y, z - v.z);
    }


    void clamp()
    {
        if (x > 75.f) x = 75.f;
        else if (x < -75.f) x = -75.f;
        if (z < -180) z += 360.0f;
        else if (z > 180) z -= 360.0f;

        y = 0.f;
    }

    bool IsZero()
    {
        if (x == 0 && y == 0 && z == 0)
            return true;
        else
            return false;
    }

};

//Vector4
class Vector4
{
public:
    Vector4() : x(0.f), y(0.f), z(0.f), w(0.f)
    {

    }

    Vector4(float _x, float _y, float _z, float _w) : x(_x), y(_y), z(_z), w(_w)
    {

    }
    ~Vector4()
    {

    }

    float x;
    float y;
    float z;
    float w;
};
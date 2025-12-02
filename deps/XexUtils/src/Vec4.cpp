#include "pch.h"
#include "Vec4.h"

namespace XexUtils
{
namespace Math
{

vec4::vec4()
    : x(0.0f), y(0.0f), z(0.0f), w(0.0f)
{
}

vec4::vec4(float x, float y, float z, float w)
    : x(x), y(y), z(z), w(w)
{
}

float vec4::magnitude() const
{
    return sqrtf(x * x + y * y + z * z + w * w);
}

vec4 vec4::normalize() const
{
    return *this / magnitude();
}

void vec4::add(const vec4 &other)
{
    x += other.x;
    y += other.y;
    z += other.z;
    w += other.w;
}

void vec4::substract(const vec4 &other)
{
    x -= other.x;
    y -= other.y;
    z -= other.z;
    w -= other.w;
}

void vec4::multiply(const vec4 &other)
{
    x *= other.x;
    y *= other.y;
    z *= other.z;
    w *= other.w;
}

void vec4::multiply(const float &multiplier)
{
    x *= multiplier;
    y *= multiplier;
    z *= multiplier;
    w *= multiplier;
}

void vec4::divide(const vec4 &other)
{
    x /= other.x;
    y /= other.y;
    z /= other.z;
    w /= other.w;
}

void vec4::divide(const float &divider)
{
    x /= divider;
    y /= divider;
    z /= divider;
    w /= divider;
}

bool vec4::isNull() const
{
    return x == 0.0f && y == 0.0f && z == 0.0f && w == 0.0f;
}

bool vec4::operator==(const vec4 &other) const
{
    return x == other.x && y == other.y && z == other.z && w == other.w;
}

bool vec4::operator!=(const vec4 &other) const
{
    return x != other.x || y != other.y || z != other.z || w != other.w;
}

bool vec4::operator<(const vec4 &other) const
{
    return magnitude() < other.magnitude();
}

bool vec4::operator<=(const vec4 &other) const
{
    return magnitude() <= other.magnitude();
}

bool vec4::operator>(const vec4 &other) const
{
    return magnitude() > other.magnitude();
}

bool vec4::operator>=(const vec4 &other) const
{
    return magnitude() >= other.magnitude();
}

vec4 vec4::operator+(const vec4 &other) const
{
    return vec4(x + other.x, y + other.y, z + other.z, w + other.w);
}

vec4 vec4::operator-(const vec4 &other) const
{
    return vec4(x - other.x, y - other.y, z - other.z, w - other.w);
}

vec4 vec4::operator*(const vec4 &other) const
{
    return vec4(x * other.x, y * other.y, z * other.z, w * other.w);
}

vec4 vec4::operator*(const float &multiplier) const
{
    return vec4(x * multiplier, y * multiplier, z * multiplier, w * multiplier);
}

vec4 vec4::operator/(const vec4 &other) const
{
    return vec4(x / other.x, y / other.y, z / other.z, w / other.w);
}

vec4 vec4::operator/(const float &divider) const
{
    return vec4(x / divider, y / divider, z / divider, w / divider);
}

vec4 vec4::operator-() const
{
    return vec4(-x, -y, -z, -w);
}

}
}

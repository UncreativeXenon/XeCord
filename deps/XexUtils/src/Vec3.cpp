#include "pch.h"
#include "Vec3.h"

namespace XexUtils
{
namespace Math
{

vec3::vec3()
    : x(0.0f), y(0.0f), z(0.0f)
{
}

vec3::vec3(float x, float y, float z)
    : x(x), y(y), z(z)
{
}

float vec3::magnitude() const
{
    return sqrtf(x * x + y * y + z * z);
}

vec3 vec3::normalize() const
{
    return *this / magnitude();
}

void vec3::add(const vec3 &other)
{
    x += other.x;
    y += other.y;
    z += other.z;
}

void vec3::substract(const vec3 &other)
{
    x -= other.x;
    y -= other.y;
    z -= other.z;
}

void vec3::multiply(const vec3 &other)
{
    x *= other.x;
    y *= other.y;
    z *= other.z;
}

void vec3::multiply(const float &multiplier)
{
    x *= multiplier;
    y *= multiplier;
    z *= multiplier;
}

void vec3::divide(const vec3 &other)
{
    x /= other.x;
    y /= other.y;
    z /= other.z;
}

void vec3::divide(const float &divider)
{
    x /= divider;
    y /= divider;
    z /= divider;
}

bool vec3::isNull() const
{
    return x == 0.0f && y == 0.0f && z == 0.0f;
}

bool vec3::operator==(const vec3 &other) const
{
    return x == other.x && y == other.y && z == other.z;
}

bool vec3::operator!=(const vec3 &other) const
{
    return x != other.x || y != other.y || z != other.z;
}

bool vec3::operator<(const vec3 &other) const
{
    return magnitude() < other.magnitude();
}

bool vec3::operator<=(const vec3 &other) const
{
    return magnitude() <= other.magnitude();
}

bool vec3::operator>(const vec3 &other) const
{
    return magnitude() > other.magnitude();
}

bool vec3::operator>=(const vec3 &other) const
{
    return magnitude() >= other.magnitude();
}

vec3 vec3::operator+(const vec3 &other) const
{
    return vec3(x + other.x, y + other.y, z + other.z);
}

vec3 vec3::operator-(const vec3 &other) const
{
    return vec3(x - other.x, y - other.y, z - other.z);
}

vec3 vec3::operator*(const vec3 &other) const
{
    return vec3(x * other.x, y * other.y, z * other.z);
}

vec3 vec3::operator*(const float &multiplier) const
{
    return vec3(x * multiplier, y * multiplier, z * multiplier);
}

vec3 vec3::operator/(const vec3 &other) const
{
    return vec3(x / other.x, y / other.y, z / other.z);
}

vec3 vec3::operator/(const float &divider) const
{
    return vec3(x / divider, y / divider, z / divider);
}

vec3 vec3::operator-() const
{
    return vec3(-x, -y, -z);
}

}
}

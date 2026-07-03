#pragma once

typedef struct _Vector3 {
	float x;
	float y;
	float z;
	_Vector3& operator/(float Amount) {
		x /= Amount;
		y /= Amount;
		z /= Amount;
		return *this;
	}
	_Vector3& operator/(const _Vector3& Vector) {
		x /= Vector.x;
		y /= Vector.y;
		z /= Vector.z;
		return *this;
	}
	_Vector3& operator*(float Amount) {
		x *= Amount;
		y *= Amount;
		z *= Amount;
		return *this;
	}
	_Vector3& operator*(const _Vector3& Vector) {
		x *= Vector.x;
		y *= Vector.y;
		z *= Vector.z;
		return *this;
	}
	_Vector3& operator+(float Amount) {
		x += Amount;
		y += Amount;
		z += Amount;
		return *this;
	}
	_Vector3& operator+(const _Vector3& Vector) {
		x += Vector.x;
		y += Vector.y;
		z += Vector.z;
		return *this;
	}
	_Vector3& operator-(float Amount) {
		x -= Amount;
		y -= Amount;
		z -= Amount;
		return *this;
	}
	_Vector3& operator-(const _Vector3& Vector) {
		x -= Vector.x;
		y -= Vector.y;
		z -= Vector.z;
		return *this;
	}
} Vector3, * PVector3;
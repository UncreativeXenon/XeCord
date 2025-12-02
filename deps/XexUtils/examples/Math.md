# Math

Add two three-component vectors together (check the [vec2](../include/Vec2.h), [vec3](../include/Vec3.h) and [vec4](../include/Vec4.h) structs to see all of the available operations):

```C++
void Init()
{
    XexUtils::Math::vec3 v1(1.0f, 2.0f, 3.0f);
    XexUtils::Math::vec3 v2(2.0f, 3.0f, 4.0f);

    XexUtils::Math::vec3 v3 = v1 + v2; // x: 3.0, y: 5.0, z: 7.0
}
```

Convert an angle from degrees to radians:

```C++
void Init()
{
    float degrees = 30.0f;
    float radians = XexUtils::Math::Radians(degrees); // 0.523599
}
```

Project a vector:

```C++
void Init()
{
    XexUtils::Math::vec3 myCurrentPosition = GetCurrentPosition();
    XexUtils::Math::vec3 myCurrentOrientation = GetCurrentOrientation();
    XexUtils::Math::vec3 TenUnitsInFrontOfMe = XexUtils::Math::ProjectForward(myCurrentPosition, myCurrentOrientation.y, 10.0f);
}
```

Round to the next multiple of a number:

```C++
void Init()
{
    XexUtils::Math::RoundToNextMultipleOf<3>(4); // => 6
    XexUtils::Math::RoundToNextMultipleOf<5>(2); // => 5

    XexUtils::Math::RoundToNextMultipleOf<4>(4); // => 8 (keep in mind it rounds to the NEXT multiple)
}
```

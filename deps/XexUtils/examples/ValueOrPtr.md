# ValueOrPtr

Manipulate both a value and a pointer seemlessly:

```C++
void Init()
{
    int myInt = 3;

    XexUtils::ValueOrPtr<int> v1(myInt);
    v1 = 4;
    printf("myInt: %d, v1: %d\n", myInt, v1); // myInt: 3, v1: 4  =>  myInt was not changed

    XexUtils::ValueOrPtr<int> v2(&myInt);
    v2 = 4;
    printf("myInt: %d, v2: %d\n", myInt, v1); // myInt: 4, v2: 4  =>  myInt was changed
}
```

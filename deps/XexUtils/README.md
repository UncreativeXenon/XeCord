# XexUtils

XexUtils is a library to make Xbox 360 applications and/or libraries.

## Installation

### With pre-compiled binaries

-   Download the latest binaries and header files from the [releases](https://github.com/ClementDreptin/XexUtils/releases).
-   From Visual Studio, right click on your project, go to `Properties` and then:
    -   Add `\path\to\XexUtils\lib` to `Configuration Properties > Linker > General > Additional Libary Directories`.
    -   Add `XexUtils.lib` (or `XexUtilsd.lib` for the debug version) to `Configuration Properties > Linker > Input > Additional Dependencies`.
    -   Add `\path\to\XexUtils\include` to `Configuration Properties > C/C++ > General > Additional Include Directories`.

### Compiling from source

-   Clone the repository with its submodule. XexUtils depends on [BearSSL](https://bearssl.org/).
    ```
    git clone --recursive https://github.com/ClementDreptin/XexUtils.git
    ```
-   Add XexUtils as a project in Visual Studio:&nbsp;
    Right click on the solution name in the solution explorer then `Add > Existing Project...` and select `XexUtils.vcxproj` in `\path\to\XexUtils`.
-   Add it as a reference to your main project:&nbsp;
    Right click on your main project in the solution explorer then `Add > Reference...`, tick `XexUtils` and click OK.
-   Add BearSSL as a project in Visual Studio:&nbsp;
    Right click on the solution name in the solution explorer then `Add > Existing Project...` and select `BearSSL.vcxproj` in `\path\to\XexUtils\deps\BearSSL.vcxproj`.

## Documentation

You can look at the [examples](./examples) directory, which will show you a basic usage of every public function. If you want a detailed API reference, you can look at the Doxygen comments in the [source header files](./src), which should display on hover in your editor if it's modern enough.

## Running the tests

The tests are an app that runs **on the console** and is deployed to the `devkit:\Tests` directory (same as `hdd:\DEVKIT\Tests`).

### Visual Studio 2010

Open `test\Tests.sln` in Visual Studio.

**Note**: Using Visual Studio 2010 is the only way to run the test app in a debugger (sadly).

### Visual Studio 2022 (or any environment)

You can't build with the 64-bit version of MSBuild so you'll need to run the 32-bit version manually. Open PowerShell (which can be done in `View > Terminal` in Visual Studio) and run the following command:

```PS1
# Create an alias to the 32-bit version of MSBuild named msbuild
# The default installation path of VS2022 is C:\Program Files\Microsoft Visual Studio\2022\Community
Set-Alias msbuild "<path_vs2022>\MSBuild\Current\Bin\MSBuild.exe"
```

Now run `msbuild` to compile the test app and deploy it to your console.

## Acknowledgements

-   [BearSSL](https://bearssl.org/) - The TLS implementation used in sockets.
-   [XboxTLS](https://github.com/JakobRangel/XboxTLS) - What inspired and showed how to integrate BearSSL in an Xbox 360 environment.

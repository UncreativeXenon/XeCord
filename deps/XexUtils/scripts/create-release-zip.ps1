$ErrorActionPreference = "Stop"

$RootDir = "$PSScriptRoot\.."
$TestDir = "$RootDir\test"

function BuildTests {
    # Path to the 32-bit version of MSBuild
    $MsbuildExePath = "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"

    # Build the tests for both build configurations
    $BuildConfigs = @("Debug", "Release")
    foreach ($BuildConfig in $BuildConfigs) {
        & $MsbuildExePath "$TestDir\Tests.sln" /p:Configuration=$BuildConfig
        if (-not $?) {
            throw "Couldn't build tests in $BuildConfig config."
        }
    }
}

function CreateZip {
    $BuildDir = "$TestDir\build"
    $IncludeDir = "$RootDir\include"
    $SrcDir = "$RootDir\src"
    $DebugLib = "$BuildDir\Debug\bin\XexUtilsd.lib"
    $ReleaseLib = "$BuildDir\Release\bin\XexUtils.lib"
    $OutputZip = "$RootDir\XexUtils.zip"

    # Create a temporary directory which has the same structure as the output zip
    $TmpDir = "$([System.IO.Path]::GetTempPath())\XexUtils"
    $TmpIncludeDir = "$TmpDir\include"
    $TmpSrcDir = "$TmpDir\src"
    $TmpLibDir = "$TmpDir\lib"
    New-Item -ItemType Directory -Path $TmpDir -Force
    New-Item -ItemType Directory -Path $TmpIncludeDir, $TmpLibDir, $TmpSrcDir -Force

    # Copy the appropriate files into the temporary directory
    Get-ChildItem -Path $IncludeDir -Filter *.h | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $TmpIncludeDir
    }
    Get-ChildItem -Path $SrcDir -Filter *.h | ForEach-Object {
        Copy-Item -Path $_.FullName -Destination $TmpSrcDir
    }
    Copy-Item -Path $DebugLib -Destination $TmpLibDir
    Copy-Item -Path $ReleaseLib -Destination $TmpLibDir

    # Create the zip
    Compress-Archive -Path "$TmpDir\*" -DestinationPath $OutputZip -Force

    # Remove the temporary directory
    Remove-Item -Path $TmpDir -Recurse -Force
}

BuildTests

CreateZip

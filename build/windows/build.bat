@echo off
setlocal
pushd "%~dp0\..\.."
if errorlevel 1 exit /b 1

set "REQUIRE_CUDA=0"
if /I "%~1"=="--require-cuda" set "REQUIRE_CUDA=1"
if /I "%CUDA_REQUIRED%"=="1" set "REQUIRE_CUDA=1"
set "CUDA_DISABLED=0"
if /I "%~1"=="--no-cuda" set "CUDA_DISABLED=1"
if /I "%~2"=="--no-cuda" set "CUDA_DISABLED=1"
if "%REQUIRE_CUDA%"=="1" if "%CUDA_DISABLED%"=="1" (
    echo [ERROR] --require-cuda and --no-cuda cannot be used together.
    goto :build_failed
)
if not defined CUDA_ARCH set "CUDA_ARCH=sm_61"

:: Locate Visual Studio C++ build tools unless the caller selected an installation.
if not defined VS_PATH (
    for /f "usebackq tokens=*" %%I in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_PATH=%%I"
)
if not defined VS_PATH (
    echo [ERROR] Visual Studio 2022 C++ build tools were not found. Set VS_PATH to the installation directory.
    goto :build_failed
)
if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" (
    echo [ERROR] vcvarsall.bat was not found under "%VS_PATH%".
    goto :build_failed
)

:: Respect an explicit toolkit selection; otherwise detect an installed toolkit,
:: then try NVCC on PATH. This also handles newly installed toolkits before the
:: current shell has reloaded its environment variables.
if "%CUDA_DISABLED%"=="1" set "CUDA_PATH="
if "%CUDA_DISABLED%"=="0" if not defined CUDA_PATH (
    for /d %%I in ("%ProgramFiles%\NVIDIA GPU Computing Toolkit\CUDA\v12.*") do if exist "%%~fI\bin\nvcc.exe" set "CUDA_PATH=%%~fI"
)
if "%CUDA_DISABLED%"=="0" if not defined CUDA_PATH (
    for /f "delims=" %%N in ('where nvcc.exe 2^>nul') do if not defined CUDA_PATH set "CUDA_PATH=%%~dpN.."
)
if "%CUDA_DISABLED%"=="0" if defined CUDA_PATH for %%I in ("%CUDA_PATH%") do set "CUDA_PATH=%%~fI"

if "%REQUIRE_CUDA%"=="1" if not defined CUDA_PATH (
    echo [ERROR] CUDA was required but no CUDA Toolkit/nvcc installation was found.
    goto :build_failed
)

:: Keep intermediate files isolated and preserve the previous executable on failure.
if not exist "build\.cache" mkdir "build\.cache"
if errorlevel 1 goto :build_failed
del /q "build\.cache\cerberus.obj" "build\.cache\opencl_kernels.obj" "build\.cache\crypt_blowfish.obj" "build\.cache\gpu_kernels.obj" "build\.cache\cerberus.exe" 2>nul

:: Setup MSVC Environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
if %errorlevel% neq 0 (
    echo [ERROR] Failed to setup MSVC environment.
    goto :build_failed
)

:: Resolve include and lib flags
set "EXTRA_INC=/Idependencies\opencl\include"
set "EXTRA_LIB="

if defined CUDA_PATH (
    if exist "%CUDA_PATH%\include" set "EXTRA_INC=%EXTRA_INC% /I"%CUDA_PATH%\include""
    if exist "%CUDA_PATH%\lib\x64" set "EXTRA_LIB=%EXTRA_LIB% /LIBPATH:"%CUDA_PATH%\lib\x64""
)

:: Compile CUDA Code (if nvcc is available)
set "CUDA_OBJ="
set "CUDA_DEF="
if defined CUDA_PATH (
    if exist "%CUDA_PATH%\bin\nvcc.exe" (
        if exist "%CUDA_PATH%\lib\x64\cudart.lib" (
            echo [CUDA] Compiling GPU Kernels...
            echo [CUDA] Target architecture: %CUDA_ARCH%
            "%CUDA_PATH%\bin\nvcc.exe" -O3 -allow-unsupported-compiler -arch=%CUDA_ARCH% -Xcompiler=/MT -c "src\algorithms\gpu_kernels.cu" -o "build\.cache\gpu_kernels.obj" -I"%CUDA_PATH%\include"
            if not errorlevel 1 (
                set "CUDA_OBJ=build\.cache\gpu_kernels.obj cudart.lib"
                set "CUDA_DEF=/DENABLE_CUDA"
            ) else (
                if "%REQUIRE_CUDA%"=="1" (
                    echo [ERROR] CUDA compilation failed and CUDA was required.
                    goto :build_failed
                )
                echo [WARNING] CUDA compilation failed. Continuing with OpenCL only.
            )
        ) else (
            if "%REQUIRE_CUDA%"=="1" (
                echo [ERROR] CUDA runtime library cudart.lib was not found.
                goto :build_failed
            )
            echo [WARNING] CUDA runtime library cudart.lib not found. Continuing with OpenCL only.
        )
    ) else if "%REQUIRE_CUDA%"=="1" (
        echo [ERROR] nvcc.exe was not found under "%CUDA_PATH%\bin".
        goto :build_failed
    )
)

if not defined CUDA_OBJ (
    if "%REQUIRE_CUDA%"=="1" (
        echo [ERROR] CUDA was required but no CUDA object was produced.
        goto :build_failed
    )
    echo [INFO] Building with OpenCL and Multi-threaded CPU engines.
    if "%CUDA_DISABLED%"=="1" (
        echo [INFO] CUDA was disabled by --no-cuda.
    ) else if not defined CUDA_PATH (
        echo [INFO] CUDA_PATH is unset and nvcc was not found on PATH; CUDA support is disabled.
    )
)

:: Compile C++ Host Code with C++20
echo [CPP] Compiling Host Code (C++20)...
cl.exe /EHsc /std:c++20 /utf-8 /O2 /MT %CUDA_DEF% /c "src\cerberus.cpp" /Fo:"build\.cache\cerberus.obj" %EXTRA_INC%
if %errorlevel% neq 0 (
    echo [ERROR] Host Code Compilation Failed!
    goto :build_failed
)

cl.exe /EHsc /std:c++20 /utf-8 /O2 /MT /c "src\algorithms\opencl_kernels.cpp" /Fo:"build\.cache\opencl_kernels.obj" %EXTRA_INC%
if %errorlevel% neq 0 (
    echo [ERROR] OpenCL Kernels Compilation Failed!
    goto :build_failed
)

cl.exe /O2 /MT /c "dependencies\crypt_blowfish\crypt_blowfish.c" /Fo:"build\.cache\crypt_blowfish.obj"
if %errorlevel% neq 0 (
    echo [ERROR] bcrypt implementation compilation failed!
    goto :build_failed
)

:: Link
echo [LINK] Linking Executable...
link.exe /OUT:"build\.cache\cerberus.exe" "build\.cache\cerberus.obj" "build\.cache\opencl_kernels.obj" "build\.cache\crypt_blowfish.obj" %CUDA_OBJ% %EXTRA_LIB%
if %errorlevel% neq 0 (
    echo [ERROR] Linking Failed!
    goto :build_failed
)

:: A CUDA-enabled executable requires the CUDA runtime DLL beside it on target machines.
if defined CUDA_OBJ (
    echo [CUDA] CUDA backend is enabled in the executable.
    if not exist "%CUDA_PATH%\bin\cudart64_*.dll" (
        echo [ERROR] CUDA runtime DLL is missing; cannot package the CUDA-enabled executable.
        goto :build_failed
    )
    copy /Y "%CUDA_PATH%\bin\cudart64_*.dll" "." >nul
    if errorlevel 1 (
        echo [ERROR] Could not copy the CUDA runtime DLLs.
        goto :build_failed
    )
)

move /Y "build\.cache\cerberus.exe" "cerberus.exe" >nul
if errorlevel 1 (
    echo [ERROR] Could not install the new executable; the previous one was preserved.
    goto :build_failed
)

echo [SUCCESS] Build Complete: "cerberus.exe"
set "BUILD_EXIT=0"
goto :build_done

:build_failed
set "BUILD_EXIT=1"

:build_done
popd
endlocal & exit /b %BUILD_EXIT%

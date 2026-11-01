@echo off
setlocal

:: Define Visual Studio path if not set
if not defined VS_PATH set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community"

:: Detect CUDA Path dynamically if not set
if not defined CUDA_PATH (
    for /d %%D in ("C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v*") do (
        set "CUDA_PATH=%%D"
    )
)

:: Cleanup previous build outputs
if exist "cerberus.exe" del "cerberus.exe"
if exist "cerberus.obj" del "cerberus.obj"
if exist "Brute Force Methods.exe" del "Brute Force Methods.exe"
if exist "Brute Force Methods.obj" del "Brute Force Methods.obj"
if exist "opencl_kernels.obj" del "opencl_kernels.obj"
if exist "gpu_kernels.obj" del "gpu_kernels.obj"

:: Setup MSVC Environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
if %errorlevel% neq 0 (
    echo [ERROR] Failed to setup MSVC environment.
    exit /b 1
)

:: Resolve include and lib flags
set "EXTRA_INC=/Iinclude"
set "EXTRA_LIB=/LIBPATH:lib\x64"

if defined CUDA_PATH (
    if exist "%CUDA_PATH%\include" set "EXTRA_INC=%EXTRA_INC% /I"%CUDA_PATH%\include""
    if exist "%CUDA_PATH%\lib\x64" set "EXTRA_LIB=%EXTRA_LIB% /LIBPATH:"%CUDA_PATH%\lib\x64""
)

:: Compile CUDA Code (if nvcc is available)
set "CUDA_OBJ="
set "CUDA_DEF="
if defined CUDA_PATH (
    if exist "%CUDA_PATH%\bin\nvcc.exe" (
        echo [CUDA] Compiling GPU Kernels...
        "%CUDA_PATH%\bin\nvcc.exe" -O3 -allow-unsupported-compiler -c "gpu_kernels.cu" -o "gpu_kernels.obj" -I"%CUDA_PATH%\include"
        if %errorlevel% equ 0 (
            set "CUDA_OBJ=gpu_kernels.obj cudart.lib"
            set "CUDA_DEF=/DENABLE_CUDA"
        ) else (
            echo [WARNING] CUDA compilation failed. Continuing with OpenCL only.
        )
    )
)

if not defined CUDA_OBJ (
    echo [INFO] Building with OpenCL and Multi-threaded CPU engines.
)

:: Compile C++ Host Code with C++20
echo [CPP] Compiling Host Code (C++20)...
cl.exe /EHsc /std:c++20 /O2 %CUDA_DEF% /c "cerberus.cpp" /Fo:"cerberus.obj" %EXTRA_INC%
if %errorlevel% neq 0 (
    echo [ERROR] Host Code Compilation Failed!
    exit /b 1
)

cl.exe /EHsc /std:c++20 /O2 /c "opencl_kernels.cpp" /Fo:"opencl_kernels.obj" %EXTRA_INC%
if %errorlevel% neq 0 (
    echo [ERROR] OpenCL Kernels Compilation Failed!
    exit /b 1
)

:: Link
echo [LINK] Linking Executable...
link.exe /OUT:"cerberus.exe" "cerberus.obj" "opencl_kernels.obj" %CUDA_OBJ% OpenCL.lib %EXTRA_LIB%
if %errorlevel% neq 0 (
    echo [ERROR] Linking Failed!
    exit /b 1
)

echo [SUCCESS] Build Complete: "cerberus.exe"
endlocal

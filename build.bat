@echo off
setlocal

:: Define paths (adjust if needed)
set "VS_PATH=C:\Program Files\Microsoft Visual Studio\2022\Community"
set "CUDA_PATH=C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1"

:: Cleanup
if exist "Brute Force Methods.exe" del "Brute Force Methods.exe"
if exist "Brute Force Methods.obj" del "Brute Force Methods.obj"
if exist "gpu_kernels.obj" del "gpu_kernels.obj"

:: Setup MSVC Environment
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
if %errorlevel% neq 0 (
    echo [ERROR] Failed to setup MSVC environment.
    exit /b 1
)

:: Compile C++ Host Code
echo [CPP] Compiling Host Code...
cl.exe /EHsc /c "Brute Force Methods.cpp" /Fo:"Brute Force Methods.obj" /I"%CUDA_PATH%\include"
cl.exe /EHsc /c "opencl_kernels.cpp" /Fo:"opencl_kernels.obj" /I"%CUDA_PATH%\include"
if %errorlevel% neq 0 (
    echo [ERROR] CL Compilation Failed!
    exit /b 1
)

:: Compile CUDA Code
if exist "%CUDA_PATH%\bin\nvcc.exe" (
    echo [CUDA] Compiling GPU Kernels...
    "%CUDA_PATH%\bin\nvcc.exe" -c "gpu_kernels.cu" -o "gpu_kernels.obj" -I"%CUDA_PATH%\include"
    set "CUDA_OBJ=gpu_kernels.obj cudart.lib"
) else (
    echo [WARNING] CUDA Compiler not found. Skipping CUDA build.
    set "CUDA_OBJ="
)

:: Link
echo [LINK] Linking Executable...
link.exe /OUT:"Brute Force Methods.exe" "Brute Force Methods.obj" "opencl_kernels.obj" %CUDA_OBJ% OpenCL.lib /LIBPATH:"%CUDA_PATH%\lib\x64"
if %errorlevel% neq 0 (
    echo [ERROR] Linking Failed!
    exit /b 1
)

echo [SUCCESS] Build Complete.
endlocal

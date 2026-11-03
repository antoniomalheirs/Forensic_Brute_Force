@echo off
setlocal EnableExtensions
pushd "%~dp0\.."
if errorlevel 1 exit /b 1

if not defined VSWHERE set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not defined VS_PATH (
    if not exist "%VSWHERE%" (
        echo [ERROR] vswhere.exe not found; install Visual Studio C++ build tools.
        popd
        exit /b 1
    )
    for /f "usebackq tokens=*" %%I in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_PATH=%%I"
)
if not defined VS_PATH (
    echo [ERROR] Visual Studio C++ x64 build tools were not found.
    popd
    exit /b 1
)

call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (
    popd
    exit /b 1
)

if not exist "build\.cache" mkdir "build\.cache"
if errorlevel 1 (
    popd
    exit /b 1
)

if /I not "%CERBERUS_TEST_CUDA%"=="1" goto :compile
if not defined CUDA_PATH (
    echo [ERROR] CERBERUS_TEST_CUDA=1 requires CUDA_PATH.
    popd
    exit /b 1
)
if not exist "%CUDA_PATH%\bin\nvcc.exe" (
    echo [ERROR] CERBERUS_TEST_CUDA=1 requires nvcc.exe.
    popd
    exit /b 1
)
pushd "build\.cache"
if errorlevel 1 (
    popd
    popd
    exit /b 1
)
set "CUDA_TEST_ARCH=%CERBERUS_TEST_CUDA_ARCH%"
if not defined CUDA_TEST_ARCH set "CUDA_TEST_ARCH=sm_61"
"%CUDA_PATH%\bin\nvcc.exe" -O2 -allow-unsupported-compiler -DCERBERUS_TESTING -arch=%CUDA_TEST_ARCH% -Xcompiler=/MT -c "..\..\src\algorithms\gpu_kernels.cu" -o "gpu_kernels_test.obj" -I"%CUDA_PATH%\include"
if errorlevel 1 (
    popd
    popd
    exit /b 1
)
popd
if errorlevel 1 (
    popd
    exit /b 1
)
set "PATH=%CUDA_PATH%\bin;%PATH%"

:compile
pushd "build\.cache"
if errorlevel 1 (
    popd
    exit /b 1
)
if /I not "%CERBERUS_TEST_CUDA%"=="1" goto :compile_cpu
cl.exe /nologo /EHsc /std:c++20 /utf-8 /O2 /MT /DENABLE_CUDA /DCERBERUS_TESTING /I..\..\dependencies\opencl\include /I..\..\dependencies\crypt_blowfish /I"%CUDA_PATH%\include" ..\..\tests\cpp\cerberus_unit_tests.cpp ..\..\src\algorithms\opencl_kernels.cpp ..\..\dependencies\crypt_blowfish\crypt_blowfish.c gpu_kernels_test.obj /Fe:cerberus_cpp_unit_tests.exe /link /LIBPATH:"%CUDA_PATH%\lib\x64" cudart.lib
if errorlevel 1 (
    popd
    exit /b 1
)
goto :run

:compile_cpu
cl.exe /nologo /EHsc /std:c++20 /utf-8 /O2 /MT /DCERBERUS_TESTING /I..\..\dependencies\opencl\include /I..\..\dependencies\crypt_blowfish ..\..\tests\cpp\cerberus_unit_tests.cpp ..\..\src\algorithms\opencl_kernels.cpp ..\..\dependencies\crypt_blowfish\crypt_blowfish.c /Fe:cerberus_cpp_unit_tests.exe
if errorlevel 1 (
    popd
    exit /b 1
)

:run
"cerberus_cpp_unit_tests.exe"
set "TEST_EXIT=%errorlevel%"
popd
if errorlevel 1 (
    popd
    exit /b 1
)
endlocal & exit /b %TEST_EXIT%

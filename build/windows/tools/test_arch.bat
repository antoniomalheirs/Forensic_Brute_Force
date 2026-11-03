@echo off
setlocal EnableExtensions EnableDelayedExpansion
pushd "%~dp0\..\..\.."
if errorlevel 1 exit /b 1

if not defined VS_PATH (
    for /f "usebackq tokens=*" %%I in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_PATH=%%I"
)
if not defined VS_PATH goto :setup_failed
if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" goto :setup_failed
if not defined CUDA_PATH (
    for /f "delims=" %%N in ('where nvcc.exe 2^>nul') do if not defined CUDA_PATH set "CUDA_PATH=%%~dpN.."
)
if defined CUDA_PATH for %%I in ("%CUDA_PATH%") do set "CUDA_PATH=%%~fI"
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 goto :setup_failed
if not defined CUDA_PATH goto :setup_failed
if not exist "%CUDA_PATH%\bin\nvcc.exe" goto :setup_failed

if not defined CUDA_ARCHES (
    for /f "tokens=1" %%A in ('"%CUDA_PATH%\bin\nvcc.exe" --list-gpu-arch 2^>nul') do (
        set "ARCH=%%A"
        if /i "!ARCH:~0,8!"=="compute_" (
            set "ARCH=!ARCH:compute_=!"
            set "CUDA_ARCHES=!CUDA_ARCHES! !ARCH!"
        )
    )
)
if not defined CUDA_ARCHES (
    echo [ERROR] Could not detect supported architectures. Set CUDA_ARCHES, for example "80 86 89".
    goto :architecture_failed
)

if not exist "build\.cache" mkdir "build\.cache"
if errorlevel 1 goto :build_failed
set "FAILED=0"

for %%A in (%CUDA_ARCHES%) do (
    echo Testing sm_%%A...
    "%CUDA_PATH%\bin\nvcc.exe" -allow-unsupported-compiler -c "src\algorithms\gpu_kernels.cu" -arch=sm_%%A -o "build\.cache\test_arch_sm_%%A.obj"
    if errorlevel 1 (
        echo [FAIL] sm_%%A
        set "FAILED=1"
    ) else (
        echo [PASS] sm_%%A
    )
    if exist "build\.cache\test_arch_sm_%%A.obj" del /q "build\.cache\test_arch_sm_%%A.obj"
)

popd
endlocal & exit /b %FAILED%

:build_failed
echo [ERROR] Could not create the build\.cache directory.
popd
endlocal & exit /b 1

:setup_failed
echo [ERROR] Could not initialize MSVC or locate CUDA NVCC. Set VS_PATH and CUDA_PATH.
popd
endlocal & exit /b 1

:architecture_failed
popd
endlocal & exit /b 1

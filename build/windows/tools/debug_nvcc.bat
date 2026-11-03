@echo off
setlocal
pushd "%~dp0\..\..\.."
if errorlevel 1 exit /b 1
if not defined CUDA_ARCH set "CUDA_ARCH=sm_61"

if not defined VS_PATH (
    for /f "usebackq tokens=*" %%I in (`"%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath`) do set "VS_PATH=%%I"
)
if not defined VS_PATH (
    echo [ERROR] Visual Studio 2022 C++ build tools were not found. Set VS_PATH to the installation directory.
    goto :failed
)
if not defined CUDA_PATH (
    for /d %%I in ("%ProgramFiles%\NVIDIA GPU Computing Toolkit\CUDA\v12.*") do if exist "%%~fI\bin\nvcc.exe" set "CUDA_PATH=%%~fI"
)
if not defined CUDA_PATH (
    for /f "delims=" %%N in ('where nvcc.exe 2^>nul') do if not defined CUDA_PATH set "CUDA_PATH=%%~dpN.."
)
if defined CUDA_PATH for %%I in ("%CUDA_PATH%") do set "CUDA_PATH=%%~fI"

if not exist "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" (
    echo [ERROR] vcvarsall.bat was not found under "%VS_PATH%".
    goto :failed
)
call "%VS_PATH%\VC\Auxiliary\Build\vcvarsall.bat" x64
if errorlevel 1 (
    echo [ERROR] Failed to setup MSVC environment.
    goto :failed
)
if not defined CUDA_PATH (
    echo [ERROR] CUDA_PATH is not set and nvcc.exe was not found on PATH.
    goto :failed
)
if not exist "%CUDA_PATH%\bin\nvcc.exe" (
    echo [ERROR] nvcc.exe was not found under "%CUDA_PATH%\bin".
    goto :failed
)

if not exist "build\.cache" mkdir "build\.cache"
if errorlevel 1 goto :failed
"%CUDA_PATH%\bin\nvcc.exe" -allow-unsupported-compiler -arch=%CUDA_ARCH% -c "src\algorithms\gpu_kernels.cu" -o "build\.cache\gpu_kernels.obj"
set "NVCC_EXIT=%errorlevel%"
if not "%NVCC_EXIT%"=="0" (
    echo [ERROR] NVCC failed with exit code %NVCC_EXIT%.
) else (
    echo [SUCCESS] NVCC compilation completed.
)
pause
popd
endlocal & exit /b %NVCC_EXIT%

:failed
set "BUILD_EXIT=1"
pause
popd
endlocal & exit /b %BUILD_EXIT%

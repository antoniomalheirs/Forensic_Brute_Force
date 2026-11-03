@echo off
setlocal EnableExtensions
pushd "%~dp0"
if errorlevel 1 exit /b 1

set "SETUP_BUILD=0"
set "SETUP_BUILD_ARG="
if /I "%~1"=="--help" goto :help
if /I "%~1"=="--build" set "SETUP_BUILD=1"
if /I "%~1"=="--cpu-only" (
    set "SETUP_BUILD=1"
    set "SETUP_BUILD_ARG=--no-cuda"
)
if /I "%~1"=="--require-cuda" (
    set "SETUP_BUILD=1"
    set "SETUP_BUILD_ARG=--require-cuda"
)
if not "%~1"=="" if /I not "%~1"=="--build" if /I not "%~1"=="--cpu-only" if /I not "%~1"=="--require-cuda" goto :help
if not "%~2"=="" goto :help

if exist "cerberus.exe" if "%SETUP_BUILD%"=="0" goto :diagnose
if not exist "build\windows\build.bat" (
    echo [ERROR] Source build files are missing. This package contains only the runtime.
    set "SETUP_EXIT=1"
    goto :done
)

if "%SETUP_BUILD_ARG%"=="--no-cuda" goto :build
if not defined CUDA_ARCH (
    set "SETUP_GPU="
    where nvidia-smi.exe >nul 2>&1
    if not errorlevel 1 (
        for /f "tokens=*" %%G in ('nvidia-smi -L 2^>nul') do if not defined SETUP_GPU set "SETUP_GPU=%%G"
    )
    if defined SETUP_GPU (
        set "CUDA_ARCH=native"
        echo [SETUP] NVIDIA GPU detected. CUDA will target the GPU in this environment.
    ) else (
        set "CUDA_ARCH=all-major"
        echo [SETUP] No visible NVIDIA GPU. CUDA, if installed, will use portable major targets.
    )
) else (
    echo [SETUP] Keeping requested CUDA_ARCH=%CUDA_ARCH%.
)

:build
echo [SETUP] Building CERBERUS for this environment...
call "build\windows\build.bat" %SETUP_BUILD_ARG%
if errorlevel 1 (
    echo [ERROR] Build did not complete. Install Visual Studio C++ x64 tools; for CUDA, install a supported CUDA Toolkit.
    set "SETUP_EXIT=1"
    goto :done
)
if not exist "cerberus.exe" (
    echo [ERROR] Build completed without producing cerberus.exe.
    set "SETUP_EXIT=1"
    goto :done
)

:diagnose
echo.
echo [SETUP] Checking the runtime and local data files...
cerberus.exe doctor
set "SETUP_EXIT=%errorlevel%"
goto :done

:help
echo Usage: setup.bat [--build ^| --cpu-only ^| --require-cuda]
echo   no option      Check an existing CERBERUS runtime; build if it is absent.
echo   --build        Rebuild and adapt CUDA to the detected environment.
echo   --cpu-only     Rebuild with CPU and OpenCL; do not compile CUDA.
echo   --require-cuda Require a working CUDA build.
set "SETUP_EXIT=0"

:done
popd
endlocal & exit /b %SETUP_EXIT%

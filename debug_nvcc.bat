@echo off
call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
"C:\Program Files\NVIDIA GPU Computing Toolkit\CUDA\v13.1\bin\nvcc.exe" -arch=sm_50 -c gpu_kernels.cu -o gpu_kernels.obj
if %errorlevel% neq 0 (
    echo NVCC Failed with error %errorlevel%
) else (
    echo NVCC Succeeded
)
pause

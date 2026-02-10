@echo off
echo Testing sm_50...
nvcc -c gpu_kernels.cu -arch=sm_50 -o test_50.obj > nul 2>&1
if %errorlevel% equ 0 ( echo [PASS] sm_50 ) else ( echo [FAIL] sm_50 )

echo Testing sm_52...
nvcc -c gpu_kernels.cu -arch=sm_52 -o test_52.obj > nul 2>&1
if %errorlevel% equ 0 ( echo [PASS] sm_52 ) else ( echo [FAIL] sm_52 )

echo Testing sm_60...
nvcc -c gpu_kernels.cu -arch=sm_60 -o test_60.obj > nul 2>&1
if %errorlevel% equ 0 ( echo [PASS] sm_60 ) else ( echo [FAIL] sm_60 )

echo Testing sm_61...
nvcc -c gpu_kernels.cu -arch=sm_61 -o test_61.obj > nul 2>&1
if %errorlevel% equ 0 ( echo [PASS] sm_61 ) else ( echo [FAIL] sm_61 )

echo Testing sm_70...
nvcc -c gpu_kernels.cu -arch=sm_70 -o test_70.obj > nul 2>&1
if %errorlevel% equ 0 ( echo [PASS] sm_70 ) else ( echo [FAIL] sm_70 )

echo Testing sm_75...
nvcc -c gpu_kernels.cu -arch=sm_75 -o test_75.obj > nul 2>&1
if %errorlevel% equ 0 ( echo [PASS] sm_75 ) else ( echo [FAIL] sm_75 )

echo Testing sm_80...
nvcc -c gpu_kernels.cu -arch=sm_80 -o test_80.obj > nul 2>&1
if %errorlevel% equ 0 ( echo [PASS] sm_80 ) else ( echo [FAIL] sm_80 )

del test_*.obj 2>nul

@echo off
setlocal
pushd "%~dp0\..\..\.."
if errorlevel 1 exit /b 1

call "build\windows\build.bat"
if errorlevel 1 (
    echo [ERROR] Build failed; tests were not run.
    set "RUN_TEST_EXIT=1"
    goto :done
)

cerberus.exe test
set "RUN_TEST_EXIT=%errorlevel%"

:done
popd
endlocal & exit /b %RUN_TEST_EXIT%

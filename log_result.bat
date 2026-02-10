@echo off
set "TARGET=%~1"
set "SALT=%~2"
set "PASS=%~3"

REM Handle empty salt placeholder
if "%SALT%"=="-" set "SALT="

REM Format: HASH | SALT | PASSWORD
set "LINE=%TARGET% | %SALT% | %PASS%"

REM Write to TEMP (Guaranteed Writable)
echo %LINE% >> "%TEMP%\cracked_passwords.txt"

REM Attempt Copy to Desktop (Best Effort)
copy /Y "%TEMP%\cracked_passwords.txt" "C:\Users\Zeca\Desktop\cracked_passwords.txt" >nul 2>&1

REM Write to Local Debug (If possible)
echo %LINE% >> "local_cracked.txt"

exit /b 0

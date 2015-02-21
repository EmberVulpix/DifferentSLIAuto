@echo off
title DifferentSLI Sign and Install

setlocal EnableExtensions
cd /d "%~dp0"

if not exist "tools\" goto wtfrudoin

net session >nul 2>&1
if %errorlevel% neq 0 goto notadmin

call "%SystemRoot%\System32\certutil.exe" -store root DifferentSLIAuto
if %errorlevel% equ 0 goto certexists

call "tools\makecert.exe" -r -pe -ss "DifferentSLIAuto" -n "CN=DifferentSLIAuto" "%SystemRoot%\DifferentSLIAuto.cer"
call "tools\CertMgr.exe" /add "%SystemRoot%\DifferentSLIAuto.cer" /s /r localMachine root

:certexists

call "tools\ChecksumFix.exe" "nvlddmkm.sys"
call "tools\signtool.exe" sign /v /s DifferentSLIAuto /n DifferentSLIAuto /t http://timestamp.verisign.com/scripts/timstamp.dll "nvlddmkm.sys"
call "%SystemRoot%\System32\takeown.exe" /f "%SystemRoot%\System32\drivers\nvlddmkm.sys" /a
call "%SystemRoot%\System32\icacls.exe" "%SystemRoot%\System32\drivers\nvlddmkm.sys" /grant "%USERNAME%":f
call "%SystemRoot%\System32\bcdedit.exe" /set TESTSIGNING ON

if exist "%SystemRoot%\Sysnative\" goto x32mode

copy "nvlddmkm.sys" "%SystemRoot%\System32\drivers\nvlddmkm.sys" /y
goto filecopied

:x32mode
copy "nvlddmkm.sys" "%SystemRoot%\Sysnative\drivers\nvlddmkm.sys" /y

:filecopied
color 0a
echo Reboot now for changes to take effect
goto end

:wtfrudoin
color 0c
echo Please extract everything from the package including the contents of the tools folder.
goto end

:notadmin
color 0e
echo Please run this as administrator!

:end
pause > nul
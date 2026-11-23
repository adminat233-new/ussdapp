@echo off
setlocal
REM Builds and runs the conference-mixer end-to-end test (diagnostics\conf_mixer_test.cs).
REM It compiles the real app sources with the test as entry point, so the test
REM drives the production CallServer over real TCP - no stubs, no mocks.
set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
set GAC=C:\Windows\Microsoft.NET\assembly\GAC_MSIL
set GAC32=C:\Windows\Microsoft.NET\assembly\GAC_32

set PF=%GAC%\PresentationFramework\v4.0_4.0.0.0__31bf3856ad364e35\PresentationFramework.dll
set PC=%GAC32%\PresentationCore\v4.0_4.0.0.0__31bf3856ad364e35\PresentationCore.dll
set WB=%GAC%\WindowsBase\v4.0_4.0.0.0__31bf3856ad364e35\WindowsBase.dll
set SX=%GAC%\System.Xaml\v4.0_4.0.0.0__b77a5c561934e089\System.Xaml.dll
set SS=%GAC%\System.Speech\v4.0_4.0.0.0__31bf3856ad364e35\System.Speech.dll
set CS=%~dp0..\Csharp

"%CSC%" /nologo /target:exe /platform:anycpu /optimize+ ^
  /main:ConfMixerTest ^
  /out:"%~dp0ConfMixerTest.exe" ^
  /r:"%PF%" /r:"%PC%" /r:"%WB%" /r:"%SX%" ^
  /r:System.Numerics.dll /r:System.Drawing.dll ^
  /r:System.Security.dll ^
  /r:"%SS%" ^
  /r:System.Device.dll ^
  /r:System.Management.dll /r:System.Windows.Forms.dll ^
  /r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll /r:System.Xml.dll ^
  "%CS%\UssdApp.cs" "%CS%\VoipService.cs" "%CS%\Tnsrl.cs" "%CS%\CallServer.cs" ^
  "%CS%\Security.cs" "%CS%\TrackerBridge.cs" "%~dp0..\Csharp\RemoteControl.cs" "%CS%\Transport.cs" "%CS%\StickerSync.cs" "%CS%\Transcribe.cs" "%CS%\Radio.cs" "%CS%\CallRouter.cs" "%CS%\NumberLease.cs" "%CS%\Theme.cs" "%CS%\ConnectionHelper.cs" "%CS%\McpEngine.cs" "%CS%\DerpEngine.cs" "%CS%\PqCrypto.cs" ^
  "%~dp0conf_mixer_test.cs"
if errorlevel 1 (
    echo CONF TEST BUILD FAILED
    exit /b 1
)
echo.
echo Running conference mixer test...
echo.
"%~dp0ConfMixerTest.exe"
set RC=%ERRORLEVEL%
echo.
if "%RC%"=="0" (echo CONF TEST: PASS) else (echo CONF TEST: FAIL exit=%RC%)
exit /b %RC%


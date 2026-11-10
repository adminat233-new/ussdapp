@echo off
setlocal
rem The always-awake wake agent (roadmap C1). Same sources as the app, built as
rem /target:exe so it owns a console and can write its log, and run with
rem --agent so Main takes the headless path instead of building a window:
rem   UssdAgent.exe --agent --home=<profile dir> [--gui=<window exe>] [--relay=host:port]
rem It registers on the relay, decrypts what arrives, stores it in
rem <profile>\wake_inbox, starts the window with the same --home=, and exits.
set CSC=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe
if not exist "%CSC%" set CSC=C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe
set GAC=C:\Windows\Microsoft.NET\assembly\GAC_MSIL
set GAC32=C:\Windows\Microsoft.NET\assembly\GAC_32

set PF=%GAC%\PresentationFramework\v4.0_4.0.0.0__31bf3856ad364e35\PresentationFramework.dll
set PC=%GAC32%\PresentationCore\v4.0_4.0.0.0__31bf3856ad364e35\PresentationCore.dll
set WB=%GAC%\WindowsBase\v4.0_4.0.0.0__31bf3856ad364e35\WindowsBase.dll
set SX=%GAC%\System.Xaml\v4.0_4.0.0.0__b77a5c561934e089\System.Xaml.dll

echo Compiling C# wake agent with %CSC% ...
"%CSC%" /nologo /target:exe /platform:anycpu /optimize+ ^
  /win32icon:"%~dp0..\Python\ussd.ico" ^
  /out:"%~dp0UssdAgent.exe" ^
  /r:"%PF%" /r:"%PC%" /r:"%WB%" /r:"%SX%" ^
  /r:System.Numerics.dll /r:System.Drawing.dll ^
  /r:System.Security.dll ^
  /r:System.Device.dll ^
  /r:System.Windows.Forms.dll /r:System.IO.Compression.dll /r:System.IO.Compression.FileSystem.dll ^
  /resource:"%~dp0Themes\Light.xaml",ussd.Themes.Light.xaml ^
  /resource:"%~dp0Themes\Dark.xaml",ussd.Themes.Dark.xaml ^
  /resource:"%~dp0Themes\Controls.xaml",ussd.Themes.Controls.xaml ^
  "%~dp0UssdApp.cs" "%~dp0VoipService.cs" "%~dp0Tnsrl.cs" "%~dp0CallServer.cs" "%~dp0NumberLease.cs" "%~dp0Security.cs" "%~dp0TrackerBridge.cs" "%~dp0Transport.cs" "%~dp0StickerSync.cs" "%~dp0Transcribe.cs" "%~dp0Radio.cs" "%~dp0CallRouter.cs" "%~dp0Theme.cs" "%~dp0ConnectionHelper.cs"
if errorlevel 1 (
    echo BUILD FAILED
    exit /b 1
)
echo BUILD OK: %~dp0UssdAgent.exe

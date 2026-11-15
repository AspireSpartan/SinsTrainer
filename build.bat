@echo off
cd /d "%~dp0"
"%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe" /nologo /target:winexe /platform:x64 /optimize /out:SinsTrainer.exe SinsTrainer.cs
if errorlevel 1 (echo Build failed & pause & exit /b 1)
echo Built SinsTrainer.exe

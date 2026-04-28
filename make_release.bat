@echo off
setlocal
set RELEASE_NAME=WiGuard_Nexus_v5_5_Packet_Tracer_Intelligence
if exist dist rmdir /s /q dist
mkdir dist
python -m compileall -q wiguard tests app.py
if errorlevel 1 exit /b 1
python -m pytest -q
if errorlevel 1 exit /b 1
powershell -NoProfile -Command "Compress-Archive -Path * -DestinationPath dist/%RELEASE_NAME%.zip -Force -CompressionLevel Optimal"
echo Release created: dist\%RELEASE_NAME%.zip
endlocal

@echo off

:x
powershell -ep bypass -file .\web-server.ps1
goto x

pause
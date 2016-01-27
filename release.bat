@echo off
xcopy /S /Y ConfigCollection Release
del /F /Q Release\*.exp
del /F /Q Release\*.lib
del /F /Q Release\plugins\*.exp
del /F /Q Release\plugins\*.lib
del /F /Q Release\plugins\*.map
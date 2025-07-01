@echo off
title Compile
mkdir out
mkdir build
cd src
windres app.rc -o ..\build\app.o
g++ demo.cpp ..\build\app.o -o ..\out\trojan.exe -ladvapi32 -static -mwindows
cd ..
rd /s /q build
pause
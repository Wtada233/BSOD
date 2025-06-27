@echo off
title Compile
mkdir out
g++ src\demo.cpp -o out\trojan.exe -ladvapi32 -static -mwindows
pause
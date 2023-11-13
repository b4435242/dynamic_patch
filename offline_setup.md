# Offline setup

## Mingw-w64
<!--Download from https://winlibs.com/  
set PATH dependencies\winlibs-x86_64-posix-seh-gcc-13.1.0-llvm-16.0.5-mingw-w64ucrt-11.0.0-r5\mingw64\bin  
set PATH dependencies\winlibs-x86_64-posix-seh-gcc-13.1.0-llvm-16.0.5-mingw-w64ucrt-11.0.0-r5\mingw64\lib  
-->
unzip mingw64.zip
mingw64 is from mysy2 package manager `pacman -S mingw-w64-x86_64-gcc`
set PATH mingw64\bin

## MSYS2
execute dependencies/msys2-x86_64-20230526

## Python
execute dependencies/python-3.11.4-amd64

## Module
angr, IPython  
With network: cd dependencies && Start-Process download.bat  
Install offline: cd dependencies && Start-Process install.bat




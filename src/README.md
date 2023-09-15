### Dependencies
#### Mingw-w64
set path dependencies\winlibs-x86_64-posix-seh-gcc-13.1.0-llvm-16.0.5-mingw-w64ucrt-11.0.0-r5\mingw64\bin
#### Python
execute python-3.11.4-amd64
#### angr
mkdir angr && cd angr && pip download angr  
pip install --no-index --find-links dependencies/angr angr  
#### IPython
mkdir IPython && cd IPython && pip download IPython  
pip install --no-index --find-links dependencies/IPython IPython  


### Run
test/toy/a.exe  
cd src && .\debugger.exe a.exe ../test/toy/a.exe 0x140001472 0x1400014cb 0x140001450  

type dummyinput to trigger analyzation  
type bill to test normal functionality  
type abcdefghijklmnopqrstuvwxyz to test protection mechanism for control flow hijack or buffer overflow  

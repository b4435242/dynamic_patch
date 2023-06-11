### Dependencies
#### Mingw-w64
Download from https://winlibs.com/
set path dependencies\winlibs-x86_64-posix-seh-gcc-13.1.0-llvm-16.0.5-mingw-w64ucrt-11.0.0-r5\mingw64\bin
#### Python
execute python-3.11.4-amd64
#### angr
mkdir setuptools && pip download setuptools
pip install --no-index --find-links setuptools setuptools

mkdir cppheaderparser && cd cppheaderparser && pip download CppHeaderParser
tar -zxvf cppheaderparser\CppHeaderParser-2.7.4.tar.gz --directory cppheaderparser
cd cppheaderparser\CppHeaderParser-2.7.4 && python setup.py install

mkdir mulpyplexer && cd mulpyplexer && pip download mulpyplexer
tar -zxvf mulpyplexer\mulpyplexer-0.09.tar.gz --directory mulpyplexer
cd mulpyplexer\mulpyplexer-0.09 && python setup.py install

mkdir future && cd future && pip download future
tar -zxvf future\future-0.18.3.tar.gz --directory future
cd future\future-0.18.3 && python setup.py install

mkdir angr && cd angr && pip download angr  
pip install --no-index --find-links angr angr  
#### IPython
mkdir IPython && cd IPython && pip download IPython  
pip install --no-index --find-links IPython IPython  


### Run
test/toy/a.exe  
cd src && .\debugger.exe a.exe ../test/toy/a.exe 0x140001472 0x1400014cb 0x140001450  

type dummyinput to trigger analyzation  
type bill to test normal functionality  
type abcdefghijklmnopqrstuvwxyz to test protection mechanism for control flow hijack or buffer overflow  

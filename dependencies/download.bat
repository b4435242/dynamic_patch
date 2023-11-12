:: Create a directory named "angr"
mkdir angr
:: Run the pip download command for angr
pip download angr==9.2.76  --dest angr

:: Create a directory named "setuptools"
mkdir setuptools
:: Run the pip download command for setuptools
pip download setuptools --dest setuptools

:: Create a directory named "cppheaderparser"
mkdir cppheaderparser
:: Run the pip download command for CppHeaderParser
pip download CppHeaderParser==2.7.4 --dest cppheaderparser
:: unzip
tar -zxvf cppheaderparser\CppHeaderParser-2.7.4.tar.gz --directory cppheaderparser

:: Create a directory named "mulpyplexer"
mkdir mulpyplexer
:: Run the pip download command for mulpyplexer
pip download mulpyplexer==0.09 --dest mulpyplexer
:: unzip
tar -zxvf mulpyplexer\mulpyplexer-0.09.tar.gz --directory mulpyplexer


:: Create a directory named "future"
mkdir future
:: Run the pip download command for future
pip download future==0.18.3 --dest future
:: unzip
tar -zxvf future\future-0.18.3.tar.gz --directory future


mkdir IPython
pip download IPython --dest IPython

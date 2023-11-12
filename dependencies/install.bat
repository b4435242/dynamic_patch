@echo off


:: angr
(
pip install --no-index --find-links setuptools setuptools

cd cppheaderparser\CppHeaderParser-2.7.4 
python setup.py install
cd ..

cd mulpyplexer\mulpyplexer-0.09
python setup.py install
cd ..

cd future\future-0.18.3
python setup.py install
cd ..
)

pip install --no-index --find-links angr angr

:: IPython
pip install --no-index --find-links IPython IPython

pause

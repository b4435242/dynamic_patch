python ../..//src/main.py --bin toy.exe --cmd toy_cmd --port 9953 --pid $(Get-Process -Name toy | Select-Object -ExpandProperty Id)

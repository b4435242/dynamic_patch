import psutil

def get_pid(proc_name):
	for proc in psutil.process_iter(['pid', 'name']):
		if proc.info['name'] == proc_name:
			print(f"PID of {proc_name} is {proc.info['pid']}")
			pid = int(proc.info['pid'])
			with open('pid', 'w') as f:
				f.write(str(pid))

if __name__ == "__main__":
	proc_name = 'a.exe'
	get_pid(proc_name)
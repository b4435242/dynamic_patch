import gdb
import os, sys
import subprocess

process_name = "a.exe"
bin = "../test/toy/a.exe"
regs = "regs"
stack = "stack"
start_addr=0x401550
end_addr=0x401597

def run_debugger():
	gdb.execute("set env PYTHONHOME={}".format(sys.exec_prefix))
	gdb.execute("set env PYTHONPATH=C:\\Python311\\Lib")
	gdb.execute("set env PYTHONIOENCODING=cp950")

	subprocess.Popen(["python", "util.py"]).wait()
	with open('pid', 'r') as f:
		pid = int(f.read())
		print(pid)


	# Attach to a running process
	gdb.execute("attach {}".format(pid))

	# Set a breakpoint at a specific address
	address = 0x401550
	gdb.execute("break *{}".format(address))

	# Dump memory and registers
	regs_path = "regs"
	os.remove(regs_path)
	gdb.execute("set logging on {}".format(regs_path))
	gdb.execute("info registers")
	gdb.execute("set logging off")
	gdb.execute("dump memory stack $sp $sp+100")
	gdb.execute("x/10x {}".format(address))


	symbolic_cmd = ["python", "overflow_detect.py", "--bin", bin, \
		"--start_addr", str(start_addr), "--end_addr", str(end_addr), \
		"--regs", regs, "--stack", stack]
	proc = subprocess.Popen(symbolic_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
	proc.wait()

	output, err = proc.communicate()

	print(output)
	print(err)



if __name__ == "__main__":
	run_debugger()
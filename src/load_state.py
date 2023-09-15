import angr
import re, os
import struct
import pickle
import IPython

def parse_register_file(reg_file):
	registers = {}
	
	with open(reg_file, 'r') as f:
		for line in f:
			line = line.strip()
			#print(line)
			if line.startswith("RIP:"):
				rip = int(line.split(":")[1], 16)
				registers['rip'] = rip
			elif line.startswith("RSP:"):
				rsp = int(line.split(":")[1], 16)
				registers['rsp'] = rsp
			elif line.startswith("RBP:"):
				rbp = int(line.split(":")[1], 16)
				registers['rbp'] = rbp
			elif line.startswith("RAX:"):
				rax = int(line.split(":")[1], 16)
				registers['rax'] = rax
			elif line.startswith("RBX:"):
				rbx = int(line.split(":")[1], 16)
				registers['rbx'] = rbx
			elif line.startswith("RCX:"):
				rcx = int(line.split(":")[1], 16)
				registers['rcx'] = rcx
			elif line.startswith("RDX:"):
				rdx = int(line.split(":")[1], 16)
				registers['rdx'] = rdx
			elif line.startswith("RSI:"):
				rsi = int(line.split(":")[1], 16)
				registers['rsi'] = rsi
			elif line.startswith("RDI:"):
				rdi = int(line.split(":")[1], 16)
				registers['rdi'] = rdi
			elif line.startswith("R8:"):
				r8 = int(line.split(":")[1], 16)
				registers['r8'] = r8
			elif line.startswith("R9:"):
				r9 = int(line.split(":")[1], 16)
				registers['r9'] = r9
			elif line.startswith("R10:"):
				r10 = int(line.split(":")[1], 16)
				registers['r10'] = r10
			elif line.startswith("R11:"):
				r11 = int(line.split(":")[1], 16)
				registers['r11'] = r11
			elif line.startswith("R12:"):
				r12 = int(line.split(":")[1], 16)
				registers['r12'] = r12
			elif line.startswith("R13:"):
				r13 = int(line.split(":")[1], 16)
				registers['r13'] = r13
			elif line.startswith("R14:"):
				r14 = int(line.split(":")[1], 16)
				registers['r14'] = r14
			elif line.startswith("R15:"):
				r15 = int(line.split(":")[1], 16)
				registers['r15'] = r15
			elif line.startswith("EFLAGS:"):
				eflags = int(line.split(":")[1], 16)
				registers['eflags'] = eflags

	return registers



def set_regs(state, regs_path):
	regs = parse_register_file(regs_path)

	state.regs.rax = struct.pack('>Q', regs['rax'])
	state.regs.rbx = struct.pack('>Q', regs['rbx'])
	state.regs.rcx = struct.pack('>Q', regs['rcx'])
	state.regs.rdx = struct.pack('>Q', regs['rdx'])
	state.regs.rsi = struct.pack('>Q', regs['rsi'])
	state.regs.rdi = struct.pack('>Q', regs['rdi'])
	state.regs.rbp = struct.pack('>Q', regs['rbp'])
	state.regs.rsp = struct.pack('>Q', regs['rsp'])
	state.regs.r8 = struct.pack('>Q', regs['r8'])
	state.regs.r9 = struct.pack('>Q', regs['r9'])
	state.regs.r10 = struct.pack('>Q', regs['r10'])
	state.regs.r11 = struct.pack('>Q', regs['r11'])
	state.regs.r12 = struct.pack('>Q', regs['r12'])
	state.regs.r13 = struct.pack('>Q', regs['r13'])
	state.regs.r14 = struct.pack('>Q', regs['r14'])
	state.regs.r15 = struct.pack('>Q', regs['r15'])
	#state.regs.rip = struct.pack('>Q', regs['rip'])
	state.regs.eflags = struct.pack('>Q', regs['eflags'])
	#state.regs.cs = struct.pack('>Q', int(regs[18], 16))
	#state.regs.ss = struct.pack('>Q', int(regs[19], 16))
	#state.regs.ds = struct.pack('>Q', int(regs[20], 16))
	#state.regs.es = struct.pack('>Q', int(regs[21], 16))
	#state.regs.fs = struct.pack('>Q', int(regs[22], 16))
	#state.regs.gs = struct.pack('>Q', int(regs[23], 16))

def parse_stack_file(stack_path):
	# Open stack dump file
	with open(stack_path, "r") as f:
		stack_dump = f.read()

	# Define regex pattern to match address and value
	pattern = r"\s*0x([0-9a-fA-F]+)\s+0x([0-9a-fA-F]+)"

	# Find all matches in the stack dump file
	matches = re.findall(pattern, stack_dump)

	# Create a list to store the stack values
	stack_values = {}

	# Iterate over the matches and convert the value to an integer
	for match in matches:
		address = int(match[0], 16)
		value = int(match[1], 16)
		stack_values[address] = value

	# Print the stack values
	#for address, value in stack_values.items():
	#	print("Address: 0x{:x} Value: 0x{:x}".format(address, value))
	return stack_values

def set_stack(state, stack_path):
	stack_values = parse_stack_file(stack_path)

	for address, value in stack_values.items():
		#address = struct.pack('>Q', value)
		state.mem[address].uint64_t = struct.pack('<Q', value)
		#print(state.mem[address].uint64_t)

def dump_constraints(constraints, filename):
	with open(filename, 'wb') as f:
		pickle.dump(constraints, f)

def load_constraints(filename):
	with open(filename, 'rb') as f:
		constraints = pickle.load(f)
	return constraints

def dump_symbolic_vars(symbolic_vars, filename):
	with open(filename, 'wb') as f:
		pickle.dump(symbolic_vars, f)

def load_symbolic_vars(filename):
	with open(filename, 'rb') as f:
		symbolic_vars = pickle.load(f)
	return symbolic_vars

def load_stdin_buf(filename):
	with open(filename, 'r') as file:
		lines = file.readlines()
		content_bytes = b''.join([int(value, 16).to_bytes(8, 'little') for line in lines for value in line.split()[1:]])
	''' Replace first \x00 to \n for angr constraints '''
	processed_bytes = content_bytes
	for i, b in enumerate(content_bytes):
		if b == 0:
			processed_bytes = content_bytes[:i]
			processed_bytes += b'\n'
			break
	print(processed_bytes)
	return processed_bytes


def load_analysis(filename):
	with open(filename, 'r') as file:
		lines = file.readlines()
	bof_func = lines[2].rstrip()
	reg_id = lines[3].rstrip()
	return bof_func, reg_id


def get_reg(filename, reg_id, ctype):
	regs = parse_register_file(filename)
	bytes_data = struct.pack('<Q', regs[reg_id])
	if ctype=="double":
		val = struct.unpack('d', bytes_data)[0]
	elif ctype=="uint64_t":
		val = struct.unpack('Q', bytes_data)[0]
	return val
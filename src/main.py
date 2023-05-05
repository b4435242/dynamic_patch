import os
import angr
import archinfo
import claripy
import signal
import struct
import time
import re
from tqdm import tqdm
import argparse
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation


import logging

#logging.getLogger('angr').setLevel('DEBUG')

class angr_gets(angr.SimProcedure):
	#pylint:disable=arguments-differ
	def run(self, dst):
		fd = 0
		simfd = self.state.posix.get_fd(fd)
		if simfd is None:
			return 0
			
		max_size = self.state.libc.max_gets_size

		# case 0: the data is concrete. we should read it a byte at a time since we can't seek for
		# the newline and we don't have any notion of buffering in-memory
		if simfd.read_storage.concrete:
			count = 0
			while count < max_size - 1:
				data, real_size = simfd.read_data(1)
				if self.state.solver.is_true(real_size == 0):
					break
				self.state.memory.store(dst + count, data)
				count += 1
				if self.state.solver.is_true(data == b'\n'):
					break
			self.state.memory.store(dst + count, b'\0')
			return dst

		# case 2: the data is symbolic, the newline could be anywhere. Read the maximum number of bytes
		# (SHORT_READS should take care of the variable length) and add a constraint to assert the
		# newline nonsense.
		# caveat: there could also be no newline and the file could EOF.
		else:
			data, real_size = simfd.read_data(max_size)

			for i, byte in enumerate(data.chop(8)):
				self.state.add_constraints(self.state.solver.If(
					i+1 != real_size, 
					byte != b'\n',
					self.state.solver.Or(			 # otherwise one of the following must be true:
						i+2 == max_size,				 # - we ran out of space, or
						simfd.eof(),				 # - the file is at EOF, or
						byte == b'\n'				 # - it is a newline
					)))
			self.state.add_constraints(byte == b'\n')# gets最后加入\n

			self.state.memory.store(dst, data, size=real_size)
			end_address = dst + real_size - 1
			end_address = end_address.annotate(MultiwriteAnnotation())
			self.state.memory.store(end_address, b'\0')

			return dst

def set_regs(state, regs_path):
	with open(regs_path, "r") as f:
		_regs = f.read()
	# format of info registers
	_regs = _regs.split('\n')
	regs = []
	for r in _regs:
		vals = list(filter(None, re.split('\s', r)))
		if len(vals)==0:
			continue
		regs.append(vals[1])


	state.regs.rax = struct.pack('>Q', int(regs[0], 16))
	state.regs.rbx = struct.pack('>Q', int(regs[1], 16))
	state.regs.rcx = struct.pack('>Q', int(regs[2], 16))
	state.regs.rdx = struct.pack('>Q', int(regs[3], 16))
	state.regs.rsi = struct.pack('>Q', int(regs[4], 16))
	state.regs.rdi = struct.pack('>Q', int(regs[5], 16))
	state.regs.rbp = struct.pack('>Q', int(regs[6], 16))
	state.regs.rsp = struct.pack('>Q', int(regs[7], 16))
	state.regs.r8 = struct.pack('>Q', int(regs[8], 16))
	state.regs.r9 = struct.pack('>Q', int(regs[9], 16))
	state.regs.r10 = struct.pack('>Q', int(regs[10], 16))
	state.regs.r11 = struct.pack('>Q', int(regs[11], 16))
	state.regs.r12 = struct.pack('>Q', int(regs[12], 16))
	state.regs.r13 = struct.pack('>Q', int(regs[13], 16))
	state.regs.r14 = struct.pack('>Q', int(regs[14], 16))
	state.regs.r15 = struct.pack('>Q', int(regs[15], 16))
	state.regs.rip = struct.pack('>Q', int(regs[16], 16))
	state.regs.eflags = struct.pack('>Q', int(regs[17], 16))
	#state.regs.cs = struct.pack('>Q', int(regs[18], 16))
	#state.regs.ss = struct.pack('>Q', int(regs[19], 16))
	#state.regs.ds = struct.pack('>Q', int(regs[20], 16))
	#state.regs.es = struct.pack('>Q', int(regs[21], 16))
	state.regs.fs = struct.pack('>Q', int(regs[22], 16))
	state.regs.gs = struct.pack('>Q', int(regs[23], 16))

def set_stack(state, rbp, stack_path):
	with open(stack_path, "rb") as f:
		stack = f.read()
	num = len(stack)
	#print(stack)
	for i in range(num, 0, -1):
		#state.mem[state.regs.rbp-(4*(num-i)):].dword = struct.pack('<I', int(stack[4*i : 4*(i+1)].encode('hex'), 16))
		#print(struct.pack('>B', stack[num-i]))
		state.mem[rbp-i].word = struct.pack('>B', stack[num-i])

def parse_arg():
	parser = argparse.ArgumentParser()
	parser.add_argument("--regs", dest="regs")
	parser.add_argument("--stack", dest="stack")
	parser.add_argument("--shellcode", dest="shellcode")
	parser.add_argument("--bin", dest="bin")
	parser.add_argument("--start_address", dest="start_address")
	parser.add_argument("--end_address", dest="end_address")
	args = parser.parse_args()
	return args

def overflow_detect_filter(simgr):
	'''detect buffer overflow'''
	for active_state in simgr.active:
		 print("Current instruction address: 0x%x" % active_state.addr)
	for state in simgr.unconstrained:
		if state.regs.pc.symbolic:
			print("Found vulnerable state.")
			bof_aeg.vuln_state = state.copy()

			tmp = list(state.regs.pc.variables)
			variables = []
			# keep stdin only
			for i in tmp:
				if 'stdin' in i:
					variables.append(i)

			if len(variables) > 1:
				pwn.log.error("Stack overflow caused by more than one stdin?")

			vuln_block = bof_aeg.project.factory.block(list(state.history.bbl_addrs)[-1])
			bof_aeg.vuln_addr = vuln_block.addr + vuln_block.size - 1
			pwn.log.info("Vuln_addr: 0x%x"%bof_aeg.vuln_addr)
			bof_aeg.vuln_input = b''.join(state.posix.stdin.concretize())

			for name,func in elf.functions.items():
				if func.address <= vuln_block.addr and vuln_block.addr < func.address+func.size:
					pwn.log.info("Vuln_func(%s): 0x%x"%(name,func.address))
					bof_aeg.vuln_func = func

			if state.regs.pc.symbolic:
				# get controllable symbolic address after rbp+8(pc)
				rbp = state.solver.eval(state.regs.rsp - 0x10)
				tmp = list(state.memory.addrs_for_name(variables[0]))
				tmp.sort()
				for i in range(len(tmp)):
					if tmp[i] == rbp+8:
						bof_aeg.vuln_control_addrs = tmp[i:]
						break

			simgr.stashes["found"].append(state)
			simgr.stashes["unconstrained"].remove(state)
			break
		

	return simgr

def find_stack_bof(project, end_address):
	add_options = {
		angr.options.ZERO_FILL_UNCONSTRAINED_MEMORY,
		angr.options.ZERO_FILL_UNCONSTRAINED_REGISTERS,
		angr.options.REVERSE_MEMORY_NAME_MAP,
		#angr.options.STRICT_PAGE_ACCESS, # Raise a SimSegfaultError on illegal memory accesses
		#angr.options.TRACK_ACTION_HISTORY,
	}
	print("base addr {}".format(project.loader.main_object))
	print(project.loader.all_objects)
    

	state = project.factory.entry_state(addr=0x4015b4, add_options=add_options)
	state.libc.buf_symbolic_bytes = 0x1000
	state.libc.max_str_len = 0x1000
	state.libc.max_gets_size = 0x200 # define gets() size; 溢出太长会影响system的envp
	simgr = project.factory.simgr(state, save_unconstrained=True)
	simgr.explore(find=end_address, step_func=overflow_detect_filter)
	if simgr.found == []:
		print("Cannot find stack bof.")

def main():
	args = parse_arg()

	with open(args.shellcode, "rb") as f:
		shellcode = f.read()
	#print(shellcode)

	arch = archinfo.arch_from_id('x86_64')
	start_address, end_address = int(args.start_address, 0), int(args.end_address, 0)
	#p = angr.project.load_shellcode(shellcode, arch, load_address=start_address)
	p = angr.Project(args.bin, load_options={'auto_load_libs': False})
	p.hook_symbol('gets',angr_gets())

	s1 = p.factory.entry_state()
	set_regs(s1, args.regs)
	#print(s1.regs.rbp)
	set_stack(s1, s1.regs.rbp, args.stack)
	#print(s1.mem[s1.regs.rbp-4:].uint8_t.resolved)

	find_stack_bof(p, end_address)
	#sm = p.factory.simulation_manager(s1, save_unconstrained=True)
	#sm.explore(find = end_address)

	#print("unconstrained state %d"%len(sm.unconstrained))
	#print("found states %d"%len(sm.found))
if __name__ == "__main__":
	main()

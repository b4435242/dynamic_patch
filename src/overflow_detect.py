import angr, argparse, sys, IPython
import claripy
import load_state
import struct
import procedure
import  math
from decimal import *
import loader

from angr.misc.ux import once
import logging

rip_pattern = 0xCCCCCCCCCCCCCCCC


_l = logging.getLogger(name=__name__)
sys.set_int_max_str_digits(0)



class Bof_Aeg(object):
	def __init__(self, bin_path, bof_func, hook_len, base_addr, start_addr):
		# virtual base address
		self.project = angr.Project(bin_path, main_opts={'base_addr': base_addr}, load_options={'auto_load_libs': False}) 

		self.num_input_chars = 256
		self.overflow = True
		self.vuln_addr = 0
		self.reg_id = ""
		self.start_addr = start_addr
		self.bof_func = bof_func
		self.hook_len = hook_len



	def toy_hook(self):
		self.project.hook_symbol('gets', procedure.gets())

	def cve_2013_2028_config(self):
		self.recv_addr = 0x1004554b8
		self.project.hook(self.recv_addr, hook=procedure.ngx_recv, length=3)	# replace call r->connection->recv
		self.size_addr = 0x7ffffc078 # manual for case of nginx
		# segmentation fault if vuln_addr set at ret
		# call before write_analysis to set vuln_addr manually

	def cve_2021_3177_config(self):
		#cc = self.project.factory.cc_from_arg_kinds((True, True), ret_fp=True)
		self.project.hook(self.start_addr, procedure.sprintf())

	def hook_setup(self, state):
		state.globals["hook_len"] = self.hook_len
		if self.bof_func=="get":
			self.project.hook(self.start_addr, procedure.gets()) # simprocedure
		elif self.bof_func=="recv":
			self.project.hook(self.start_addr, procedure.recv, length=self.hook_len) # user hook
		elif self.bof_func=="sprintf":
			self.project.hook(self.start_addr, procedure.sprintf()) # simprocedure

	def is_unconstrained(self, m, constraints, start_addr):
		

		if self.bof_func=="gets":
			''' Use concretized input which satisfies constraints to check if it can exploit vulnerability '''
			
			# Generate concretized input with constraints #
			state = self.project.factory.entry_state()
			constraints = constraints[:m+1]
			for c in constraints:
				state.solver.add(c)

			buffer = self.state.posix.stdin.content[0][0]
			concretized_buffer = state.solver.eval(buffer, cast_to=bytes)
			#trim 
			print(concretized_buffer)
			trim_index = 1
			while concretized_buffer[-trim_index]==0:
				trim_index += 1
			concretized_buffer = concretized_buffer[:-trim_index]

			print(concretized_buffer)
			#IPython.embed()

			# Check if it can find random address e.g. rip_pattern=0xcccccccc here #
			simfile = angr.SimFile('/dev/stdin', content=concretized_buffer)
			state = self.project.factory.call_state(addr=start_addr, stdin=simfile, add_options={ # currently must start from the start of func
				angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
				angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
				angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
				})
			load_state.set_regs(state, regs)
			state.globals["hook_len"] = self.hook_len
			simgr = self.project.factory.simgr(state)
			
			simgr.explore(find=rip_pattern)
			return len(simgr.found)>0
		elif self.bof_func=="recv":
			''' symbolic_input here means recv buf '''
			buffer = self.state.posix.stdin.content[0][0]

			# Generate concretized input with constraints #
			state = self.project.factory.entry_state()
			for c in constraints:
				state.solver.add(c)


			# concretize input with extra threshold constraint
			#symbolic_size = self.state.globals["r8"] # load var symbolic_size 
			#threshold_constraint = claripy.ULE(symbolic_size, m)
			#state.solver.add(symbolic_size==m)
			#print("[is_unconstrained] constraints={}".format(state.solver.constraints))
			
			concretized_buffer = state.solver.eval(buffer, cast_to=bytes)
			#print(concretized_input)

			# Check if it can find random address e.g. rip_pattern=0xcccccccc here #
			simfile = angr.SimFile('/dev/stdin', content=concretized_buffer)
			state = self.project.factory.call_state(addr=start_addr, stdin=simfile, add_options={ # currently must start from the start of func
				angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
				angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
				angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
				})
			load_state.set_regs(state, regs)
			state.globals["hook_len"] = self.hook_len
			state.globals["r8"] = m # set concrete size for hook ngx_recv 

			simgr = self.project.factory.simgr(state)
			
			simgr.explore(find=rip_pattern)
			return len(simgr.found)>0
		elif self.bof_func=="sprintf":
			
			state = self.project.factory.call_state(addr=start_addr, add_options={ # currently must start from the start of func
				angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
				angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
				angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
				})
			load_state.set_regs(state, regs)
			load_state.set_stack(state, stack)
			state.globals["hook_len"] = self.hook_len
			''' set up r8 or r9 with concrete number'''
			# self.reg_id is r8 or r9, which is determined by self.find_minimum_constraints.extra_constraints()
			state.globals[self.reg_id] = m
			simgr = self.project.factory.simgr(state, save_unconstrained=True)
			simgr.stashes['mem_corrupt']  = []
			simgr.explore(step_func=self.check_mem_corruption)
			return len(simgr.mem_corrupt)>0


	def find_minimum_constraints(self, constraints, start_addr):
		if self.bof_func=="gets": 
			# Function to extract byte index from constraint name
			def get_byte_index(constraint):
				# Parse the constraint name to extract the byte index
				name = str(constraint)
				start = name.index('[') + 1
				end = name.index(':')
				return -int(name[start:end])

			# Sort the constraints based on the byte index
			constraints = sorted(constraints, key=get_byte_index)

			# binary search
			n = len(constraints)
			l = 0
			r = n-1
			while l<=r:
				m = (l+r)/2
				m = int(m)
				res = self.is_unconstrained(m, constraints, start_addr)
				if res:
					r = m-1
				else:
					l = m+1
			
			# drop 8 last bytes constraints cuz it is a specific random address
			if r>=8:
				r -= 8
			return constraints[:l+1] # originallly r+1?
		elif self.bof_func=="recv":
			# get r8 (size) constraints with <= op
			def extract_constraints():
				for c in constraints:
					if c.op=="ULE" and "r8" in str(c.args[0]):
						var = self.state.globals["r8"]
						val = self.state.solver.eval(c.args[1])
						return var, val
			
			symbolic_var, concrete_val = extract_constraints()

			# binary search
			n = concrete_val
			l = 0
			r = n-1
			while l<=r:
				m = (l+r)/2
				m = int(m)
				res = self.is_unconstrained(m, constraints, start_addr)
				if res:
					r = m-1
				else:
					l = m+1
			# generate new constraint for size, trigger err if size>threshold
			print("[find_minimum_constraints] size={}".format(l+1))
			threshold_constraint = claripy.UGE(symbolic_var, l+1) # l is index, while l+1 is size
			return [threshold_constraint]

		elif self.bof_func=="sprintf":
			# get r8 or r9 constraints with <= op
			# determine key var is r8 or r9
			def extract_constraints():
				def op_filter(c):
					return c.op=="ULE" or c.op=="fpLEQ"
				for c in constraints:
					if "r8" in str(c.args[0]) and op_filter(c):
						self.reg_id = "r8"
						var = self.state.globals["r8"]
						val = self.state.solver.eval(c.args[1])
						return var, val, c.op
					elif "r9" in str(c.args[0]) and op_filter(c):
						self.reg_id = "r9"
						var = self.state.globals["r9"]
						val = self.state.solver.eval(c.args[1])
						return var, val, c.op
			symbolic_var, concrete_val, op = extract_constraints()

			if "fp" in op: # real number case
				# bin_pathary search on digits 
				n = concrete_val
				l = 0
				r = n-1
				# transform to digits 
				l, r = len(str(Decimal(l))), len(str(Decimal(r)))
				while l<=r:
					m = (l+r)/2
					m = int(m)
					real_number = math.pow(10, m-1) # pass real number with m digits
					res = self.is_unconstrained(real_number, constraints, start_addr)
					print('[is_unconstrained]m={}, l={}, r={}, res={}'.format(m, l, r, res))
					if res:
						r = m-1
					else:
						l = m+1
				# generate new constraint for num, trigger err if num>threshold
				print("[find_minimum_constraints] digits of num={}".format(l))
				threshold = claripy.FPV(math.pow(10, l-1), claripy.fp.FSORT_DOUBLE) # transform back to num, l is digit of num
				threshold_constraint = claripy.fpGEQ(symbolic_var, threshold) 
				return [threshold_constraint]

	def check_mem_corruption(self, simgr):
		print("active {}".format(simgr.active))
		#for path in simgr.active:
		#	if path.addr==0x18001bc74:


		if len(simgr.unconstrained):
			for path in simgr.unconstrained:
				if path.satisfiable(extra_constraints=[path.regs.rip == rip_pattern]):
				#if path.regs.rip.symbolic:
					path.add_constraints(path.regs.rip == rip_pattern)
					ret_addr = self.get_ret_addr(path)
					if ret_addr <= self.end_addr and ret_addr>=self.start_addr:
						print("unconstrained {}".format(simgr.unconstrained))
						print("ret_addr: 0x%x"%ret_addr)
						if path.satisfiable():
							simgr.stashes['mem_corrupt'].append(path)
					simgr.stashes['unconstrained'].remove(path)
					simgr.drop(stash='active')
				
		return simgr

	def get_ret_addr(self, state):
		# use ret as vuln addr
		vuln_block = bof_aeg.project.factory.block(list(state.history.bbl_addrs)[-1])
		return vuln_block.addr + vuln_block.size - 1

	

	def find_buf_overflow(self, start_addr, end_addr, regs, stack):
		#symsize = claripy.BVS('stdin_size', 64)
		self.start_addr = start_addr
		self.end_addr = end_addr

		symbolic_input = claripy.BVS('input', self.num_input_chars*8)
		#self.symbolic_input = symbolic_input
		simfile = angr.SimFile('/dev/stdin', content=symbolic_input)
		state = self.project.factory.call_state(addr=start_addr, add_options={
			angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
			angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
			angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS,
			})

		''' Setup concolic execution env '''
		load_state.set_regs(state, regs)
		load_state.set_stack(state, stack)
		print("rsp={}, rbp={}".format(state.regs.rsp, state.regs.rbp))
		
		self.hook_setup(state)


		state.libc.buf_symbolic_bytes = 0x100
		state.libc.max_str_len = 0x100
		state.libc.max_gets_size = 0x100 
		state.libc.max_packet_size = 0x1000+0x100 # nginx case: buffer size + overflow 
		
		# For sprintf func and recv
		state.globals["r8"] = claripy.BVS('r8', 64)
		state.globals["r9"] = claripy.BVS('r9', 64)

		# For hooking
		state.globals["hook_len"] = self.hook_len

		def log_func(s):
			print("[log] rcx={}, rdx={}, r8={}, r9={}, rsp={}, rbp={}, rip={}".format(hex(s.solver.eval(s.regs.rcx)), hex(s.solver.eval(s.regs.rdx)),  hex(s.solver.eval(s.regs.r8)),  hex(s.solver.eval(s.regs.r9)), hex(s.solver.eval(s.regs.rsp)), hex(s.solver.eval(s.regs.rbp)), hex(s.solver.eval(s.regs.rip))))
			#self.stdin_buf_addr = s.solver.eval(s.regs.rcx) # for case of toy app 
			#self.recv_buf_addr = s.solver.eval(s.regs.rdx) # for case of nginx 
			self.size_addr = 0x7ffffc078 # manual for case of nginx
			#IPython.embed()
		

		state.inspect.b('simprocedure', simprocedure_name='gets', when=angr.BP_BEFORE, action=log_func)
		state.inspect.b('simprocedure', simprocedure_name='ngx_recv', when=angr.BP_BEFORE, action=log_func)
		state.inspect.b('simprocedure', simprocedure_name='sprintf', when=angr.BP_BEFORE, action=log_func)


		#for char in symbolic_input.chop(bits=8):
		#	state.add_constraints(char >= 'A', char <= 'z')

		

		simgr = self.project.factory.simgr(state, save_unconstrained=True)
		simgr.use_technique(angr.exploration_techniques.DFS())
		simgr.stashes['mem_corrupt']  = []
		
		simgr.explore(step_func=self.check_mem_corruption)
		print("corrupt {} len={}".format(simgr.stashes['mem_corrupt'], len(simgr.stashes['mem_corrupt'])))
	

		if len(simgr.stashes['mem_corrupt'])==0:
			self.overflow = False
			return 


		unconstrained_state = simgr.stashes['mem_corrupt'][-1]
		unconstrained_state.solver.simplify()
		self.state = unconstrained_state
		constraints = unconstrained_state.solver.constraints
		print(constraints)
		
		minimum_constraints = self.find_minimum_constraints(constraints, start_addr)
		self.minimum_constraints = minimum_constraints


		print("constraints = {}".format(minimum_constraints))
		#IPython.embed()

		'''
		# Solve for command-line argument that will let us set RBP and RIP
		solution = unconstrained_state.solver.eval(self.state.posix.stdin.content[0][0], cast_to=bytes)
		#print("Command-line arg to hijack rip:", solution)
		print("Hijacked-value to be placed at offset:", solution.index(rip_pattern.to_bytes(8, byteorder='little')))
		#print(rip_pattern)

		'''

	def get_symbolic_var(self):
		if self.bof_func=="gets":
			return self.state.posix.stdin.content[0][0]
		elif self.bof_func=="recv":
			return self.state.globals["r8"]
		elif self.bof_func=="sprintf":
			return self.state.globals[self.reg_id]

	def write_analysis(self):
		lines = [
			str(self.overflow) + '\n',
			hex(self.start_addr) + '\n',
			str(self.bof_func) + '\n',
			self.reg_id + '\n',
		]
		with open('analysis', 'w') as f:
			f.writelines(lines)
		if self.overflow:
			load_state.dump_constraints(self.minimum_constraints, "constraints")
			load_state.dump_symbolic_vars(self.get_symbolic_var(), "symbolic_vars")

def main():
	
	'''parser = argparse.ArgumentParser()

	parser.add_argument("--bin_path", dest="bin_path")
	parser.add_argument("--start_addr", dest="start_addr")
	parser.add_argument("--end_addr", dest="end_addr")
	parser.add_argument("--regs", dest="regs")
	parser.add_argument("--stack", dest="stack")
	args = parser.parse_args()'''
	if len(sys.argv) != 9:
	  sys.exit("Not correct num of args")
	global bin_path, regs, stack
	bin_path = str(sys.argv[1])
	bof_func = str(sys.argv[2])
	hook_len = int(sys.argv[3])
	regs = str(sys.argv[4])
	stack = str(sys.argv[5])
	start_addr = int(sys.argv[6], 16)
	end_addr = int(sys.argv[7], 16) 
	base_addr = int(sys.argv[8], 16)

	#p = angr.Project(args.bin_path)
	global bof_aeg
	bof_aeg = Bof_Aeg(bin_path, bof_func, hook_len, base_addr, start_addr)
	bof_aeg.find_buf_overflow(start_addr, end_addr, regs, stack)

	bof_aeg.write_analysis()

	#IPython.embed()
	#print(simgr.mem_corrupt[0].addr)
	
if __name__ == "__main__":
	main()

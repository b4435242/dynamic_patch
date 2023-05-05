import angr, argparse, sys, IPython
import claripy
import load_state


def check_mem_corruption(simgr):
	print(simgr.active)
	if len(simgr.unconstrained):
		for path in simgr.unconstrained:
			#if path.satisfiable(extra_constraints=[path.regs.pc == b"CCCC"]):
			if path.regs.pc.symbolic:
				
				vuln_block = bof_aeg.project.factory.block(list(path.history.bbl_addrs)[-1])
				bof_aeg.vuln_addr = vuln_block.addr + vuln_block.size - 1
				print("Vuln_addr: 0x%x"%bof_aeg.vuln_addr)
				#path.add_constraints(path.regs.pc == b"CCCC")
				if path.satisfiable():
					simgr.stashes['mem_corrupt'].append(path)
				simgr.stashes['unconstrained'].remove(path)
				simgr.drop(stash='active')
	return simgr

class Bof_Aeg(object):
	def __init__(self, bin, base_addr):
		# virtual base address
		self.project = angr.Project(bin, main_opts={'base_addr': base_addr})

	def find_buf_overflow(self, start_addr, end_addr, regs, stack):
		#symsize = claripy.BVS('stdin_size', 64)
		variable = claripy.BVS('var', 256*8)
		input_value = "\nh"
		#input_value = b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x8b\xa5\x1c\xefG\xd8YD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
		simfile = angr.SimFile('/dev/stdin', content=variable)
		state = self.project.factory.blank_state(addr=start_addr, add_options=angr.options.unicorn, stdin=simfile)
		state.options |= {angr.sim_options.CONSTRAINT_TRACKING_IN_SOLVER}
		load_state.set_regs(state, regs)
		load_state.set_stack(state, stack)


		simgr = self.project.factory.simgr(state, save_unconstrained=True)
		simgr.stashes['mem_corrupt']  = []
		
		simgr.explore(step_func=check_mem_corruption, find=end_addr)
		print("corrupt {}".format(simgr.stashes['mem_corrupt']))
		#print(len(simgr.stashes['mem_corrupt'][0].posix.dumps(0)))
		
		unconstrained_state = simgr.stashes['mem_corrupt'][0]
		
		input_bvv = claripy.BVV(input_value, len(input_value)*8)
		input_bvv = input_bvv.zero_extend((256-len(input_value))*8)
		unconstrained_state.solver.add(variable==input_bvv)
		stdin_constraints = unconstrained_state.solver.constraints
		
		print("len of constraints = {}".format(len(stdin_constraints)))
		print(stdin_constraints)
		#IPython.embed()
		
		
		# Check if the test state satisfies the stdin constraints of the constrained state
		satisfiable = unconstrained_state.solver.satisfiable()

		if satisfiable:
		    print("The test string satisfies the stdin constraints.")
		else:
		    print("The test string does not satisfy the stdin constraints.")
		

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

	#IPython.embed()
	#print(simgr.mem_corrupt[0].addr)
	
if __name__ == "__main__":
	main()

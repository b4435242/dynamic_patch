import angr

def main():
	# Define the initial state of the program
	project = angr.Project("./vulnerable", auto_load_libs=False)
	state = project.factory.entry_state()

	# Set a symbolic variable for the input buffer
	input_buffer = state.solver.BVS("input_buffer", 16 * 8)
	state.memory.store(state.regs.rsp - 0x10, input_buffer, endness=project.arch.memory_endness)

	# Explore all possible paths in the program
	simgr = project.factory.simulation_manager(state)
	simgr.run()

	# Check if the instruction pointer has been hijacked
	for path in simgr.deadended:
		if path.satisfiable():
			if path.addr != project.loader.main_bin.get_symbol("vulnerable_function").rebased_addr:
				print("Instruction pointer hijacked!")
				print("Hijacked address: 0x%x" % path.addr)







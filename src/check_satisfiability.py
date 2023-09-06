import angr, claripy
import load_state
import sys
import IPython

num_input_chars = 256

def satisfiable(bin, constraints, symbolic_input, concrete_input, mode):
	project = angr.Project(bin)
	state = project.factory.entry_state()
	for c in constraints:
		state.solver.add(c)

	if mode=="gets":
		# reverse and pad with 0 due to big-endian of stdin in angr
		#processing_input = input[::-1]
		if (type(concrete_input)==str):
			concrete_input = concrete_input.encode()
		
		
		processing_input = concrete_input + b'\x00' * (num_input_chars-len(concrete_input))
		
		# BVV of string
		input_bvv = claripy.BVV(processing_input, num_input_chars*8)
		#input_bvv = input_bvv.zero_extend((num_input_chars-len(input))*8)
		#state.solver.add(symbolic_input==input_bvv)
		#IPython.embed()
		satisfiable = state.solver.satisfiable(extra_constraints=[symbolic_input==input_bvv])
	
	elif mode=="recv" or mode=="sprintf":
		# concrete_input is a number to represent size of buf here 
		# symbolic_input is a symbolic var of size in the constraint
		# form a new constraint of symbolic_input==concrete_input to test satisfiability
		state.solver.add(symbolic_input==concrete_input)
		print(state.solver.constraints)
		print(concrete_input)
		satisfiable = state.solver.satisfiable(extra_constraints=[symbolic_input==concrete_input])



	print(state.solver.constraints)
	if satisfiable:
		print("{} satisfies the stdin constraints.".format(input))
	else:
		print("{} does not satisfy the stdin constraints.".format(input))	

	with open("satisfiabililty", "w") as f:
		f.write(str(satisfiable))


if __name__ == "__main__":

	bin = str(sys.argv[1])
	constraints = load_state.load_constraints("constraints")
	symbolic_input = load_state.load_symbolic_vars("symbolic_vars")
	print("constraints={}".format(constraints))
	mode, reg_id = load_state.load_analysis("analysis")
	if mode=="gets":
		concrete_input = load_state.load_stdin_buf("concrete_input")
	elif mode=="recv":
		concrete_input = load_state.get_reg("registers", "r8", "uint_64t") 
	elif mode=="sprintf":
		concrete_input = load_state.get_reg("registers", reg_id, "double") # for convinience

	#IPython.embed()

	satisfiable(bin, constraints, symbolic_input, concrete_input, mode)



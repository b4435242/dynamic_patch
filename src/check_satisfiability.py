import angr, claripy
import load_state
import sys
import IPython

num_input_chars = 256

def satisfiable(bin, constraints, symbolic_input, input):
	project = angr.Project(bin)
	state = project.factory.entry_state()
	for c in constraints:
		state.solver.add(c)

	
	# reverse and pad with 0 due to big-endian of stdin in angr
	#processing_input = input[::-1]
	if (type(input)==str):
		input = input.encode()
	
	
	processing_input = input + b'\x00' * (num_input_chars-len(input))
	
	# BVV of string
	input_bvv = claripy.BVV(processing_input, num_input_chars*8)
	#input_bvv = input_bvv.zero_extend((num_input_chars-len(input))*8)
	state.solver.add(symbolic_input==input_bvv)
	#IPython.embed()
	satisfiable = state.solver.satisfiable(extra_constraints=[symbolic_input==input_bvv])
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
	concrete_input = load_state.load_stdin_buf("stdin_buf")
	#IPython.embed()

	satisfiable(bin, constraints, symbolic_input, concrete_input)



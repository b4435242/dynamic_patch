import angr, argparse, sys, IPython
import claripy
from angr.storage.memory_mixins.address_concretization_mixin import MultiwriteAnnotation
from angr.procedures.stubs.format_parser import FormatParser
#from format_parser import FormatParser
import logging
import struct
from decimal import *



_l = logging.getLogger(name=__name__)

class gets(angr.SimProcedure):
	# pylint:disable=arguments-differ

	def run(self, dst):
		if once("gets_warning"):
			_l.warning(
				"The use of gets in a program usually causes buffer overflows. You may want to adjust "
				"SimStateLibc.max_gets_size to properly mimic an overflowing read."
			)
		# Manually assign params value from calling convetion
		dst = self.state.regs.rcx

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


		
def recv(state):
	dst = state.regs.rdx
	fd = 0
	simfd = state.posix.get_fd(fd)
	symbolic_size = state.globals["r8"]
	real_size = simfd.read(dst, symbolic_size)		

	#print("[ngx_recv]mem on rip is {}".format(state.memory.load(0x7ffffc088, 8)))
	print("[ngx_recv]max_packet_size={}".format(state.libc.max_packet_size))
	print("[ngx_recv]recv size={}".format(state.solver.eval(real_size)))
	#IPython.embed()

	# put return val in rax
	#state.regs.rax = claripy.BVS('res', 32)
	state.regs.rax = -2 #NGX_AGAIN


class sprintf(FormatParser):
	# pylint:disable=arguments-differ

	def run(self, dst_ptr, fmt):  # pylint:disable=unused-argument
		# Angr treats all args as args of fmt, so manually pop 2 args for dst_ptr and fmt
		# Originally assign from calling convetion rcx and rdx

		va_arg = self.va_arg
		fmt = va_arg("void*") #fmt = self.state.regs.rdx
		dst_ptr = va_arg("void*") #dst_ptr = self.state.regs.rcx
		# Only support 2 arg of fmt now for symbolic execution with x86-64 cc(calling convention) rcx rdx r8 r9
		if 'r8' in self.state.globals:
			self.state.regs.r8 = self.state.globals['r8']
		if 'r9' in self.state.globals:
			self.state.regs.r9 = self.state.globals['r9']

		print("[sprintf] fmt={}".format(fmt))
		print("[sprintf] dst_ptr={}".format(dst_ptr))


		# The format str is at index 1
		fmt_str = self._parse(fmt)

		# implementation of replace
		def replace():
			string = None
			reg = ["r8", "r9"]
			reg_idx = 0
			for component in fmt_str.components:
				# if this is just concrete data
				if isinstance(component, bytes):
					string = fmt_str._add_to_string(string, fmt_str.parser.state.solver.BVV(component))
				elif isinstance(component, str):
					raise Exception("this branch should be impossible?")
				elif isinstance(component, claripy.ast.BV):  # pylint:disable=isinstance-second-argument-not-valid-type
					string = fmt_str._add_to_string(string, component)
				else:
					# okay now for the interesting stuff
					# what type of format specifier is it?
					fmt_spec = component
					if fmt_spec.spec_type == b"s":
						if fmt_spec.length_spec == b".*":
							str_length = va_arg("size_t")
						else:
							str_length = None
						str_ptr = va_arg("char*")
						string = fmt_str._add_to_string(string, fmt_str._get_str_at(str_ptr, max_length=str_length))
					# self-implement for float and double type with supporting symbolic and concrete with 2 args at most which is from r8 or r9 only
					# symbolic: create symbolic string of same length of MAX_VAL 
					# concrete: create symbolic string of same length of input 
					elif fmt_spec.spec_type in (b"f"):	
						# r8 r9 pass flow globals -> regs -> i_val
						i_val = va_arg("void*")
							
						# C type
						MAX_FLOAT = claripy.FPV(struct.unpack('>f', b'\x7f\x7f\xff\xff')[0], claripy.fp.FSORT_DOUBLE)
						MAX_DOUBLE = claripy.FPV(struct.unpack('>d', b'\x7f\xef\xff\xff\xff\xff\xff\xff')[0], claripy.fp.FSORT_DOUBLE)  # 1.7976931348623157e+308
						# f_val assigned as symbolic var
						f_val = claripy.FPS(reg[reg_idx], claripy.fp.FSORT_DOUBLE)
						if fmt_str.parser.state.solver.symbolic(i_val): # case of symbolic float or double input
							self.state.globals[reg[reg_idx]] = f_val
							# concretize symbolic var to C max value
							if fmt_spec.size==8: # double
								c_val = fmt_str.parser.state.solver.eval(f_val, extra_constraints=[f_val==MAX_DOUBLE])
								self.state.solver.add(f_val<=MAX_DOUBLE)
							else: # float
								c_val = fmt_str.parser.state.solver.eval(f_val, extra_constraints=[f_val==MAX_FLOAT])
								self.state.solver.add(f_val<=MAX_FLOAT)
						else:  # case of concrete float or double input
							c_val = fmt_str.parser.state.solver.eval(f_val, extra_constraints=[f_val==self.state.globals[reg[reg_idx]]]) # originally f_val==i_val, but need to take care of transformation from Python number to C float/double bytes 

						# extend format to full precision
						s_val = str(Decimal(c_val))
						
						if isinstance(fmt_spec.length_spec, int):
							s_val = s_val.rjust(fmt_spec.length_spec, fmt_spec.pad_chr)
						# transform concrete to symbolic with same length
						symbolic_s_val = claripy.BVS("s_val", len(s_val)*8)
						#IPython.embed()
						string = fmt_str._add_to_string(string, symbolic_s_val)
						
					# integers, for most of these we'll end up concretizing values..
					else:
						# ummmmmmm this is a cheap translation but I think it should work
						i_val = va_arg("void*")
						c_val = int(fmt_str.parser.state.solver.max(i_val))
						c_val &= (1 << (fmt_spec.size * 8)) - 1
						if fmt_spec.signed and (c_val & (1 << ((fmt_spec.size * 8) - 1))):
							c_val -= 1 << fmt_spec.size * 8

						#IPython.embed()

						if fmt_spec.spec_type in (b"d", b"i"):
							s_val = str(c_val)
						elif fmt_spec.spec_type == b"u":
							s_val = str(c_val)
						elif fmt_spec.spec_type == b"c":
							s_val = chr(c_val & 0xFF)
						elif fmt_spec.spec_type == b"x":
							s_val = hex(c_val)[2:]
						elif fmt_spec.spec_type == b"o":
							s_val = oct(c_val)[2:]
						elif fmt_spec.spec_type == b"p":
							s_val = hex(c_val)
						else:
							raise SimProcedureError("Unimplemented format specifier '%s'" % fmt_spec.spec_type)

						if isinstance(fmt_spec.length_spec, int):
							s_val = s_val.rjust(fmt_spec.length_spec, fmt_spec.pad_chr)

						string = fmt_str._add_to_string(string, fmt_str.parser.state.solver.BVV(s_val.encode()))
					reg_idx += 1
			return string
		out_str = replace() #out_str = fmt_str.replace(self.va_arg)
		self.state.memory.store(dst_ptr, out_str)
		
		print("[sprintf] fmt_str={}".format(fmt_str))
		print("[sprintf] out_str={}".format(out_str))
		
		# place the terminating null byte
		self.state.memory.store(
			dst_ptr + (out_str.size() // self.arch.byte_width), self.state.solver.BVV(0, self.arch.byte_width)
		)
		
		print("[sprintf]rip={}".format(self.state.regs.rip))
		
		# ret to unexpected address cuz hook simprocedure on addr, which works well with hook on symbol #
		# workaround: jump to next instruction
		self.jump(self.state.addr+self.state.globals["hook_len"])
		#return out_str.size() // self.arch.byte_width	




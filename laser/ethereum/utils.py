import re
from z3 import *

TT256 = 2 ** 256
TT256M1 = 2 ** 256 - 1
TT255 = 2 ** 255

def safe_decode(hex_encoded_string):

    if (hex_encoded_string.startswith("0x")):
        return bytes.fromhex(hex_encoded_string[2:])
    else:
        return bytes.fromhex(hex_encoded_string)

def to_signed(i):
    return i if i < TT255 else i - TT256

def get_instruction_index(instruction_list, address):

	index = 0

	for instr in instruction_list:
		if instr['address'] == address:
			return index
		index += 1

	return None

def get_trace_line(instr, state):

	stack = str(state.stack[::-1])

	stack = re.sub("(\d+)",	lambda m: hex(int(m.group(1))), stack)
	stack = re.sub("\n", "", stack)

	return str(instr['address']) + " " + instr['opcode'] + "\tSTACK: " + stack

def pop_bitvec(state):
    # pop one element from stack, converting boolean expression to bitvector

    item = state.stack.pop()

    if type(item) == BoolRef:
        return If(item, BitVecVal(1, 256), BitVecVal(0, 256))
    else:
        return item

def solve_path(svm, path, caller = None, owner = None, owner_storage_index = None):

    s = Solver() 

    if(caller is not None):
        s.add(svm.env['caller'] == caller)
    if(owner is not None):
        s.add(svm.storage[owner_storage_index] == owner)

    for edge in path:
        if edge.condition is not None:
            s.add(edge.condition)

    if (s.check() == sat):
        return s.model()

    else:
        return None

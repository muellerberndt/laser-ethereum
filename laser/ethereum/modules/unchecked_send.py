from laser.ethereum import helper
from z3 import *

def execute(svm):

	for k in svm.nodes:
		node = svm.nodes[k]

		for instruction in node.instruction_list:

			if(instruction['opcode'] == "CALL"):
				state = node.states[instruction['address']]

				gas, to, value, meminstart, meminsz, memoutstart, memoutsz = \
                        state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop()

				print("CALL with value: " + str(value))

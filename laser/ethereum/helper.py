import re
from z3 import *
import logging

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


def get_concrete_int(item):

    if (type(item) == int):
        return item

    if (type(item) == BitVecNumRef):
        return item.as_long()

    return simplify(item).as_long()


def concrete_int_from_bytes(_bytes, start_index):

    b = _bytes[start_index:start_index+32]

    val = int.from_bytes(b, byteorder='big')

    return val


def concrete_int_to_bytes(val):

    logging.info("concrete_int_to_bytes " + str(bytes) + ", " + str(start_index))

    return (simplify(val).as_long()).to_bytes(32, byteorder='big')


def storage_constraints_for_path(svm, path):

    storage_constraints = []

    for edge in path:
       if (edge.condition is not None):

            cond = str(edge.condition)

            if 'storage' in cond:

                m = re.search(r'storage_([0-9a-f]+)', cond)

                if (m):

                    storage_constraints.append(m.group(1))

    return storage_constraints


def solver_for_path(svm, path):

    solver = Solver() 

    for edge in path:
        if edge.condition is not None:
            solver.add(edge.condition)

    return solver


def solve_path(svm, path):

    s = Solver()

    for edge in path:
        if edge.condition is not None:
            s.add(edge.condition)

    if (s.check() == sat):
        return s.model()

    else:
        return unsat


def satisfy_recursively(svm, node_addr, models = [], visited = []):

    if (node_addr in visited):
        logging.info("Circular reference, aborting")
        return None

    visited.append(node_addr)

    logging.info("Trying to solve constraints for node " + str(node_addr))

    for path in svm.paths[node_addr]:

        can_solve = True

        # Get constraints on storage locations

        constraints = storage_constraints_for_path(svm, path)

        nc = len(constraints)

        if (nc):

            logging.info("Path constrained by storage slots: " + str(constraints))

            logging.info("Trying to resolve " + str(nc) + " storage writes")

            solved = 0

            try:

                for storage_offset in constraints:

                    for _node_addr in svm.sstor_node_lists[storage_offset]:

                        m = satisfy_recursively(svm, _node_addr, models, visited)

                        logging.info("Satisfy returned " + str(m))

                        if m:
                            solved += 1
                            break

                logging.info(str(solved) + " of " + str(nc) + " writes satisfied")

                if solved == nc:

                    logging.info("Found viable path to node " + str(node_addr) + ", trying to solve")

                else:

                    logging.info("Unable to find viable path to node " + str(node_addr) + "")

                    can_solve = False

            except KeyError:
                    logging.info("No writes available to storage location")
                    can_solve = False

        else:

                logging.info("No storage constraints on path.")


        if can_solve:

            model = solve_path(svm, path)

            if (model == unsat):
                logging.info("Unsatisfiable")
                return False
            else:
                models.append(model)
                logging.info("Model found")               
                return True
                
        else:
            return False


def satisfy(svm, node_addr):

    models = []

    satisfy_recursively(svm, node_addr, models)

    return models


def debug_operand(operand):
    logging.info(str(type(operand)) + ", " + str(simplify(operand)))

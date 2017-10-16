from enum import Enum
from laser.ethereum import utils
from z3 import *
import copy
import logging

TT256 = 2 ** 256
TT256M1 = 2 ** 256 - 1
TT255 = 2 ** 255

MAX_DEPTH = 5

logging.basicConfig(level=logging.INFO)

class SVMError(Exception):
    pass


class JumpType(Enum):
    CONDITIONAL = 1
    UNCONDITIONAL = 2


class State(): 

    def __init__(self):

        self.vars = {}

        self.vars['callvalue'] = BitVec("callvalue", 256)
        self.vars['caller'] = BitVec("caller", 256)
        self.vars['origin'] = BitVec("origin", 256)
        self.vars['address_to'] = BitVec("address_to", 256) 

        self.calldata = {}
        self.memory = {}
        self.storage = {}
        self.stack = []
        self.pc = 0

    def calldata_alloc(self, offset):
        data = BitVec("calldata_" + str(offset), 256)
        return data


class Node:

    def __init__(self, start_addr=0):
        self.start_addr = start_addr
        self.instruction_list = []


class Edge:
    
    def __init__(self, node_from, node_to, edge_type=JumpType.UNCONDITIONAL, condition=None):

        self.node_from = node_from
        self.node_to = node_to
        self.type = edge_type
        self.condition = condition

class SVM:

    def __init__(self, disassembly, max_depth=MAX_DEPTH, branch_at_jumpi = False):
        self.disassembly = disassembly
        self.nodes = {}
        self.addr_visited = []
        self.edges = []
        self.paths = {}
        self.send_eth_nodes = []
        self.trace = ""
        self.max_depth = max_depth
        self.branch_at_jumpi = branch_at_jumpi


    def walk_to_node(self, this_node, node_to, path, paths, depth):

        if (depth > MAX_DEPTH):
            return

        if this_node == node_to:
            paths.append(path)
            return

        for edge in self.edges:

            if edge.node_from == this_node:
                new_path = copy.deepcopy(path)
                new_path.append(edge)
                self.walk_to_node(edge.node_to, node_to, new_path, paths, depth + 1)


    def find_paths(self, node_to):

        paths = []

        self.walk_to_node(0, node_to, [], paths, 0)

        return paths


    def sym_exec(self):

        logging.info("Starting SVM execution")

        self.nodes[0] = self._sym_exec(State(), 0)

        logging.info(str(len(self.nodes)) + " nodes, " + str(len(self.edges)) + " edges")

        logging.info("Resolving paths")

        for key in self.nodes:

            paths = self.find_paths(key)

            logging.debug("Found " + str(len(paths)) + " path to node " + str(key))

            self.paths[key] = paths


    def _sym_exec(self, state, depth):
    
        start_addr = self.disassembly.instruction_list[state.pc]['address']
        node = Node(start_addr)

        logging.debug("- Entering new block, index = " + str(state.pc) + ", address = " + str(start_addr) + ", depth = " + str(depth))

        halt = False

        while not halt:

            instr = self.disassembly.instruction_list[state.pc]
            node.instruction_list.append(instr)

            op = instr['opcode']

            logging.debug(utils.get_trace_line(instr, state))

            state.pc += 1

            # stack ops
            
            if op.startswith("PUSH"):
                value = BitVecVal(int(instr['argument'][2:], 16), 256)
                state.stack.append(value)

            elif op.startswith('DUP'):
                depth = int(op[3:])
                state.stack.append(state.stack[-depth])

            elif op.startswith('SWAP'):
                depth = int(op[4:])
                temp = state.stack[-depth - 1]
                state.stack[-depth - 1] = state.stack[-1]
                state.stack[-1] = temp

            elif op == 'POP':
                state.stack.pop()

            # Bitwise ops

            elif op == 'AND':
                state.stack.append(state.stack.pop() & state.stack.pop())

            elif op == 'OR':
                op1 = state.stack.pop()
                op2 = state.stack.pop()

                if (type(op1) == BoolRef):
                    op1 = If(op1, BitVecVal(1,256), BitVecVal(0,256))

                if (type(op2) == BoolRef):
                    op2 = If(op2, BitVecVal(1,256), BitVecVal(0,256))

                state.stack.append(op1 | op2)

            elif op == 'XOR':
                state.stack.append(state.stack.pop() ^ state.stack.pop())

            elif op == 'NOT':
                state.stack.append(TT256M1 - state.stack.pop())

            elif op == 'BYTE':
                s0, s1 = state.stack.pop(), state.stack.pop()

                if s0 >= 32:
                    state.stack.append(0)
                else:
                    state.stack.append((s1 // 256 ** (31 - s0)) % 256)

            # Arithmetics

            elif op == "ADD":
                state.stack.append((utils.pop_bitvec(state) + utils.pop_bitvec(state)))

            elif op == "SUB":
                state.stack.append((utils.pop_bitvec(state) - utils.pop_bitvec(state)))

            elif op == 'MUL':
                state.stack.append(utils.pop_bitvec(state) * utils.pop_bitvec(state))

            elif op == 'DIV':
                s0, s1 = utils.pop_bitvec(state), utils.pop_bitvec(state)
                state.stack.append(0 if s1 == 0 else s0 / s1)

            elif op == 'MOD':
                s0, s1 = utils.pop_bitvec(state), utils.pop_bitvec(state)
                state.stack.append(0 if s1 == 0 else s0 % s1)

            elif op == 'SDIV':
                s0, s1 = utils.to_signed(utils.pop_bitvec(state)), utils.to_signed(utils.pop_bitvec(state))
                state.stack.append(0 if s1 == 0 else (abs(s0) // abs(s1) *
                                              (-1 if s0 * s1 < 0 else 1)) & TT256M1)

            elif op == 'SMOD':
                s0, s1 = utils.to_signed(utils.pop_bitvec(state)), utils.to_signed(utils.pop_bitvec(state))
                state.stack.append(0 if s1 == 0 else (abs(s0) % abs(s1) *
                                              (-1 if s0 < 0 else 1)) & TT256M1)

            elif op == 'ADDMOD':
                s0, s1, s2 = utils.pop_bitvec(state), utils.pop_bitvec(state), utils.pop_bitvec(state)
                state.stack.append((s0 + s1) % s2 if s2 else 0)

            elif op == 'MULMOD':
                s0, s1, s2 = utils.pop_bitvec(state), utils.pop_bitvec(state), utils.pop_bitvec(state)
                state.stack.append((s0 * s1) % s2 if s2 else 0)

            elif op == 'EXP':
                # Not implemented. The only EXP operations I have seen used are pow(op1, 0), so return 1
                base, exponent = state.stack.pop(), state.stack.pop()

                state.stack.append(BitVecVal(1,256))

            elif op == 'SIGNEXTEND':
                s0, s1 = state.stack.pop(), state.stack.pop()
                if s0 <= 31:
                    testbit = s0 * 8 + 7
                    if s1 & (1 << testbit):
                        state.stack.append(s1 | (TT256 - (1 << testbit)))
                    else:
                        state.stack.append(s1 & ((1 << testbit) - 1))
                else:
                    state.stack.append(s1)

            # Comparisons

            elif op == 'LT':

                exp = ULT(utils.pop_bitvec(state), utils.pop_bitvec(state))
                state.stack.append(exp)

            elif op == 'GT':

                exp = UGT(utils.pop_bitvec(state), utils.pop_bitvec(state))
                state.stack.append(exp)

            elif op == 'SLT':

                exp = SLT(utils.pop_bitvec(state) < utils.pop_bitvec(state))
                state.stack.append(exp)

            elif op == 'SGT':

                exp = SGT(utils.pop_bitvec(state) > utils.pop_bitvec(state))
                state.stack.append(exp)

            elif op == 'EQ':

                exp = state.stack.pop() == state.stack.pop()
                state.stack.append(exp)

            elif op == 'ISZERO':

                val = state.stack.pop()

                if (type(val) == BoolRef):
                   exp = val == True
                else:   
                   exp = val == 0

                state.stack.append(exp)

             # Call data

            elif op == 'CALLVALUE':
                state.stack.append(state.vars['callvalue'])

            elif op == 'CALLDATALOAD':
                offset = state.stack.pop()
                state.stack.append(state.calldata_alloc(offset))

            elif op == 'CALLDATASIZE':
                state.stack.append(BitVec("calldatasize", 256))

            elif op == 'CALLDATACOPY':
                mstart, dstart, size = state.stack.pop(), state.stack.pop(), state.stack.pop()

            # Control flow

            elif op == 'STOP':
                return node

            # Environment

            elif op == 'ADDRESS':
                state.stack.append(state.vars['address_to'])

            elif op == 'BALANCE':
                addr = state.stack.pop()
                state.stack.append(BitVec("balance_at_" + str(addr), 256))

            elif op == 'ORIGIN':
                state.stack.append(state.vars['origin'])

            elif op == 'CALLER':
                state.stack.append(state.vars['caller'])

            elif op == 'CODESIZE':
                state.stack.append(len(self.disassembly.instruction_list))

            if op == 'SHA3':
                s0, s1 = utils.pop_bitvec(state), utils.pop_bitvec(state)
                state.stack.append(BitVec("sha_hash", 256))

            elif op == 'GASPRICE':
                state.stack.append(0)

            elif op == 'CODECOPY':
                start, s1, size = state.stack.pop(), state.stack.pop(), state.stack.pop()
                # Not implemented

            elif op == 'EXTCODESIZE':
                addr = state.stack.pop()
                state.stack.append(BitVec("extcodesize", 256))

            elif op == 'EXTCODECOPY':
                addr = state.stack.pop()
                start, s2, size = state.stack.pop(), state.stack.pop(), state.stack.pop()
                # Not implemented

            elif op == 'BLOCKHASH':
                state.stack.append(BitVec("blockhash", 256))

            elif op == 'COINBASE':
                state.stack.append(BitVec("coinbase", 256))

            elif op == 'TIMESTAMP':
                state.stack.append(BitVec("timestamp", 256))

            elif op == 'NUMBER':
                state.stack.append(BitVec("block_number", 256))

            elif op == 'DIFFICULTY':
                state.stack.append(BitVec("block_difficulty", 256))

            elif op == 'GASLIMIT':
                state.stack.append(BitVec("block_gaslimit", 256))

            elif op == 'MLOAD':
                offset = state.stack.pop()

                try:
                    data = state.memory[offset]
                except KeyError:
                    state.memory[offset] = BitVec("mem_" + str(offset), 256)
                    data = state.memory[offset]

                state.stack.append(data)

            elif op == 'MSTORE':
                offset, value = state.stack.pop(), state.stack.pop()

                state.memory[offset] = value

            elif op == 'MSTORE8':
                offset, value = state.stack.pop(), state.stack.pop()

                state.memory[offset] = value % 256

            elif op == 'SLOAD':
                offset = state.stack.pop()
                logging.debug("Storage access at offset " + str(offset))

                try:
                    data = state.storage[offset]
                except KeyError:
                    state.storage[offset] = BitVec("storage_" + str(offset), 256)
                    data = state.storage[offset]

                state.stack.append(data)

            elif op == 'SSTORE':
                offset, value = state.stack.pop(), state.stack.pop()

                state.storage[offset] = value

            elif op == 'JUMP':

                jump_addr = state.stack.pop()

                if (type(jump_addr) == BitVecRef):
                    logging.info("Invalid jump argument: JUMP <bitvector> at " + str(self.disassembly.instruction_list[state.pc]['address']))

                    return node

                if (depth < self.max_depth):

                    jump_addr = jump_addr.as_long()

                    logging.debug("JUMP to " + str(jump_addr))

                    i = utils.get_instruction_index(self.disassembly.instruction_list, jump_addr)

                    if self.disassembly.instruction_list[i]['opcode'] == "JUMPDEST":
                        logging.debug("Current nodes: " + str(self.nodes))

                        if jump_addr not in self.addr_visited:
                            self.addr_visited.append(jump_addr)
                            new_state = copy.deepcopy(state)
                            new_state.pc = i
                            new_node = self._sym_exec(new_state, depth + 1)
                            self.nodes[jump_addr] = new_node

                        self.edges.append(Edge(node.start_addr, jump_addr, JumpType.UNCONDITIONAL))
                    else:
                        self.trace += "Skipping invalid jump destination"

                return node

            elif op == 'JUMPI':
                jump_addr, condition = state.stack.pop().as_long(), state.stack.pop()

                if (depth < self.max_depth):

                    i = utils.get_instruction_index(self.disassembly.instruction_list, jump_addr)

                    logging.debug("JUMPI to " + str(jump_addr))

                    if not i:
                        logging.debug("Invalid jump destination: " + str(jump_addr))
                    else:
                        instr = self.disassembly.instruction_list[i]

                        # Add new node for condition == True

                        if instr['opcode'] != "JUMPDEST":
                            logging.debug("Invalid jump destination: " + str(jump_addr))
                        else:
                            if jump_addr not in self.addr_visited:

                                self.addr_visited.append(jump_addr)

                                new_state = copy.deepcopy(state)

                                new_state.pc = i

                                new_node = self._sym_exec(new_state, depth + 1)
                                self.nodes[jump_addr] = new_node

                            logging.debug("Adding edge with condition: " + str(condition))

                            self.edges.append(Edge(node.start_addr, jump_addr, JumpType.CONDITIONAL, condition))

                        if (self.branch_at_jumpi):

                            # Add new node for condition == False

                            new_state = copy.deepcopy(state)

                            new_node = self._sym_exec(new_state, depth)

                            start_addr = self.disassembly.instruction_list[state.pc]['address']
                            self.nodes[start_addr] = new_node

                            self.edges.append(Edge(node.start_addr, start_addr, JumpType.CONDITIONAL, Not(condition)))

                            return node


            elif op == 'PC':
                state.stack.append(state.pc - 1)

            elif op == 'MSIZE':
                state.stack.append(BitVec("msize", 256))

            elif op == 'GAS':
                state.stack.append(10000000)

            elif op.startswith('LOG'):
                depth = int(op[3:])
                mstart, msz = state.stack.pop(), state.stack.pop()
                topics = [state.stack.pop() for x in range(depth)]
                # Not supported

            elif op == 'CREATE':
                value, mstart, msz = state.stack.pop(), state.stack.pop(), state.stack.pop()
                # Not supported
                state.stack.append(0)

            elif op == 'CALL':
                gas, to, value, meminstart, meminsz, memoutstart, memoutsz = \
                state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop()
                # Not supported

                send_eth = False

                if (type(value) is not BitVecNumRef):
                    send_eth = True
                elif value.as_long() > 0:
                    send_eth = True

                if (send_eth):
                    logging.info("CALL with non-zero value: " + str(value))
                    self.send_eth_nodes.append(start_addr)
             
                state.stack.append(BitVecVal(0, 256))

            elif op == 'CALLCODE':
                gas, to, value, meminstart, meminsz, memoutstart, memoutsz = \
                state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop()
                # Not supported          
                state.stack.append(BitVecVal(0, 256))

            elif op == 'RETURN':
                offset, length = state.stack.pop(), state.stack.pop()
                # Not supported        
                # logging.debug("Returning from block " +  str(start_addr))
                return node

            elif op == 'SUICIDE':
                # logging.debug("Returning from block " +  str(start_addr))
                return node

            elif op == 'REVERT':
                # logging.debug("Returning from block " +  str(start_addr))
                return node

            elif op == 'INVALID':
                # logging.debug("Returning from block " +  str(start_addr))
                return node


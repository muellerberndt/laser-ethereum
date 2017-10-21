from enum import Enum
from laser.ethereum import utils
from z3 import *
import copy
import logging
from random import randint
import sha3


TT256 = 2 ** 256
TT256M1 = 2 ** 256 - 1
TT255 = 2 ** 255

MAX_DEPTH = 16


class SVMError(Exception):
    pass


class JumpType(Enum):
    CONDITIONAL = 1
    UNCONDITIONAL = 2


class State(): 

    def __init__(self):

        self.calldata = {}
        self.memory = {}
        self.stack = []
        self.pc = 0

    def calldata_alloc(self, offset):
        data = BitVec("calldata_" + str(offset), 256)
        return data


class Node:

    def __init__(self, start_addr=0):
        self.start_addr = start_addr
        self.instruction_list = []

    def __str__(self):
        return str(self.as_dict())
        
    def as_dict(self):

        code = ""

        for instruction in self.instruction_list:
            code += str(instruction['address']) + " " + instruction['opcode']
            if instruction['opcode'].startswith("PUSH"):
                code += " " + instruction['argument']

            code += "\\n"

        return {'id': self.start_addr, 'code': code}


class Edge:
    
    def __init__(self, node_from, node_to, edge_type=JumpType.UNCONDITIONAL, condition=None):

        self.node_from = node_from
        self.node_to = node_to
        self.type = edge_type
        self.condition = condition

    def __str__(self):
        return str(self.as_dict())
        
    def as_dict(self):

        return {'from': self.node_from, 'to': self.node_to}

class SVM:

    def __init__(self, disassembly, max_depth=MAX_DEPTH, branch_at_jumpi = False):
        self.disassembly = disassembly
        self.nodes = {}
        self.addr_visited = []
        self.edges = []
        self.paths = {}
        self.send_eth_locs = []
        self.suicide_locs = []
        self.reentrancy_funcs = []
        self.sstor_node_lists = {}
        self.storage = {}
        self.function_state = {}
        self.trace = ""
        self.max_depth = max_depth
        self.branch_at_jumpi = branch_at_jumpi

        self.env = {}

        self.env['callvalue'] = BitVec("callvalue", 256)
        self.env['caller'] = BitVec("caller", 256)
        self.env['origin'] = BitVec("origin", 256)
        self.env['address_to'] = BitVec("address_to", 256) 


    def depth_first_search(self, this_node, node_to, path, paths, depth, nodes_visited):

        if (depth > MAX_DEPTH):
            return

        if this_node == node_to:
            paths.append(path)
            return

        nodes_visited.append(this_node)

        edges_out = []

        for edge in self.edges:

            if edge.node_from == this_node and edge.node_to not in nodes_visited:
                edges_out.append(edge)

        for edge in edges_out:

            new_path = copy.deepcopy(path)
            new_path.append(edge)
            self.depth_first_search(edge.node_to, node_to, new_path, paths, depth + 1, nodes_visited)


    def find_paths(self, node_to):

        paths = []
        nodes_visited = []

        self.depth_first_search(0, node_to, [], paths, 0, nodes_visited)

        return paths


    def sym_exec(self):

        logging.debug("Starting SVM execution")

        self.nodes[0] = self._sym_exec(State(), 0)

        logging.info(str(len(self.nodes)) + " nodes, " + str(len(self.edges)) + " edges")

        logging.info("Resolving paths")

        for key in self.nodes:

            paths = self.find_paths(key)

            logging.debug("Found " + str(len(paths)) + " paths to node " + str(key))

            self.paths[key] = paths


    def _sym_exec(self, state, depth):
    
        start_addr = self.disassembly.instruction_list[state.pc]['address']
        node = Node(start_addr)

        logging.debug("- Entering new block, index = " + str(state.pc) + ", address = " + str(start_addr) + ", depth = " + str(depth))

        if start_addr == 0:
            self.function_state['current_func'] = "prologue"
            self.function_state['current_func_addr'] = start_addr
            self.function_state['sstore_called'] = False            

        if start_addr in self.disassembly.addr_to_func:
            # Start of a function

            function_name = self.disassembly.addr_to_func[start_addr]

            self.function_state['current_func'] = function_name
            self.function_state['sstore_called'] = False

            logging.info("- Entering function " + function_name)

            node.instruction_list.append({'opcode': function_name, 'address': self.disassembly.instruction_list[state.pc]['address']})

            state.pc += 1

        halt = False

        instr = self.disassembly.instruction_list[state.pc]

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
                op1 = state.stack.pop() 
                op2 = state.stack.pop()

                state.stack.append(op1 & op2)

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
                state.stack.append(UDiv(s0, s1))

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
                # we only implement 2 ** x
                base, exponent = state.stack.pop(), state.stack.pop()

                if (base.as_long() == 2):
                    if exponent == 0:
                        state.stack.append(BitVecVal(1, 256))
                    else:
                        state.stack.append(base << (exponent - 1))

                else:
                    state.stack.append(base)

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

                exp = utils.pop_bitvec(state) < utils.pop_bitvec(state)
                state.stack.append(exp)

            elif op == 'SGT':

                exp = utils.pop_bitvec(state) > utils.pop_bitvec(state)
                state.stack.append(exp)

            elif op == 'EQ':

                op1 = state.stack.pop()
                op2 = state.stack.pop()

                if(type(op1) == BoolRef):
                    op1 = If(op1, BitVecVal(1,256), BitVecVal(0,256))

                if(type(op2) == BoolRef):
                    op2 = If(op2, BitVecVal(1,256), BitVecVal(0,256))

                exp = op1 == op2

                state.stack.append(exp)

            elif op == 'ISZERO':

                val = state.stack.pop()

                if (type(val) == BoolRef):
                   exp = val == False
                else:   
                   exp = val == 0

                state.stack.append(exp)

             # Call data

            elif op == 'CALLVALUE':
                state.stack.append(self.env['callvalue'])

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
                state.stack.append(self.env['address_to'])

            elif op == 'BALANCE':
                addr = state.stack.pop()
                state.stack.append(BitVec("balance_at_" + str(addr), 256))

            elif op == 'ORIGIN':
                state.stack.append(self.env['origin'])

            elif op == 'CALLER':
                state.stack.append(self.env['caller'])

            elif op == 'CODESIZE':
                state.stack.append(len(self.disassembly.instruction_list))

            if op == 'SHA3':
                s0, s1 = utils.pop_bitvec(state), utils.pop_bitvec(state)

                mem = state.memory[s0]

                # Don't actually calculate the hash

                state.stack.append(BitVec("SHA3(" + str(simplify(mem)) + ")", 256))

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

                logging.debug("Load from memory[" + str(offset) + "]: " + str(data))

                state.stack.append(data)

            elif op == 'MSTORE':
                offset, value = state.stack.pop(), state.stack.pop()

                logging.debug("Store to memory[" + str(offset) + "]: " + str(value))

                state.memory[offset] = value

            elif op == 'MSTORE8':
                offset, value = state.stack.pop(), state.stack.pop()

                state.memory[offset] = value % 256

            elif op == 'SLOAD':
                index = state.stack.pop()
                logging.debug("Storage access at index " + str(index))

                if type(index) == BitVecRef:
                    # SLOAD from hash offset

                    k = sha3.keccak_512()
                    k.update(bytes(str(index), 'utf-8'))
                    index = k.hexdigest()[:8]

                try:
                    data = self.storage[index]
                except KeyError:
                    data = BitVec("storage_" + str(index), 256)
                    self.storage[index] = data

                state.stack.append(data)

            elif op == 'SSTORE':
                index, value = state.stack.pop(), state.stack.pop()

                self.function_state['sstore_called'] = True

                logging.debug("Write to storage[" + str(index) + "] at node " + str(start_addr))

                if type(index) == BitVecRef:
                    # SSTORE to hash offset

                    k = sha3.keccak_512()
                    k.update(bytes(str(index), 'utf-8'))
                    index = k.hexdigest()[:8]

                    self.storage[index] = value
                else:
                    index = str(index)

                try:
                    self.sstor_node_lists[index].append(start_addr)
                except KeyError:
                    self.sstor_node_lists[index] = [start_addr]

                try:
                    self.storage[index]
                except KeyError:
                    self.storage[index] = BitVec("storage_" + str(index), 256)

            elif op == 'JUMP':

                jump_addr = state.stack.pop()

                if (type(jump_addr) == BitVecRef):
                    logging.debug("Invalid jump argument: JUMP <bitvector> at " + str(self.disassembly.instruction_list[state.pc]['address']))

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

                            if (type(condition) == BoolRef):
                                self.edges.append(Edge(node.start_addr, start_addr, JumpType.CONDITIONAL, Not(condition)))
                            else:
                                self.edges.append(Edge(node.start_addr, start_addr, JumpType.CONDITIONAL, condition == 0))                               

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

                send_eth = False

                if (type(value) is not BitVecNumRef):
                    send_eth = True
                elif value.as_long() > 0:
                    send_eth = True

                if (send_eth):
                    logging.debug("CALL with non-zero value: " + str(value))
                    self.send_eth_locs.append({'address': start_addr, 'function_name': self.function_state['current_func']})

                    if not self.function_state['sstore_called']:
                        logging.info("Possible reentrancy at " + self.function_state['current_func'])
                        self.reentrancy_funcs.append(self.function_state['current_func_addr'])

                ret = BitVec("retval_" + str(self.disassembly.instruction_list[state.pc]['address']) + "_" + str(randint(0, 1000)), 256)

                state.stack.append(ret)

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
                self.suicide_locs.append({'address': start_addr, 'function_name': self.function_state['current_func']})
                return node

            elif op == 'REVERT':
                # logging.debug("Returning from block " +  str(start_addr))
                return node

            elif op == 'INVALID':
                # logging.debug("Returning from block " +  str(start_addr))
                return node


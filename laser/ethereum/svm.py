from enum import Enum
from laser.ethereum import utils
from z3 import *
import copy
import logging
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
    CALL = 3
    RETURN = 4


class State(): 

    def __init__(self, gas = 1000000):
        self.storage = {}
        self.memory = []
        self.stack = []
        self.last_returned = []
        self.gas = gas
        self.pc = 0

    def as_dict(self):

        return {'memory': self.memory, 'stack': self.stack, 'storage': self.storage, 'pc': self.pc, 'gas': self.gas}



    def mem_extend(self, start, sz):

        if sz and start + sz > len(self.memory):

            n_append = start + sz - len(self.memory)

            while n_append > 0:
                self.memory.append(0)
                n_append -= 1

            # Deduct gas.. not yet implemented


class Context(): 

    def __init__(
        self,
        module,
        calldata = [],
        callvalue = BitVec("callvalue", 256),
        caller = BitVec("caller", 256),
        origin = BitVec("origin", 256),
        address = BitVec("address", 256),
        ):

        self.module = module
        self.calldata = calldata
        self.callvalue = callvalue
        self.caller = caller
        self.origin = origin
        self.address = address



class Node:

    def __init__(self, module_name, start_addr=0):
        self.module_name = module_name
        self.start_addr = start_addr
        self.instruction_list = []
        self.states = {}

    def __str__(self):
        return str(self.as_dict())
        
    def as_dict(self):

        code = ""

        for instruction in self.instruction_list:
            code += str(instruction['address']) + " " + instruction['opcode']
            if instruction['opcode'].startswith("PUSH"):
                code += " " + instruction['argument']

            code += "\\n"

        return {'module_name': self.module_name, 'code': code, 'start_addr': self.start_addr, 'instruction_list': self.instruction_list, 'states': self.states}


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

    def __init__(self, modules, max_depth=MAX_DEPTH, simplify_model=True, dynamic_loader=None):
        self.modules = modules
        self.nodes = {}
        self.addr_visited = []
        self.edges = []
        self.paths = {}
        self.function_state = {}
        self.trace = ""
        self.max_depth = max_depth
        self.simplify_model = simplify_model
        self.last_caller = ""
        self.total_states = 0
        self.active_node_prefix = ""
        self.dynamic_loader = dynamic_loader


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

        self.depth_first_search(self.active_node_prefix + ':0', node_to, [], paths, 0, nodes_visited)

        return paths


    def sym_exec(self, main_address):

        logging.debug("Starting SVM execution")

        self.active_node_prefix = self.modules[main_address]['name']
        context = Context(self.modules[main_address])
        self.nodes[self.active_node_prefix + ':0'] = self._sym_exec(context, State(), 0)

        logging.info("Execution complete, saved " + str(self.total_states) + " states")

        logging.debug("--- NODES ---")
        logging.debug(self.nodes)
        logging.debug("--- EDGES ---")

        for e in self.edges:
            logging.debug(str(e.as_dict()))

        logging.info(str(len(self.nodes)) + " nodes, " + str(len(self.edges)) + " edges")
        logging.info("Resolving paths")

        for key in self.nodes:

            paths = self.find_paths(key)

            logging.debug("Found " + str(len(paths)) + " paths to node " + str(key))

            self.paths[key] = paths


    def _sym_exec(self, context, state, depth):
    
        disassembly = context.module['disassembly']

        start_addr = disassembly.instruction_list[state.pc]['address']
        node = Node(context.module['name'], start_addr)

        logging.debug("- Entering block " + self.active_node_prefix + ", index = " + str(state.pc) + ", address = " + str(start_addr) + ", depth = " + str(depth))

        if start_addr == 0:
            self.function_state['current_func'] = "prologue"
            self.function_state['current_func_addr'] = start_addr

        if start_addr in disassembly.addr_to_func:
            # Start of a function

            function_name = disassembly.addr_to_func[start_addr]

            self.function_state['current_func'] = function_name

            logging.info("- Entering function " + function_name)

            node.instruction_list.append({'opcode': function_name, 'address': disassembly.instruction_list[state.pc]['address']})

            state.pc += 1

        halt = False

        instr = disassembly.instruction_list[state.pc]

        while not halt:

            instr = disassembly.instruction_list[state.pc]
            node.instruction_list.append(instr)
            node.states[disassembly.instruction_list[state.pc]['address']] = state
            self.total_states += 1

            op = instr['opcode']

            logging.debug("[" + context.module['name'] + "] " + utils.get_trace_line(instr, state))

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

            elif op == 'ADD':
                state.stack.append((utils.pop_bitvec(state) + utils.pop_bitvec(state)))

            elif op == 'SUB':
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

             # Call data`

            elif op == 'CALLVALUE':
                state.stack.append(context.callvalue)

            elif op == 'CALLDATALOAD':
                try:
                    offset = utils.get_concrete_int(state.stack.pop())
                    state.stack.append(context.calldata[offset])
                except AttributeError:
                    logging.debug("CALLDATALOAD: Unsupported symbolic index at " + str(disassembly.instruction_list[state.pc]['address']))
                    state.stack.append(BitVec("calldata_" + str(offset), 256))
                except IndexError:
                    logging.debug("Non-existent calldata offset, using symbolic variable instead")
                    state.stack.append(BitVec("calldata_" + str(offset), 256))
                                       
            elif op == 'CALLDATASIZE':

                calldatasize = len(context.calldata)

                if (calldatasize > 0):
                    state.stack.append(BitVecVal(calldatasize, 256))
                else:
                    state.stack.append(BitVec("calldatasize", 256))

            elif op == 'CALLDATACOPY':

                try:
                    mstart = utils.get_concrete_int(state.stack.pop())
                    dstart = utils.get_concrete_int(state.stack.pop())
                    size = utils.get_concrete_int(state.stack.pop())
                except:
                    # Calldata is symbolic. Do nothing
                    continue

                state.mem_extend(mstart, size)

                i_data = context.calldata[dstart]

                for i in range(mstart, mstart + size):
                    state.memory[i] = context.calldata[i_data]
                    i_data += 1

            # Control flow

            elif op == 'STOP':
                return node

            # Environment

            elif op == 'ADDRESS':
                state.stack.append(context.address)

            elif op == 'BALANCE':
                addr = state.stack.pop()
                state.stack.append(BitVec("balance_at_" + str(addr), 256))

            elif op == 'ORIGIN':
                state.stack.append(context.origin)

            elif op == 'CALLER':
                state.stack.append(context.caller)

            elif op == 'CODESIZE':
                state.stack.append(len(disassembly.instruction_list))

            if op == 'SHA3':
                s0, s1 = utils.pop_bitvec(state), utils.pop_bitvec(state)

                state.stack.append(BitVec("KECCAC_" + str(s0) + ")", 256))

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
                    offset = utils.get_concrete_int(offset)
                except AttributeError:
                    logging.debug("MLOAD from symbolic index. Not supported")
                    data = BitVec("mem_" + str(offset), 256)
                    continue

                try:   
                    data = state.memory[offset]
                except IndexError: # Memory slot not yet allocated
                    
                    data = BitVec("mem_" + str(offset), 25)
                    state.mem_extend(offset, 1)
                    state.memory[offset] = data

                logging.debug("Load from memory[" + str(offset) + "]: " + str(data))

                state.stack.append(data)

            elif op == 'MSTORE':

                try:
                    offset = utils.get_concrete_int(state.stack.pop())
                except AttributeError:
                    logging.debug("MSTORE to symbolic index. Not supported")
                    continue
                           
                value = state.stack.pop()
                state.mem_extend(offset, 1)

                logging.debug("Store to memory[" + str(offset) + "]: " + str(value))

                state.memory[offset] = value

            elif op == 'MSTORE8':
                offset, value = state.stack.pop(), state.stack.pop()

                mem_extend(offset, 1)

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
                    data = state.storage[index]
                except KeyError:
                    data = BitVec("storage_" + str(index), 256)
                    state.storage[index] = data

                state.stack.append(data)

            elif op == 'SSTORE':
                index, value = state.stack.pop(), state.stack.pop()

                logging.debug("Write to storage[" + str(index) + "] at node " + str(start_addr))

                if type(index) == BitVecRef:
                    # SSTORE to hash offset

                    k = sha3.keccak_512()
                    k.update(bytes(str(index), 'utf-8'))
                    index = k.hexdigest()[:8]

                    state.storage[index] = value
                else:
                    index = str(index)

                try:
                    state.storage[index]
                except KeyError:
                    state.storage[index] = BitVec("storage_" + str(index), 256)

            elif op == 'JUMP':

                try:
                    jump_addr = utils.get_concrete_int(state.stack.pop())
                except AttributeError:
                    logging.debug("Invalid jump argument (symbolic address) at " + str(disassembly.instruction_list[state.pc]['address']))
                    return node

                if (depth < self.max_depth):

                    logging.debug("JUMP to " + str(jump_addr))

                    i = utils.get_instruction_index(disassembly.instruction_list, jump_addr)

                    if disassembly.instruction_list[i]['opcode'] == "JUMPDEST":
                        logging.debug("Current nodes: " + str(self.nodes))

                        if jump_addr not in self.addr_visited:
                            self.addr_visited.append(jump_addr)
                            new_state = copy.deepcopy(state)
                            new_state.pc = i
                            new_node = self._sym_exec(context, new_state, depth + 1)
                            self.nodes[self.active_node_prefix + ':' + str(jump_addr)] = new_node

                        self.edges.append(Edge(self.active_node_prefix + ":" + str(node.start_addr), self.active_node_prefix + ":" + str(jump_addr), JumpType.UNCONDITIONAL))
                    else:
                        self.trace += "Skipping invalid jump destination"

                return node

            elif op == 'JUMPI':
                jump_addr = utils.get_concrete_int(state.stack.pop())
                condition = state.stack.pop()

                if (depth < self.max_depth):

                    i = utils.get_instruction_index(disassembly.instruction_list, jump_addr)

                    logging.debug("JUMPI to " + str(jump_addr))

                    if not i:
                        logging.debug("Invalid jump destination: " + str(jump_addr))
                    else:
                        instr = disassembly.instruction_list[i]

                        # Add new node for condition == True

                        if instr['opcode'] != "JUMPDEST":
                            logging.debug("Invalid jump destination: " + str(jump_addr))
                        else:

                            # Prune unreachable destinations (for CALLS with concrete function hash)

                            if str(simplify(condition)) != "False":

                                if jump_addr not in self.addr_visited:

                                    self.addr_visited.append(jump_addr)

                                    new_state = copy.deepcopy(state)

                                    new_state.pc = i

                                    new_node = self._sym_exec(context, new_state, depth + 1)
                                    self.nodes[self.active_node_prefix + ':' + str(jump_addr)] = new_node

                                logging.debug("Adding edge with condition: " + str(condition))

                                self.edges.append(Edge(self.active_node_prefix + ":" + str(node.start_addr), self.active_node_prefix + ":" + str(jump_addr), JumpType.CONDITIONAL, condition))

                        if not self.simplify_model:

                            new_state = copy.deepcopy(state)

                            new_node = self._sym_exec(context, new_state, depth)

                            start_addr = disassembly.instruction_list[state.pc]['address']
                            self.nodes[self.active_node_prefix + ':' + str(start_addr)] = new_node

                            if (type(condition) == BoolRef):
                                self.edges.append(Edge(self.active_node_prefix + ":" + str(node.start_addr), self.active_node_prefix + ":" + str(start_addr), JumpType.CONDITIONAL, Not(condition)))
                            else:
                                self.edges.append(Edge(self.active_node_prefix + ":" + str(node.start_addr), self.active_node_prefix + ":" + str(start_addr), JumpType.CONDITIONAL, condition == 0))                               

                            return node


            elif op == 'PC':
                state.stack.append(state.pc - 1)

            elif op == 'MSIZE':
                state.stack.append(BitVec("msize", 256))

            elif op == 'GAS':
                state.stack.append(10000000)

            elif op.startswith('LOG'):
                depth = int(op[3:])
                state.stack.pop(), state.stack.pop()
                [state.stack.pop() for x in range(depth)]
                # Not supported

            elif op == 'CREATE':
                state.stack.pop(), state.stack.pop(), state.stack.pop()
                # Not supported
                state.stack.append(0)

            elif op == 'CALL' or op == 'CALLCODE' or op == 'DELEGATECALL':
                gas, to, value, meminstart, meminsz, memoutstart, memoutsz = \
                state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop()

                logging.info(op + " to " + str(to))

                try:
                    callee_address = hex(utils.get_concrete_int(to))
                except AttributeError:
                    logging.info("Unable to get concrete call address.")
                    if self.dynamic_loader is not None:

                        logging.info("Contract not loaded, attempting to resolve dependency")
                        module =  self.dynamic_loader.dynld(context.module['address'], str(simplify(to)))

                        if module is None:

                            logging.info("No contract code returned, not a contract account?")
                            continue

                    else:
                        logging.info("Contract not loaded and dynamic loader unavailable. Skipping call")

                        ret = BitVec("retval_" + str(disassembly.instruction_list[state.pc]['address']), 256)
                        state.stack.append(ret)

                        continue


                callee_address = module['address']
                self.modules[callee_address] = module    
                logging.info(op + " to: " + callee_address)

                try:
                    callee_module = self.modules[callee_address]
                except KeyError:
                    logging.info("Contract " + str(callee_address) + " not loaded.")
                    logging.info((str(self.modules)))
                    
                    ret = BitVec("retval_" + str(disassembly.instruction_list[state.pc]['address']), 256)
                    state.stack.append(ret)

                    continue   

                calldata = state.memory[utils.get_concrete_int(meminstart):utils.get_concrete_int(meminstart+meminsz)]

                logging.info("calldata: " + str(calldata))

                self.last_caller = context.module['name'] + ":" + str(disassembly.instruction_list[state.pc]['address'])
                prefix_temp = self.active_node_prefix

                if (op == 'CALL'):
                    
                    self.active_node_prefix = callee_module['name'] + ':CALL_from_' + context.module['name'] + '_' + str(disassembly.instruction_list[state.pc]['address'] - 1)
                    callee_context = Context(callee_module, calldata = calldata, caller = context.address, origin = context.origin)

                    self.nodes[self.active_node_prefix + ':0'] = self._sym_exec(callee_context, State(), 0)

                elif (op == 'CALLCODE'):

                    self.active_node_prefix = callee_module['name'] + ':DELEGATECALL_from_' + context.module['name'] + '_' + str(disassembly.instruction_list[state.pc]['address'] - 1)

                    temp_code = context.code
                    temp_value = context.value
                    temp_caller = context.caller
                    context.code  = callee_module.code
                    context.value = value
                    context.caller = context.address

                    self.nodes[self.active_node_prefix + ':0'] = self._sym_exec(callee_context, State(), 0)

                    context.code = temp_code
                    context.value = temp_value
                    context.caller = temp_caller

                elif (op == 'DELEGATECALL'):

                    self.active_node_prefix = callee_module['name'] + ':CALL_from_' + context.module['name'] + '_' + str(disassembly.instruction_list[state.pc]['address'] - 1)

                    temp = context.code
                    context.code  = callee_module.code

                    self.nodes[self.active_node_prefix +':0'] = self._sym_exec(callee_context, State(), 0)

                    context.code = temp

                self.edges.append(Edge(prefix_temp + ":" + str(node.start_addr), self.active_node_prefix + ':0', JumpType.CALL))
                self.active_node_prefix = prefix_temp

                ret = BitVec("retval_" + str(disassembly.instruction_list[state.pc]['address']), 256)
                state.stack.append(ret)

                new_state = copy.deepcopy(state)

                memoutstart = utils.get_concrete_int(memoutstart)
                memoutsz = utils.get_concrete_int(memoutsz)

                new_state.mem_extend(memoutstart, memoutsz)
                # new_state.memory[memoutstart:memoutstart + memoutsz] = self.last_returned

                new_node = self._sym_exec(context, new_state, depth)

                start_addr = disassembly.instruction_list[state.pc]['address']
                self.nodes[self.active_node_prefix + ':' + str(start_addr)] = new_node

                return node

            elif op == 'RETURN':
                offset, length = state.stack.pop(), state.stack.pop()

                try:
                    self.last_returned = state.memory[utils.get_concrete_int(offset):utils.get_concrete_int(offset+length)]
                except AttributeError:
                    logging.debug("Return with symbolic length or offset. Not supported")

                if len(self.last_caller):
                    self.edges.append(Edge(self.active_node_prefix + ":" + str(node.start_addr), self.last_caller, JumpType.RETURN))

                return node

            elif op == 'SUICIDE':
                return node

            elif op == 'REVERT':
                return node

            elif op == 'INVALID':
                return node


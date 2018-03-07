from laser.ethereum import helper
from ethereum import utils, opcodes
from enum import Enum
from z3 import *
import re
import binascii
import copy
import logging


TT256 = 2 ** 256
TT256M1 = 2 ** 256 - 1
TT255 = 2 ** 255

gbl_next_uid = 0 # node counter

class CalldataType(Enum):
    CONCRETE = 1
    SYMBOLIC = 2

class JumpType(Enum):
    CONDITIONAL = 1
    UNCONDITIONAL = 2
    CALL = 3
    RETURN = 4

class SVMError(Exception):
    pass




'''
Classes to represent the global state, machine state and execution environment as described in the Ethereum yellow paper.
'''

class Account():

    def __init__(self, address, code = None, contract_name = "unknown", balance = BitVec("balance", 256)):
        self.nonce = 0
        self.code = code
        self.balance = balance
        self.storage = {}

        '''
        Metadata
        '''

        self.address = address
        self.contract_name = contract_name


class Environment():

    def __init__(
        self, 
        active_account,
        sender, 
        calldata, 
        gasprice, 
        callvalue, 
        origin, 
        calldata_type = CalldataType.SYMBOLIC,
        ):


        # Metadata

        self.active_account = active_account

        self.address = active_account.address
        self.code = active_account.code

        self.sender = sender
        self.calldata = calldata
        self.calldata_type = calldata_type
        self.gasprice = gasprice
        self.origin = origin
        self.callvalue = callvalue



class MachineState():

    def __init__(self, gas):
        self.pc = 0
        self.stack = []
        self.memory = []
        self.memsize = 0
        self.gas = gas

    def mem_extend(self, start, sz):

        if (start < 4096 and sz < 4096):

            if sz and start + sz > len(self.memory):

                n_append = start + sz - len(self.memory)

                while n_append > 0:
                    self.memory.append(0)
                    n_append -= 1

                memsize = sz

        else:
            raise Exception

                # Deduct gas for memory extension... not yet implemented


class GlobalState():

    def __init__(self, accounts, environment, machinestate = MachineState(gas = 10000000)):
        self.accounts = accounts
        self.environment = environment
        self.mstate = machinestate

    # Returns the instruction currently being executed.

    def get_current_instruction(self):
        instructions = self.environment.code.instruction_list

        return instructions[self.mstate.pc]



'''
The final analysis result is represented as a graph. Each node of the graph represents a basic block of code.
The states[] list contains the individual global state at each program counter position. There is one set of constraints on each node.
A list of edges between nodes with associated constraints is also saved. This is not strictly necessary for analysis, but is useful
for drawing a nice control flow graph.
'''

class Node:

    def __init__(self, contract_name, start_addr=0, constraints = []):
        self.contract_name = contract_name
        self.start_addr = start_addr
        self.states = []
        self.constraints = constraints
        self.function_name = "unknown"

        # Self-assign a unique ID

        global gbl_next_uid

        self.uid = gbl_next_uid
        gbl_next_uid += 1
        
    def get_cfg_dict(self):

        code = ""

        for state in self.states:

            instruction = state.get_current_instruction()

            code += str(instruction['address']) + " " + instruction['opcode']
            if instruction['opcode'].startswith("PUSH"):
                code += " " + instruction['argument']

            code += "\\n"

        return {'contract_name': self.contract_name, 'start_addr': self.start_addr, 'function_name': self.function_name, 'code': code}


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


'''
Main symbolic execution engine.
'''

class LaserEVM:

    def __init__(self, accounts, dynamic_loader=None, max_depth=12):
        self.accounts = accounts
        self.nodes = {}
        self.addr_visited = {}
        self.edges = []
        self.current_func = ""
        self.current_func_addr = 0
        self.last_call_address = None
        self.last_jump_targets = []
        self.pending_returns = {}
        self.total_states = 0
        self.active_node_prefix = ""
        self.dynamic_loader = dynamic_loader
        self.max_depth = max_depth

        logging.info("LASER EVM initialized with dynamic loader: " + str(dynamic_loader))


    def copy_global_state(self, gblState):
        mstate = copy.deepcopy(gblState.mstate)
        environment = copy.copy(gblState.environment)

        return GlobalState(self.accounts, environment, mstate)


    def can_jump(self, jump_addr):

        # Loop detection

        if jump_addr in self.last_jump_targets:
            return False

        self.last_jump_targets.append(jump_addr)

        if len(self.last_jump_targets) > 4:
            self.last_jump_targets.pop(0)

        return True


    def sym_exec(self, main_address):

        logging.debug("Starting LASER execution")

        for account in self.accounts:
            self.addr_visited[account] = []

        # Initialize the execution environment

        environment = Environment(
            self.accounts[main_address],
            BitVec("caller", 256),
            [],
            BitVec("gasprice", 256),
            BitVec("callvalue", 256),
            BitVec("origin", 256),
            calldata_type = CalldataType.SYMBOLIC,
        )

        gblState = GlobalState(self.accounts, environment)

        node = self._sym_exec(gblState)
        self.nodes[node.uid] = node
        logging.info("Execution complete")
        logging.info(str(len(self.nodes)) + " nodes, " + str(len(self.edges)) + " edges, " + str(self.total_states) + " total states")


    def _sym_exec(self, gblState, depth=0, constraints=[]):
    
        environment = gblState.environment
        disassembly = environment.code
        state = gblState.mstate
        depth = depth

        start_addr = disassembly.instruction_list[state.pc]['address']

        if start_addr == 0:
            self.current_func = "fallback"
            self.current_func_addr = start_addr

        node = Node(environment.active_account.contract_name, start_addr, constraints)

        logging.debug("- Entering node " + str(node.uid) + ", index = " + str(state.pc) + ", address = " + str(start_addr) + ", depth = " + str(depth))

        if start_addr in disassembly.addr_to_func:
            # Enter a new function

            function_name = disassembly.addr_to_func[start_addr]
            self.current_func = function_name

            logging.info("- Entering function " + environment.active_account.contract_name + ":" + function_name)

            state.pc += 1

        node.function_name = self.current_func

        halt = False

        while not halt:

            try:
                instr = disassembly.instruction_list[state.pc]
            except IndexError:
                logging.debug("Invalid PC")
                return node

            # Save state

            node.states.append(gblState)
            gblState = self.copy_global_state(gblState)

            state = gblState.mstate

            self.total_states += 1
            state.pc += 1

            op = instr['opcode']

            # logging.debug("[" + environment.active_account.contract_name + "] " + helper.get_trace_line(instr, state))
            # slows down execution significantly.

            # stack ops

            if op.startswith("PUSH"):
                value = BitVecVal(int(instr['argument'][2:], 16), 256)
                state.stack.append(value)

            elif op.startswith('DUP'):
                dpth = int(op[3:])

                try:
                    state.stack.append(state.stack[-dpth])
                except:
                    halt = True
                    continue

            elif op.startswith('SWAP'):

                dpth = int(op[4:])

                try:
                    temp = state.stack[-dpth-1]
                except IndexError: # Stack underflow
                    halt = True
                    continue

                state.stack[-dpth-1] = state.stack[-1]
                state.stack[-1] = temp

            elif op == 'POP':
                try:
                    state.stack.pop()
                except IndexError: # Stack underflow
                    halt = True
                    continue

            # Bitwise ops

            elif op == 'AND':
                try:
                    op1, op2 = state.stack.pop(), state.stack.pop()
                except IndexError: # Stack underflow
                    halt = True
                    continue

                if (type(op1) == BoolRef):
                    op1 = If(op1, BitVecVal(1,256), BitVecVal(0,256))

                if (type(op2) == BoolRef):
                    op2 = If(op2, BitVecVal(1,256), BitVecVal(0,256))

                state.stack.append(op1 & op2)

            elif op == 'OR':
                try:
                    op1, op2 = state.stack.pop(), state.stack.pop()
                except IndexError: # Stack underflow
                    halt = True
                    continue

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

                state.stack.append(BitVecVal(0, 256))

            # Arithmetics

            elif op == 'ADD':
                state.stack.append((helper.pop_bitvec(state) + helper.pop_bitvec(state)))

            elif op == 'SUB':
                state.stack.append((helper.pop_bitvec(state) - helper.pop_bitvec(state)))

            elif op == 'MUL':
                state.stack.append(helper.pop_bitvec(state) * helper.pop_bitvec(state))

            elif op == 'DIV':
                s0, s1 = helper.pop_bitvec(state), helper.pop_bitvec(state)

                state.stack.append(UDiv(s0, s1))

            elif op == 'MOD':
                s0, s1 = helper.pop_bitvec(state), helper.pop_bitvec(state)
                state.stack.append(0 if s1 == 0 else URem(s0, s1))

            elif op == 'SDIV':
                s0, s1 = helper.pop_bitvec(state), helper.pop_bitvec(state)
                state.stack.append(s0 / s1)

            elif op == 'SMOD':
                s0, s1 = helper.pop_bitvec(state), helper.pop_bitvec(state)
                state.stack.append(0 if s1 == 0 else s0 % s1)

            elif op == 'ADDMOD':
                s0, s1, s2 = helper.pop_bitvec(state), helper.pop_bitvec(state), helper.pop_bitvec(state)
                state.stack.append((s0 + s1) % s2 if s2 else 0)

            elif op == 'MULMOD':
                s0, s1, s2 = helper.pop_bitvec(state), helper.pop_bitvec(state), helper.pop_bitvec(state)
                state.stack.append((s0 * s1) % s2 if s2 else 0)

            elif op == 'EXP':
                # we only implement 2 ** x
                base, exponent = state.stack.pop(), state.stack.pop()

                if (type(base) != BitVecNumRef):
                    state.stack.append(BitVec(str(base) + "_EXP_" + str(exponent), 256))
                elif (base.as_long() == 2):
                    if exponent == 0:
                        state.stack.append(BitVecVal(1, 256))
                    else:
                        state.stack.append(base << (exponent - 1))

                else:
                    state.stack.append(base)

            elif op == 'SIGNEXTEND':
                s0, s1 = state.stack.pop(), state.stack.pop()

                try:
                    s0 = get_concrete_int(s0)
                    s1 = get_concrete_int(s1)
                except:
                    halt = True
                    continue

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

                exp = ULT(helper.pop_bitvec(state), helper.pop_bitvec(state))
                state.stack.append(exp)

            elif op == 'GT':

                exp = UGT(helper.pop_bitvec(state), helper.pop_bitvec(state))
                state.stack.append(exp)

            elif op == 'SLT':

                exp = helper.pop_bitvec(state) < helper.pop_bitvec(state)
                state.stack.append(exp)

            elif op == 'SGT':

                exp = helper.pop_bitvec(state) > helper.pop_bitvec(state)
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
                state.stack.append(environment.callvalue)

            elif op == 'CALLDATALOAD':
                # unpack 32 bytes from calldata into a word and put it on the stack
                
                op0 = state.stack.pop()

                try:
                    offset = helper.get_concrete_int(simplify(op0))
                except AttributeError:
                    logging.debug("CALLDATALOAD: Unsupported symbolic index")
                    state.stack.append(BitVec("calldata_" + str(environment.active_account.contract_name) + "_" + str(op0), 256))
                    continue

                try:
                    b = environment.calldata[offset]
                except IndexError:
                    logging.debug("Calldata not set, using symbolic variable instead")
                    state.stack.append(BitVec("calldata_" + str(environment.active_account.contract_name) + "_" + str(op0), 256))
                    continue

                if type(b) == int:
                    # 32 byte concrete value

                    val = b''

                    try:
                        for i in range(offset, offset + 32):
                            val += environment.calldata[i].to_bytes(1, byteorder='big')

                        state.stack.append(BitVecVal(int.from_bytes(val, byteorder='big'), 256))

                    except:
                        state.stack.append(b) 
                else:
                    # symbolic variable
                    state.stack.append(b)
                                       
            elif op == 'CALLDATASIZE':

                if environment.calldata_type == CalldataType.SYMBOLIC:
                    state.stack.append(BitVec("calldatasize_" + environment.active_account.contract_name, 256))
                else:
                    state.stack.append(BitVecVal(len(environment.calldata), 256))

            elif op == 'CALLDATACOPY':
                op0, op1, op2 = state.stack.pop(), state.stack.pop(), state.stack.pop()

                try:
                    mstart = helper.get_concrete_int(op0)
                except:
                    logging.debug("Unsupported symbolic memory offset in CALLDATACOPY")
                    continue

                try:
                    dstart = helper.get_concrete_int(op1)
                except:
                    logging.debug("Unsupported symbolic calldata offset in CALLDATACOPY")
                    state.mem_extend(mstart, 1)
                    state.memory[mstart] = BitVec("calldata_" + str(environment.active_account.contract_name) + "_cpy", 256)
                    continue

                try:
                    size = helper.get_concrete_int(op2)
                except:
                    logging.debug("Unsupported symbolic size in CALLDATACOPY")
                    state.mem_extend(mstart, 1)
                    state.memory[mstart] = BitVec("calldata_" + str(environment.active_account.contract_name) + "_" + str(dstart), 256)
                    continue

                if size > 0:

                    try:
                        state.mem_extend(mstart, size)
                    except:
                        logging.debug("Memory allocation error: mstart = " + str(mstart) + ", size = " + str(size))
                        state.mem_extend(mstart, 1)
                        state.memory[mstart] = BitVec("calldata_" + str(environment.active_account.contract_name) + "_" + str(dstart), 256)
                        continue

                    try:
                        i_data = environment.calldata[dstart]

                        for i in range(mstart, mstart + size):
                            state.memory[i] = environment.calldata[i_data]
                            i_data += 1
                    except:
                        logging.debug("Exception copying calldata to memory")

                        state.memory[mstart] = BitVec("calldata_" + str(environment.active_account.contract_name) + "_" + str(dstart), 256)

                        # continue

            # Control flow

            elif op == 'STOP':
                if self.last_call_address is not None:
                    self.pending_returns[self.last_call_address].append(node.uid)

                halt = True
                continue

            # Environment

            elif op == 'ADDRESS':
                state.stack.append(environment.sender)

            elif op == 'BALANCE':
                addr = state.stack.pop()
                state.stack.append(BitVec("balance_at_" + str(addr), 256))

            elif op == 'ORIGIN':
                state.stack.append(environment.origin)

            elif op == 'CALLER':
                state.stack.append(environment.sender)

            elif op == 'CODESIZE':
                state.stack.append(len(disassembly.instruction_list))

            if op == 'SHA3':
                op0, op1 = state.stack.pop(), state.stack.pop()

                try:
                    index, length = helper.get_concrete_int(op0), helper.get_concrete_int(op1)

                except:
                    # Can't access symbolic memory offsets
                    state.stack.append(BitVec("KECCAC_mem_" + str(op0) + ")", 256))
                    continue

                try:
                    data = b''

                    for i in range(index, index + length):
                        data += helper.get_concrete_int(state.memory[i]).to_bytes(1, byteorder='big')
                        i += 1 
                
                except:

                    svar = str(state.memory[index])

                    svar = svar.replace(" ", "_")
 
                    state.stack.append(BitVec("keccac_" + svar, 256))
                    continue
                

                logging.debug("SHA3 Data: " + str(data))

                keccac = utils.sha3(utils.bytearray_to_bytestr(data))

                logging.debug("SHA3 Hash: " + str(binascii.hexlify(keccac)))

                state.stack.append(BitVecVal(helper.concrete_int_from_bytes(keccac, 0), 256))

            elif op == 'GASPRICE':
                state.stack.append(BitVecVal(1, 256))

            elif op == 'CODECOPY':
                # Not implemented
                start, s1, size = state.stack.pop(), state.stack.pop(), state.stack.pop()

            elif op == 'EXTCODESIZE':
                addr = state.stack.pop()
                state.stack.append(BitVec("extcodesize", 256))

            elif op == 'EXTCODECOPY':
                # Not implemented

                addr = state.stack.pop()
                start, s2, size = state.stack.pop(), state.stack.pop(), state.stack.pop()

            elif op == 'BLOCKHASH':
                blocknumber = state.stack.pop()
                state.stack.append(BitVec("blockhash_block_" + str(blocknumber), 256))

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
                
                op0 = state.stack.pop()

                logging.debug("MLOAD[" + str(op0) + "]")

                try:
                    offset = helper.get_concrete_int(op0)
                except AttributeError:
                    logging.debug("Can't MLOAD from symbolic index")
                    data = BitVec("mem_" + str(op0), 256)
                    continue

                try:   
                    data = helper.concrete_int_from_bytes(state.memory, offset)
                except IndexError: # Memory slot not allocated
                    data = BitVec("mem_" + str(offset), 256)
                except TypeError: # Symbolic memory
                    data = state.memory[offset]

                logging.debug("Load from memory[" + str(offset) + "]: " + str(data))

                state.stack.append(data)

            elif op == 'MSTORE':

                op0, value = state.stack.pop(), state.stack.pop()

                try:
                    mstart = helper.get_concrete_int(op0)
                except AttributeError:
                    logging.debug("MSTORE to symbolic index. Not supported")
                    continue

                try:
                    state.mem_extend(mstart, 32)
                except Exception:
                    logging.debug("Error extending memory, mstart = " + str(mstart) + ", size = 32")

                logging.debug("MSTORE to mem[" + str(mstart) + "]: " + str(value))

                try:
                    # Attempt to concretize value
                    _bytes = helper.concrete_int_to_bytes(value)

                    i = 0

                    for b in _bytes:
                        state.memory[mstart + i] = _bytes[i]
                        i += 1

                except:
                    try:
                        state.memory[mstart] = value
                    except:
                        logging.debug("Invalid memory access")
                        continue

                # logging.debug("MEM: " + str(state.memory))


            elif op == 'MSTORE8':
                # Is this ever used?
                op0, value = state.stack.pop(), state.stack.pop()

                try:
                    offset = helper.get_concrete_int(op0)
                except AttributeError:
                    logging.debug("MSTORE to symbolic index. Not supported")
                    continue

                state.mem_extend(offset, 1)

                state.memory[offset] = value % 256

            elif op == 'SLOAD':
                index = state.stack.pop()
                logging.debug("Storage access at index " + str(index))

                if type(index) == BitVecRef:
                    # SLOAD from hash offset

                    # k = sha3.keccak_512()
                    # k.update(bytes(str(index), 'utf-8'))
                    # index = k.hexdigest()[:8]

                    index = str(index)

                try:
                    data = gblState.accounts[gblState.environment.sender].storage[index]
                except KeyError:
                    data = BitVec("storage_" + str(index), 256)
                    gblState.environment.active_account.storage[index] = data

                state.stack.append(data)

            elif op == 'SSTORE':
                index, value = state.stack.pop(), state.stack.pop()

                logging.debug("Write to storage[" + str(index) + "] at node " + str(start_addr))

                if type(index) == BitVecRef:
                    index = str(index)

                try:
                    gblState.environment.active_account.storage[index] = value
                except KeyError:
                    logging.debug("Error writing to storage: Invalid index")
                    continue

            elif op == 'JUMP':

                try:
                    jump_addr = helper.get_concrete_int(state.stack.pop())
                except AttributeError:
                    logging.debug("Invalid jump argument (symbolic address)")
                    halt = True
                    continue
                except IndexError: # Stack Underflow
                    halt = True
                    continue

                if (depth < self.max_depth):

                    i = helper.get_instruction_index(disassembly.instruction_list, jump_addr)

                    if i is None:
                        logging.debug("JUMP to invalid address")
                        halt = True
                        continue

                    opcode = disassembly.instruction_list[i]['opcode']

                    if opcode == "JUMPDEST":

                        if (self.can_jump(jump_addr)):

                            new_gblState = self.copy_global_state(gblState)
                            new_gblState.mstate.pc = i

                            new_node = self._sym_exec(new_gblState, depth=depth+1, constraints=constraints)
                            self.nodes[new_node.uid] = new_node

                            self.edges.append(Edge(node.uid, new_node.uid, JumpType.UNCONDITIONAL))
                            halt = True
                            continue
                        else:
                            logging.debug("JUMP target limit reached")
                            halt = True
                            continue
                    else:
                        logging.debug("Skipping JUMP to invalid destination (not JUMPDEST): " + str(jump_addr))
                        halt = True
                        continue
                else:
                    logging.debug("Max depth reached, skipping JUMP")
                    halt = True
                    continue                    

            elif op == 'JUMPI':
                op0, condition = state.stack.pop(), state.stack.pop()

                try:
                    jump_addr = helper.get_concrete_int(op0)
                except:
                    logging.debug("Skipping JUMPI to invalid destination.")

                logging.debug("JUMP to: " + str(jump_addr))

                if (depth < self.max_depth):

                    i = helper.get_instruction_index(disassembly.instruction_list, jump_addr)

                    if not i:
                        logging.debug("Invalid jump destination: " + str(jump_addr))

                    else:
                        instr = disassembly.instruction_list[i]

                        # Add new node for condition == True

                        if instr['opcode'] != "JUMPDEST":
                            logging.debug("Invalid jump destination: " + str(jump_addr))

                        else:

                            if (type(condition) == bool):
                                logging.debug("BOOL CONDITION TYPE")
                                # continue

                            elif (type(condition) == BoolRef):

                                if (self.can_jump(jump_addr)):

                                    new_gblState = self.copy_global_state(gblState)
                                    new_gblState.mstate.pc = i

                                    new_constraints = copy.deepcopy(constraints)
                                    new_constraints.append(condition)

                                    new_node = self._sym_exec(new_gblState, depth=depth+1, constraints=new_constraints)
                                    self.nodes[new_node.uid] = new_node

                                    self.edges.append(Edge(node.uid, new_node.uid, JumpType.CONDITIONAL, condition))

                                else:
                                    logging.debug("JUMP target limit reached (JUMPI)")

                            else:
                                logging.debug("Invalid condition: " + str(condition) + "(type " + str(type(condition)) + ")")
                                halt = True
                                continue 

                        node.states.append(gblState)
                        new_gblState = copy.deepcopy(gblState)

                        if (type(condition) == BoolRef):
                            negated = Not(condition)
                        else:
                            negated = condition == 0

                        new_constraints = copy.deepcopy(constraints)
                        new_constraints.append(negated)

                        new_node = self._sym_exec(new_gblState, depth=depth, constraints=new_constraints)
                        self.nodes[new_node.uid] = new_node

                        self.edges.append(Edge(node.uid, new_node.uid, JumpType.CONDITIONAL, negated))

                        halt = True
                        continue

                else:
                    logging.debug("Max depth reached, skipping JUMPI")


            elif op == 'PC':
                state.stack.append(state.pc - 1)

            elif op == 'MSIZE':
                state.stack.append(BitVec("msize", 256))

            elif op == 'GAS':
                state.stack.append(10000000)

            elif op.startswith('LOG'):
                dpth = int(op[3:])
                state.stack.pop(), state.stack.pop()
                [state.stack.pop() for x in range(dpth)]
                # Not supported

            elif op == 'CREATE':
                state.stack.pop(), state.stack.pop(), state.stack.pop()
                # Not supported
                state.stack.append(0)

            elif op in ('CALL', 'CALLCODE', 'DELEGATECALL', 'STATICCALL'):

                if op in ('CALL', 'CALLCODE'):
                    gas, to, value, meminstart, meminsz, memoutstart, memoutsz = \
                        state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop()

                else:
                    gas, to, meminstart, meminsz, memoutstart, memoutsz = \
                        state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop()

                try:
                    callee_address = hex(helper.get_concrete_int(to))

                except AttributeError:
                    # Not a concrete call address. Call target may be an address in storage.

                    m = re.search(r'storage_(\d+)', str(simplify(to)))

                    logging.debug("CALL to: " + str(simplify(to)))

                    if (m and self.dynamic_loader is not None):
                        idx = int(m.group(1))
                        logging.info("Dynamic contract address at storage index " + str(idx))

                        # attempt to read the contract address from instance storage 

                        callee_address = self.dynamic_loader.read_storage(environment.active_account.address, idx)

                        # testrpc simply returns the address, geth response is more elaborate.

                        if not re.match(r"^0x[0-9a-f]{40}$", callee_address):

                            callee_address = "0x" + callee_address[26:]

                    else:
                        logging.info("Unable to resolve address from storage.")
                        ret = BitVec("retval_" + str(disassembly.instruction_list[state.pc]['address']), 256)
                        state.stack.append(ret)
                        continue

                if not re.match(r"^0x[0-9a-f]{40}", callee_address):
                        logging.debug("Invalid address: " + str(callee_address))
                        ret = BitVec("retval_" + str(disassembly.instruction_list[state.pc]['address']), 256)
                        state.stack.append(ret)

                        continue

                if (int(callee_address, 16) < 5):

                    logging.info("Native contract called: " + callee_address)

                    # Todo: Implement native contracts

                    ret = BitVec("retval_" + str(disassembly.instruction_list[state.pc]['address']), 256)
                    state.stack.append(ret)
                    continue

                try:

                    module = self.accounts[callee_address]

                except KeyError:
                    # We have a valid call address, but contract is not in the modules list

                    logging.info("Module with address " + callee_address + " not loaded.")

                    if self.dynamic_loader is not None:

                        logging.info("Attempting to load dependency")

                        code = self.dynamic_loader.dynld(environment.active_account.address, callee_address)

                        if code is None:

                            logging.info("No code returned, not a contract account?")
                            ret = BitVec("retval_" + str(disassembly.instruction_list[state.pc]['address']), 256)
                            state.stack.append(ret)
                            continue

                        # New contract bytecode loaded successfully, create a new contract account

                        self.accounts[callee_address] = Account(callee_address, code, callee_address)
                        self.addr_visited[callee_address] = []

                        logging.info("Dependency loaded: " + callee_address)

                    else:
                         logging.info("Dynamic loader unavailable. Skipping call")
                         ret = BitVec("retval_" + str(disassembly.instruction_list[state.pc]['address']), 256)
                         state.stack.append(ret)
                         continue

                logging.info("Executing " + op + " to: " + callee_address)

                try:
                    callee_account = self.accounts[callee_address]
                except KeyError:
                    logging.info("Contract " + str(callee_address) + " not loaded.")
                    logging.info((str(self.accounts)))
                    
                    ret = BitVec("retval_" + str(disassembly.instruction_list[state.pc]['address']), 256)
                    state.stack.append(ret)

                    continue

                # Attempt to write concrete calldata

                try:
                    calldata = state.memory[helper.get_concrete_int(meminstart):helper.get_concrete_int(meminstart+meminsz)]
                    calldata_type = CalldataType.CONCRETE
                    logging.debug("calldata: " + str(calldata))

                except AttributeError:

                    logging.info("Unsupported symbolic calldata offset")
                    calldata_type = CalldataType.SYMBOLIC
                    calldata = []

                self.last_call_address = disassembly.instruction_list[state.pc]['address']
                self.pending_returns[self.last_call_address] = []

                if (op == 'CALL'):

                    callee_environment = Environment(callee_account, environment.active_account.address, calldata, environment.gasprice, value, environment.origin, calldata_type = calldata_type)
                    new_gblState = GlobalState(gblState.accounts, callee_environment, MachineState(gas))

                    new_node = self._sym_exec(new_gblState, depth=depth+1, constraints=constraints)

                    self.nodes[new_node.uid] = new_node

                elif (op == 'CALLCODE'):

                    callee_environment = Environment(callee_account, environment.active_account.address, calldata, environment.gasprice, value, environment.origin, calldata_type = calldata_type)
                    new_gblState = GlobalState(gblState.accounts, callee_environment, MachineState(gas))

                    temp_module = environment.module
                    temp_callvalue = environment.callvalue
                    temp_caller = environment.caller
                    temp_calldata = environment.calldata

                    environment.code = callee_account.code
                    environment.callvalue = value
                    environment.caller = environment.address
                    environment.calldata = calldata

                    new_node = self._sym_exec(environment, MachineState(gas), depth=depth+1, constraints=constraints)
                    self.nodes[new_node.uid] = new_node

                    environment.module = temp_module
                    environment.callvalue = temp_callvalue
                    environment.caller = temp_caller
                    environment.calldata = temp_calldata

                elif (op == 'DELEGATECALL'):

                    temp_code = environment.code
                    temp_calldata = environment.calldata

                    environment.code = callee_account.code
                    environment.calldata = calldata

                    new_node = self._sym_exec(environment, MachineState(gas), depth=depth + 1, constraints=constraints)
                    self.nodes[new_node.uid] = new_node

                    environment.code = temp_code
                    environment.calldata = temp_calldata

                self.edges.append(Edge(node.uid, new_node.uid, JumpType.CALL))

                ret = BitVec("retval_" + str(disassembly.instruction_list[state.pc]['address']), 256)
                state.stack.append(ret)

                new_gblState = copy.deepcopy(gblState)
                new_node = self._sym_exec(gblState, depth=depth+1, constraints=constraints)

                self.nodes[new_node.uid] = new_node

                for ret_uid in self.pending_returns[self.last_call_address]:
                    self.edges.append(Edge(ret_uid, new_node.uid, JumpType.RETURN))

                state.stack.append(BitVec("retval", 256))

                continue 

            elif op == 'RETURN':
                offset, length = state.stack.pop(), state.stack.pop()

                try:
                    self.last_returned = state.memory[helper.get_concrete_int(offset):helper.get_concrete_int(offset+length)]
                except AttributeError:
                    logging.debug("Return with symbolic length or offset. Not supported")

                if self.last_call_address is not None:
                    self.pending_returns[self.last_call_address].append(node.uid)              

                halt = True
                continue                

            elif op == 'SUICIDE':
                halt = True
                continue                

            elif op == 'REVERT':
                if self.last_call_address is not None:
                    self.pending_returns[self.last_call_address].append(node.uid)

                halt = True
                continue 

            elif op == 'INVALID':
                halt = True
                continue 

        logging.debug("Returning from node " + str(node.uid))
        return node

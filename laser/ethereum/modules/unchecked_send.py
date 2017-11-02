from z3 import *
import logging

def execute(svm):

    for k in svm.nodes:
        node = svm.nodes[k]

        for instruction in node.instruction_list:

            if(instruction['opcode'] == "CALL"):

                state = node.states[instruction['address']]
                
                gas, to, value, meminstart, meminsz, memoutstart, memoutsz = \
                        state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop(), state.stack.pop()


                print("CALL to: " + str(to), " VALUE: " + str(value))

                s = Solver()

                for constraint in node.constraints:
                    s.add(constraint)

                if (s.check() == sat):
                    print("MODEL:")
                    print(s.model())

                else:
                    print("unsat")
from z3 import *

def execute(svm):

    for k in svm.nodes:
        node = svm.nodes[k]

        for instruction in node.instruction_list:

            if(instruction['opcode'] == "SUICIDE"):
                state = node.states[instruction['address']]
                to = state.stack.pop()

                print("SUICIDE to: " + str(to))
                print("FUNCTION: " + str(node.function_name))

                # print("CONSTRAINTS:")
                # print(str(node.constraints))

                s = Solver()

                for constraint in node.constraints:
                    s.add(constraint)

                if (s.check() == sat):
                    print("MODEL:")
                    print(s.model())

                else:
                    print("unsat")
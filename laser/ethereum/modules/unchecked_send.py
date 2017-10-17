from z3 import *
import logging
import re


def solve_path(svm, path, caller = None, owner = None, owner_storage_index = 1):

    s = Solver() 

    if(caller is not None):
        s.add(svm.env['caller'] == caller)
    if(owner is not None):
        s.add(svm.storage[owner_storage_index] == owner)

    for edge in path:
        s.add(condition)

    if (s.check() == sat):

        return s.model()

    else:
        return None
        

def execute(svm):

    for node_addr in svm.send_eth_nodes:

        logging.debug("Checking node at " + str(node_addr))

        for path in svm.paths[node_addr]:

            for edge in path:

                if (edge.condition is not None):

                    cond = str(edge.condition)

                    if re.search(r'caller', cond):
                        m = re.search(r'storage_(\d+)', cond)

                        if (m):
                            owner_index = int(m.group(1))

                            logging.debug("Constraint on msg.sender: caller == storage_" + str(owner_index))
                            logging.debug("Checking for writes to storage_" + (str(owner_index)))

                            try:

                                for _node_addr in svm.sstor_node_lists[owner_index]:

                                    logging.debug("Checking node " + str(_node_addr))

                                    for _path in svm.paths[_node_addr]:

                                        # Try to solve for caller != owner

                                        m = solve_path(svm, _path, caller=0x1234, owner=0x2345, owner_index=owner_index)

                                        if m is not None:
                                            print("Owner overwrite at node " + str(_node_addr))
                                            for d in m.decls():
                                                print("%s = %s" % (d.name(), hex(m[d].as_long())))
                                        else:
                                            print("Unable to satisfy constraints")       

                            except KeyError:
                                logging.debug("No writes found")

                        else:
                            logging.debug("Potential unchecked transfer, verifying...")

                            m = solve_path(svm, path, caller=0x1234, owner=0x2345, owner_index=owner_index)
                            
                            if m is not None:
                                print("Unchecked transfer at " + str(_node_addr))
                                for d in m.decls():
                                    print("%s = %s" % (d.name(), hex(m[d].as_long())))
                            else:
                                print("Unable to satisfy constraints")                   

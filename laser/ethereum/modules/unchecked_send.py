from z3 import *
import logging
import re


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
        

def execute(svm):

    for node_addr in svm.send_eth_nodes:

        logging.info("Checking node at " + str(node_addr))

        for path in svm.paths[node_addr]:

            path_checked = False

            for edge in path:

                if (edge.condition is not None):

                    cond = str(edge.condition)

                    if 'caller' in cond and 'storage_' in cond:
                        m = re.search(r'storage_(\d+)', cond)

                        if (m):
                            owner_index = int(m.group(1))
                            path_checked = True

                            logging.debug("Constraint on msg.sender: caller == storage_" + str(owner_index))
                            logging.debug("Checking for writes to storage_" + (str(owner_index)))

                            try:

                                for _node_addr in svm.sstor_node_lists[owner_index]:

                                    logging.debug("Checking node " + str(_node_addr))

                                    for _path in svm.paths[_node_addr]:

                                        # Try to solve for caller != owner

                                        m = solve_path(svm, _path, caller=0x1234, owner=0x2345, owner_storage_index=owner_index)

                                        if m is not None:
                                            print("### Owner overwrite at node " + str(_node_addr) + " ###")
                                            print("Input data:")
                                            for d in m.decls():
                                                print("%s = %s" % (d.name(), hex(m[d].as_long())))
                                            print("Ether sent at node: " + str(node_addr))

                                            m = solve_path(svm, svm.paths[node_addr][0])

                                            print("Send Ether input data:")

                                            for d in m.decls():
                                                print("%s = %s" % (d.name(), hex(m[d].as_long())))

                                        else:
                                            print("Unable to satisfy constraints")     

                                        break  

                            except KeyError:
                                logging.debug("No writes found")

            if not path_checked:

                logging.info("Potential unchecked transfer, verifying...")

                m = solve_path(svm, path)
                
                if m is not None:
                    print("### Unchecked transfer detected! ###")
                    for d in m.decls():
                        print("%s = %s" % (d.name(), hex(m[d].as_long())))
                else:
                    print("Unable to satisfy constraints")                   

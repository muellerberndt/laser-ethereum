from z3 import *
import logging
import re

def execute(svm):

    for node_addr in svm.send_eth_nodes:

        logging.debug("Checking node at " + str(node_addr) )

        for paths in svm.paths[node_addr]:

            s = Solver()

            for edge in paths:

                if (edge.condition is not None):

                    cond = str(edge.condition)

                    if re.search(r'caller', cond):
                        m = re.search(r'storage_(\d+)', cond)

                        if (m):
                            i = int(m.group(1))

                            logging.debug("Constraint on msg.sender: caller == storage_" + str(i))

                            logging.debug("Checking for writes to storage_" + (str(i)))

                            try:
                                writes = svm.storage_writes[i]

                                for w in writes:

                                    logging.debug("Checking node " + str(w))

                                    ps = svm.paths[w]

                                    for p in ps:

                                        s = Solver()

                                        for e in p:

                                            s.add(edge.condition)

                                        s.add(svm.env['caller'] == 0x111111)
                                        s.add(svm.storage[i] == 0x222222)

                                        # print(str(svm.storage))
                                        # print(str(i))
                                        
                                        if (s.check() == sat):

                                            m = s.model()

                                            print("Owner overwrite detected!")

                                            for d in m.decls():
                                                print("%s = %s" % (d.name(), hex(m[d].as_long())))

                                        else:
                                            logging.info("unsat")

                            except KeyError:
                                logging.info("No writes found")




                    s.add(edge.condition)



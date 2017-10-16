from z3 import *
import logging

def execute(svm):

    for node_addr in svm.send_eth_nodes:

        logging.info("Checking node at " + str(node_addr) )

        for paths in svm.paths[node_addr]:

            logging.info("Path " + str(paths) )

            s = Solver()

            for edge in paths:

                if (edge.condition is not None):

                    s.add(edge.condition)
                    try:
                        print(simplify(edge.condition))
                    except:
                        print(edge.condition)

            s.add(svm.env['caller'] == 0x1234567890)

            if (s.check() == sat):

                m = s.model()

                for d in m.decls():
                    print("%s = %s" % (d.name(), hex(m[d].as_long())))

            else:

                logging.info("unsat")
from . import svm
from .modules import unchecked_send
import logging

def fire(disassembly):

    _svm = svm.SVM(disassembly,  branch_at_jumpi = True)

    logging.info("Firing lasers!")

    _svm.sym_exec()

    return unchecked_send.execute(_svm)

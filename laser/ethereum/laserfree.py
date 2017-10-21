from . import svm
from .modules import unchecked_send, unchecked_suicide
import logging

def fire(disassembly):

    _svm = svm.SVM(disassembly,  branch_at_jumpi = True)

    logging.info("Firing lasers!")

    _svm.sym_exec()

    unchecked_send.execute(_svm)
    unchecked_suicide.execute(_svm)

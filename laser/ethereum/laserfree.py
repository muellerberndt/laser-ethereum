from . import svm,utils
from .modules import unchecked_send

def fire(disassembly):
    _svm = svm.SVM(disassembly,  branch_at_jumpi = True)
    _svm.sym_exec()

    return unchecked_send.execute(_svm)

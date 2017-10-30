from . import svm
from .modules import unchecked_send
import logging

def fire(modules, main_address):

    _svm = svm.SVM(modules, simplify_model = False)

    logging.info("Firing lasers!")

    _svm.sym_exec(main_address = main_address)

    logging.info("Running module [unchecked_send]")

    unchecked_send.execute(_svm)

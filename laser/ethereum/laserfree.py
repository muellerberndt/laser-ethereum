from . import svm
from .modules import unchecked_send
import logging

def fire(_svm):

    logging.info("Firing lasers!")

    logging.info("Running module [unchecked_send]")

    unchecked_send.execute(_svm)

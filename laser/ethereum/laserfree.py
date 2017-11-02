from .modules import unchecked_suicide, unchecked_send
import logging

def fire(_svm):

    logging.info("Firing lasers!")

    logging.info("Running module [unchecked_suicide]")

    unchecked_send.execute(_svm)

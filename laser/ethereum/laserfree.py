from .modules import unchecked_suicide
import logging

def fire(_svm):

    logging.info("Firing lasers!")

    logging.info("Running module [unchecked_suicide]")

    unchecked_suicide.execute(_svm)

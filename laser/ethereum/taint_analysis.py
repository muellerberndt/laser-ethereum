class TaintRecord:
    """
    TaintRecord contains tainting information for a specific (state, node)
    """
    pass


class TaintResult:
    """ Taint analysis result obtained after having ran the taint runner"""

    def check(self, state, stack_index):
        """
        Checks if stack variable is tainted
        :param state: state to check variable in
        :param stack_index: index of stack variable
        :return: tainted
        """
        pass

class TaintRunner:
    """
    Taint runner, is able to run taint analysis on symbolic execution result
    """

    @staticmethod
    def execute(statespace, node, state, stack_indexes=[]):
        """
        Runs taint analysis on the statespace
        :param statespace: symbolic statespace to run taint analysis on
        :param node: taint introduction node
        :param state: taint introduction state
        :param stack_indexes: stack indexes to introduce taint
        :return: TaintResult object containing analysis results
        """
        pass


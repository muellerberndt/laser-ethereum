class TaintRecord:
    """
    TaintRecord contains tainting information for a specific (state, node)
    """

    def __init__(self, node, state):
        """ Builds a taint record for node, state combo"""
        self.node = node
        self.state = state
        self.stack_record = {}

    def stack_tainted(self, index):
        """ Returns if stack element with index is tainted"""
        if index in self.stack_record.keys():
            return self.stack_record[index]

class TaintResult:
    """ Taint analysis result obtained after having ran the taint runner"""

    def __init__(self):
        self.records = []

    def check(self, state, stack_index):
        """
        Checks if stack variable is tainted
        :param state: state to check variable in
        :param stack_index: index of stack variable
        :return: tainted
        """
        pass

    def add_records(self, records):
        self.records += records


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
        result = TaintResult()

        # List of (Node, TaintRecord, index)
        current_nodes = []

        # TODO: build first current_node

        for node, record, index in current_nodes:
            records = TaintRunner._execute_node(node, record, index)
            result.add_records(records)

            # TODO: discover children nodes

        return result

    @staticmethod
    def _execute_node(node, last_record, state_index=0):
        """
        Runs taint analysis on a given node
        :param node: node to analyse
        :param last_record: last taint record to work from
        :param state_index: state index to start from
        :return: List of taint records linked to the states in this node
        """
        return []

    @staticmethod
    def _execute_state:
        pass
class TaintRecord:
    """
    TaintRecord contains tainting information for a specific (state, node)
    the information specifies the taint status before executing the operation belonging to the state
    """

    def __init__(self):
        """ Builds a taint record """
        self.stack_record = {}
        self.states = []

    def stack_tainted(self, index):
        """ Returns if stack element with index is tainted """
        if index in self.stack_record.keys():
            return self.stack_record[index]
        return False

    def taint_stack(self, index):
        self.stack_record[index] = True

    def remove_taint_stack(self, index):
        self.stack_record[index] = False

    def add_state(self, state):
        self.states.append(state)


class TaintResult:
    """ Taint analysis result obtained after having ran the taint runner"""

    def __init__(self):
        self.records = []

    def check(self, state, stack_index):
        """
        Checks if stack variable is tainted, before executing the instruction
        :param state: state to check variable in
        :param stack_index: index of stack variable
        :return: tainted
        """
        record = self._try_get_record(state)
        return record.stack_tainted(stack_index)

    def add_records(self, records):
        self.records += records

    def _try_get_record(self, state):
        for record in self.records:
            if state in record.states:
                return record
        return None


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

        # Build initial current_node
        init_record = TaintRecord(node, state)
        for index in stack_indexes:
            init_record.taint_stack(index)
        state_index = node.states.index(state)

        # List of (Node, TaintRecord, index)
        current_nodes = [(node, init_record, state_index)]

        for node, record, index in current_nodes:
            records = TaintRunner._execute_node(node, record, index)
            result.add_records(records)

            children = [statespace.nodes[edge.node_to] for edge in statespace.edges]
            for child in children:
                current_nodes.append((child, records[-1], 0))
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
        records = [last_record]
        for index in range(state_index, len(node.states)):
            current_state = node.states[index]
            records.append(TaintRunner._execute_state(records[-1], current_state))
        return []

    @staticmethod
    def _execute_state(record, state):
        """ Runs taint analysis on a state """
        record.add_state(state)
        new_record = TaintRecord()

        # Copy old values
        new_record.stack_record = record.stack_record

        # Apply Change
        op = state.get_current_instruction()['opcode']
        if op in TaintRunner.stack_taint_table.keys():
            mutator = TaintRunner.stack_taint_table[op]
            TaintRunner._mutate_stack(record, mutator)

        return new_record

    @staticmethod
    def _mutate_stack(record, mutator):
        pass

    stack_taint_table = {
        # instruction: (taint source, taint target)
        'ADD': (2, 1),
        'MUL': (2, 1),
        'SUB': (2, 1)
    }
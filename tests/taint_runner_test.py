import mock
import pytest
from pytest_mock import mocker
from laser.ethereum.taint_analysis import *
from laser.ethereum.svm import GlobalState, Node, Edge, LaserEVM


def test_execute_state(mocker):
    record = TaintRecord()
    record.stack_record = {
        0: True,
        1: False,
        2: True
    }

    state = GlobalState
    mocker.patch.object(state, 'get_current_instruction')
    state.get_current_instruction.return_value = {"opcode": "ADD"}

    # Act
    new_record = TaintRunner.execute_state(record, state)

    # Assert
    assert list(new_record.stack_record.items()) == [(0, True), (1, True)]
    assert list(record.stack_record.items()) == [(0, True), (1, False), (2, True)]


def test_execute_node(mocker):
    record = TaintRecord()
    record.stack_record = {
        0: True,
        1: True,
        2: False,
        3: False,
    }

    state_1 = GlobalState
    mocker.patch.object(state_1, 'get_current_instruction')
    state_1.get_current_instruction.return_value = {"opcode": "ADD"}

    state_2 = GlobalState
    mocker.patch.object(state_2, 'get_current_instruction')
    state_2.get_current_instruction.return_value = {"opcode": "ADD"}

    node = Node("Test contract")
    node.states = [state_1, state_2]

    # Act
    records = TaintRunner.execute_node(node, record)

    # Assert
    assert len(records) == 3
    assert records[0] == record
    assert list(record.stack_record.items()) == [(0, True), (1, True), (2, False), (3, False)]
    assert list(records[1].stack_record.items()) == [(0, True), (1, True), (2, False)]
    assert list(records[2].stack_record.items()) == [(0, True), (1, True)]

    assert state_2 in records[1].states
    assert state_1 in records[0].states




def test_execute(mocker):
    record = TaintRecord()
    record.stack_record = {
        0: True,
        1: True,
        2: False,
        3: False,
        4: False,
    }

    state_1 = GlobalState(None, None)
    mocker.patch.object(state_1, 'get_current_instruction')
    state_1.get_current_instruction.return_value = {"opcode": "PUSH"}

    state_2 = GlobalState(None, None)
    mocker.patch.object(state_2, 'get_current_instruction')
    state_2.get_current_instruction.return_value = {"opcode": "ADD"}

    node_1 = Node("Test contract")
    node_1.states = [state_1, state_2]

    state_3 = GlobalState(None, None)
    mocker.patch.object(state_3, 'get_current_instruction')
    state_3.get_current_instruction.return_value = {"opcode": "ADD"}

    node_2 = Node("Test contract")
    node_2.states = [state_3]

    edge = Edge(node_1.uid, node_2.uid)

    statespace = LaserEVM(None)
    statespace.edges = [edge]
    statespace.nodes[node_1.uid] = node_1
    statespace.nodes[node_2.uid] = node_2

    # Act
    result = TaintRunner.execute(statespace, node_1, state_1, [0, 1])

    # Assert
    print(result)
    assert len(result.records) == 3
    assert result.records[2].states == []
    assert state_3 in result.records[1].states
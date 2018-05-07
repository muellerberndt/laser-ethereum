import mock
import pytest
from pytest_mock import mocker
from laser.ethereum.taint_analysis import *
from laser.ethereum.svm import GlobalState


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
    TaintRunner.execute_state(record, state)

    # Assert
    assert list(record.stack_record.items()) == [(0, True), (1, True)]



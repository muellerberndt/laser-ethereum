from laser.ethereum.taint_analysis import *
from laser.ethereum.svm import MachineState


def test_result_state():
    # arrange
    taint_result = TaintResult()
    record = TaintRecord()
    state = MachineState(2)
    record.add_state(state)

    # act
    taint_result.add_records([record])
    tainted = taint_result.check(state, 2)

    # assert
    assert tainted is False
    assert record in taint_result.records


def test_result_no_state():
    # arrange
    taint_result = TaintResult()
    record = TaintRecord()
    state = MachineState(2)

    # act
    taint_result.add_records([record])
    tainted = taint_result.check(state, 2)

    # assert
    assert tainted is None
    assert record in taint_result.records
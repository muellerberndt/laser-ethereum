from laser.ethereum.taint_analysis import *

def test_mutate_not_tainted():
    # Arrange
    record = TaintRecord()

    record.stack_record = {
        0: True,
        1: False,
        2: False
    }

    # Act
    TaintRunner.mutate_stack(record, (2,1))

    # Assert
    assert record.stack_tainted(0)
    assert record.stack_tainted(1) is False
    assert list(record.stack_record.items()) == [(0, True), (1, False)]


def test_mutate_tainted():
    # Arrange
    record = TaintRecord()

    record.stack_record = {
        0: True,
        1: False,
        2: True
    }

    # Act
    TaintRunner.mutate_stack(record, (2,1))

    # Assert
    assert record.stack_tainted(0)
    assert record.stack_tainted(1)
    assert list(record.stack_record.items()) == [(0, True), (1, True)]
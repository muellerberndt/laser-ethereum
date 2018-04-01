from unittest import TestCase, skip
import json
from mythril.ether.soliditycontract import SolidityContract

from laser.ethereum.svm import GlobalState, MachineState
from laser.ethereum import svm
from tests import *


class LaserEncoder(json.JSONEncoder):
    def default(self, o):
        if getattr(o, "__module__", None) == "z3.z3":
            return str(o)
        return str(o)


def _all_info(laser):
    accounts = {}
    for address, _account in laser.accounts.items():
        account = _account.as_dict()
        account["code"] = account["code"].instruction_list
        account['balance'] = str(account['balance'])
        accounts[address] = account

    nodes = {}
    for uid, node in laser.nodes.items():
        states = []
        for state in node.states:
            if isinstance(state, MachineState):
                states.append(state.as_dict())
            elif isinstance(state, GlobalState):
                environment = state.environment.as_dict()
                environment["active_account"] = environment["active_account"].address
                states.append({
                    'accounts': state.accounts.keys(),
                    'environment': environment,
                    'mstate': state.mstate.as_dict()
                })

        nodes[uid] = {
            'uid': node.uid,
            'contract_name': node.contract_name,
            'start_addr': node.start_addr,
            'states': states,
            'constraints': node.constraints,
            'function_name': node.function_name,
            'flags': str(node.flags)
        }

    edges = [edge.as_dict() for edge in laser.edges]

    return {
        'accounts': accounts,
        'nodes': nodes,
        'edges': edges,
        'total_states': laser.total_states,
        'max_depth': laser.max_depth
    }


class SvmTest(TestCase):

    def setUp(self):
        svm.gbl_next_uid = 0

    def _test_with_file(self, filename):
        input_file = (TESTDATA / "inputs" / filename)
        output_expected = TESTDATA / "outputs_expected" / (input_file.name + ".json")
        output_current = TESTDATA / "outputs_current" / (input_file.name + ".json")

        disassembly = SolidityContract(str(input_file)).disassembly
        account = svm.Account("0x0000000000000000000000000000000000000000", disassembly)
        accounts = {account.address: account}

        laser = svm.LaserEVM(accounts)
        laser.sym_exec(account.address)
        laser_info = _all_info(laser)

        output_current.write_text(json.dumps(laser_info, cls=LaserEncoder, indent=4))

        self.assertEqual(output_expected.read_text(), output_current.read_text(),
                         "{}: information of laser is changed, you can compare follow files to see the differences:\n{}\n{}\n".format(str(input_file), str(output_expected), str(output_current)))

    def test_with_file_calls(self):
        self._test_with_file("calls.sol")

    def test_with_file_ether_send(self):
        self._test_with_file("ether_send.sol")

    def test_with_file_exceptions(self):
        self._test_with_file("exceptions.sol")

    def test_with_file_kinds_of_calls(self):
        self._test_with_file("kinds_of_calls.sol")

    def test_with_file_metacoin(self):
        self._test_with_file("metacoin.sol")

    def test_with_file_multi_contracts(self):
        self._test_with_file("multi_contracts.sol")

    def test_with_file_origin(self):
        self._test_with_file("origin.sol")

    def test_with_file_returnvalue(self):
        self._test_with_file("returnvalue.sol")

    def test_with_file_rubixi(self):
        self._test_with_file("rubixi.sol")

    def test_with_file_suicide(self):
        self._test_with_file("suicide.sol")

    def test_with_file_underflow(self):
        self._test_with_file("underflow.sol")

    @skip("generated information is too large (> 90M)")
    def test_with_file_weak_random(self):
        self._test_with_file("weak_random.sol")

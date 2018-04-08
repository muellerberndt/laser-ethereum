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


class SvmTest(BaseTestCase):

    def setUp(self):
        super(SvmTest, self).setUp()
        svm.gbl_next_uid = 0

    def test(self):
        for input_file in TESTDATA_INPUTS.iterdir():
            output_expected = TESTDATA_OUTPUTS_EXPECTED / (input_file.name + ".json")
            output_current = TESTDATA_OUTPUTS_CURRENT / (input_file.name + ".json")

            disassembly = SolidityContract(str(input_file)).disassembly
            account = svm.Account("0x0000000000000000000000000000000000000000", disassembly)
            accounts = {account.address: account}

            laser = svm.LaserEVM(accounts)
            laser.sym_exec(account.address)
            laser_info = _all_info(laser)

            output_current.write_text(json.dumps(laser_info, cls=LaserEncoder, indent=4))

            if not (output_expected.read_text() == output_expected.read_text()):
                self.found_changed_files(input_file, output_expected, output_current)

        self.assert_and_show_changed_files()

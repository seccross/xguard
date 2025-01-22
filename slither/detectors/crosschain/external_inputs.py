"""
Module detecting vulnerabilities in crosschain bridges

"""
from typing import List, Tuple
from slither.analyses.data_dependency.data_dependency import is_tainted, is_dependent
from slither.core.cfg.node import Node
# from slither.core.declarations.contract import Contract
from slither.core.declarations import Contract, Function, SolidityVariableComposed
from slither.core.declarations.function_contract import FunctionContract
from slither.core.declarations.modifier import Modifier
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations import (
    HighLevelCall,
    Index,
    LowLevelCall,
    Send,
    SolidityCall,
    Transfer,
)
from slither.slithir.operations.event_call import EventCall
from slither.slithir.operations import HighLevelCall, LibraryCall
from slither.slithir.operations.low_level_call import LowLevelCall
from slither.utils.output import Output
import re

from .common import get_args

HASH_FUNCTIONS = ["keccak256()", "sha256()", "sha3()", "keccak256(bytes)", "sha256(bytes)", "sha3(bytes)"]

class ExternalInputs(AbstractDetector):
    """
    Missing HASHLOCK and TIMELOCK for HTLC crosschain asset refund and claim
    """

    ARGUMENT = "external-inputs"
    HELP = "External inputs checker"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    SEND_FUNS, CROSSCHAINRECEIVESIGLIST, CROSSCHAINSENDEVENTLIST, RECEIVE_EVNTS = get_args()
    # SEND_FUNS = ["transferOut(address,address,uint256,bytes32,uint64,uint64,address)"]
    # RECEIVE_EVNTS = ["LogNewTransferIn"]

    WIKI = "https://github.com/liyue-cs/CrosschainSniffer"
    WIKI_TITLE = "Crosschain message might be reconstructed by event parser"
    WIKI_DESCRIPTION = "Crosschain message might be reconstructed by event parser"

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
        ```solidity
        contract C {

        modifier onlyAdmin {
            if (msg.sender != owner) throw;
            _;
        }

        function updateOwner(address newOwner) onlyAdmin external {
            owner = newOwner;
        }
        }
        ```
        `updateOwner()` has no event, so it is difficult to track off-chain owner changes.
        """
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Emit an event for critical parameter changes."

    @staticmethod
    def _detect_external_inputs(
            contract: Contract,
            receive_events: List,
            send_funcs: List
    ) -> List[Tuple[FunctionContract, List[Tuple[Node, StateVariable, Modifier]]]]:
        """
        Detects Missing TIMELOCK and HASHLOCK for HTLC crosschain asset refund and claim
        :return: Functions with detected missing TIMELOCK and HASHLOCK
        """
        results = []
        receive_params = []
        send_params = []

        # pylint: disable=too-many-nested-blocks
        for func in contract.functions_entry_points:

            # Skip non-send functions
            if func.is_constructor or func.is_protected():
                continue

            if func.solidity_signature in send_funcs:
                params = set()
                for param in func.parameters:
                    name = re.sub(r'[^a-zA-Z0-9]', '', param.name.lower())
                    params.add(name + ":" + str(param.type))
                send_params.append((func,params))
        
        for event in contract.events:
            if event.name in receive_events:
                params = set()
                for param in event.elems:
                    xx = param
                    name = re.sub(r'[^a-zA-Z0-9]', '', param.name.lower())
                    params.add(name + ":" + str(param.type))
                receive_params.append((event,params))
        
        for (func, params) in send_params:
            fparams = set(params)
            for (event, eparams) in receive_params:
                fparams -= eparams
            results.append((func, fparams))

        return results


    def _detect(self) -> List[Output]:
        """Detect missing TIMELOCK and HASHLOCK for HTLC crosschain asset refund and claim:
            list: {'(function, event)'}
        """

        # Check derived contracts for missing events
        results = []

        for contract in self.compilation_unit.contracts_derived:
            htlc_crosschain_asset_refunds = self._detect_external_inputs(contract, self.RECEIVE_EVNTS, self.SEND_FUNS)
            if len(htlc_crosschain_asset_refunds):
                for (function, inputs) in htlc_crosschain_asset_refunds:
                    info: DETECTOR_INFO = ["crosschain asset refund", function, "\n"]
                    info += ["\t- ", ', '.join(map(str, inputs)), " \n"]
                    res = self.generate_result(info)
                    results.append(res)
        return results

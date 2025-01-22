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

from .common import get_args

HASH_FUNCTIONS = ["keccak256()", "sha256()", "sha3()", "keccak256(bytes)", "sha256(bytes)", "sha3(bytes)"]

class IncompleteHtlc(AbstractDetector):
    """
    Missing HASHLOCK and TIMELOCK for HTLC crosschain asset refund and claim
    """

    ARGUMENT = "incomplete-htlc"
    HELP = "HTLC Crosschain missing checker"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    CROSSCHAINSENDSIGLIST, CROSSCHAINRECEIVESIGLIST, CROSSCHAINSENDEVENTLIST, CROSSCHAINRECEIVEEVENTLIST = get_args()

    REFUND_SIGS = ["refund(bytes32)"]
    CLAIM_SIGS = ["confirm(bytes32,bytes32)"]

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
    def _detect_htlc(
            contract: Contract,
            refund_sigs: List,
            claim_sigs: List
    ) -> List[Tuple[FunctionContract, List[Tuple[Node, StateVariable, Modifier]]]]:
        """
        Detects Missing TIMELOCK and HASHLOCK for HTLC crosschain asset refund and claim
        :return: Functions with detected missing TIMELOCK and HASHLOCK
        """
        results = []
        refund_funcs = set()
        claim_funcs = set()

        # pylint: disable=too-many-nested-blocks
        for func in contract.functions_entry_points:

            # Skip non-send functions
            if func.is_constructor or func.is_protected():
                continue

            if func.solidity_signature in refund_sigs:
                refund_funcs.add(func)
            if func.solidity_signature in claim_sigs:
                claim_funcs.add(func)
        
        for func in claim_funcs:
            missing_hash = True
            for node in func.nodes:
                slithir_operation = []
                for inter_call in node.internal_calls:
                    if isinstance(inter_call, Function):
                        slithir_operation += inter_call.all_slithir_operations()
                for ir in node.irs + slithir_operation:
                    if isinstance(ir, (SolidityCall)):
                        if ir.function.full_name in HASH_FUNCTIONS:
                            missing_hash = False
                            break
                if not missing_hash:
                    break
            if missing_hash:
                results.append((func, "MISSING HASH CHECK"))

        for func in refund_funcs:
            missing_time = True
            for node in func.nodes:
                slithir_operation = []
                for inter_call in node.internal_calls:
                    if isinstance(inter_call, Function):
                        slithir_operation += inter_call.all_slithir_operations()
                for ir in node.irs + slithir_operation:
                    exp = str(ir.expression)
                    if ("block.timestamp" in exp) or ("block.number" in exp):
                        missing_time = False
                        break
                if not missing_time:
                    break
            if missing_time:
                results.append((func, "MISSING TIME CHECK"))

        return results


    def _detect(self) -> List[Output]:
        """Detect missing TIMELOCK and HASHLOCK for HTLC crosschain asset refund and claim:
            list: {'(function, info)'}
        """

        # Check derived contracts for missing events
        results = []

        CROSSCHAINSIGLIST = self.CROSSCHAINRECEIVESIGLIST + self.CROSSCHAINSENDSIGLIST
        for contract in self.compilation_unit.contracts_derived:
            htlc_crosschain_asset_refunds = self._detect_htlc(contract, self.REFUND_SIGS, self.CLAIM_SIGS)
            if len(htlc_crosschain_asset_refunds):
                for (function, detail) in htlc_crosschain_asset_refunds:
                    info: DETECTOR_INFO = ["crosschain asset refund", function, "\n"]
                    info += ["\t- ", detail, " \n"]
                    res = self.generate_result(info)
                    results.append(res)
        return results

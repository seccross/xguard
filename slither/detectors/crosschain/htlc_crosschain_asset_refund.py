"""
Module detecting vulnerabilities in crosschain bridges

"""
from typing import List, Tuple
from .globalVar import GCROSSCHAINSENDSIGLIST, GCROSSCHAINRECEIVESIGLIST, GCROSSCHAINRECEIVEEVENTLIST, GCROSSCHAINSENDEVENTLIST
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


class HTLCCrosschainAssetRefund(AbstractDetector):
    """
    Missing events for critical contract parameters set by owners and used in access control
    """

    ARGUMENT = "HTLC-crosschain-asset-refund"
    HELP = "HTLC Crosschain asset refund"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    CROSSCHAINSENDSIGLIST = GCROSSCHAINSENDSIGLIST
    CROSSCHAINRECEIVESIGLIST = GCROSSCHAINRECEIVESIGLIST
    CROSSCHAINSENDEVENTLIST = GCROSSCHAINSENDEVENTLIST
    CROSSCHAINRECEIVEEVENTLIST = GCROSSCHAINRECEIVEEVENTLIST
    TIMELOCKANDHASHLOCKRELATEDSTATE = ["timelock", "transfers"]



    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#missing-events-access-control"
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
    def _detect_crosschain_asset_refund(
            contract: Contract,
            crosschainfunctionsig: List,
            lockset: List
    ) -> List[Tuple[FunctionContract, List[Tuple[Node, StateVariable, Modifier]]]]:
        """
        Detects if critical contract parameters set by owners and used in access control are missing events
        :param contract: The contract to check
        :return: Functions with nodes of critical operations but no events
        """
        results = []

        # pylint: disable=too-many-nested-blocks
        for func in contract.functions_entry_points:

            # Skip non-send functions
            if func.is_constructor or func.is_protected():
                continue

            transfer_functions = set()

            for node in func.nodes:
                # func = node.function
                slithir_operation = []
                for inter_call in node.internal_calls:
                    slithir_operation += inter_call.all_slithir_operations()

                for ir in node.irs + slithir_operation:
                    if isinstance(ir, (HighLevelCall, LowLevelCall, LibraryCall, Transfer, Send)):
                        if isinstance(ir, (HighLevelCall)):
                            if isinstance(ir.function, Function):
                                if ir.function.full_name in ["transfer(address,uint256)", "transferFrom(address,address,uint256)"]:
                                    if node not in transfer_functions:
                                        transfer_functions.add(node)
                        elif isinstance(ir, LibraryCall) and ir.function.solidity_signature in ["safeTransfer(address,address,uint256)"]:
                            transfer_functions.add(node)
                        elif isinstance(ir, (Transfer, Send)):
                            transfer_functions.add(node)

            for transfer_node in transfer_functions:
                if not any(state for dominator in transfer_node.dominators if dominator.is_conditional() for state in dominator.state_variables_read if state.name in lockset):
                     results.append((func, transfer_node))

        return results



    def _detect(self) -> List[Output]:
        """Detect missing events for critical contract parameters set by owners and used in access control
        Returns:
            list: {'(function, node)'}
        """

        # Check derived contracts for missing events
        results = []

        CROSSCHAINSIGLIST = self.CROSSCHAINRECEIVESIGLIST + self.CROSSCHAINSENDSIGLIST
        for contract in self.compilation_unit.contracts_derived:
            htlc_crosschain_asset_refunds = self._detect_crosschain_asset_refund(contract, CROSSCHAINSIGLIST, self.TIMELOCKANDHASHLOCKRELATEDSTATE)
            if len(htlc_crosschain_asset_refunds):
                for (function, node) in htlc_crosschain_asset_refunds:
                    info: DETECTOR_INFO = ["crosschain asset refund", function, "\n"]
                    info += ["\t- ", node, " \n"]
                    res = self.generate_result(info)
                    results.append(res)
        return results

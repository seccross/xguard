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


class HTLCCrosschainAssetRefund(AbstractDetector):
    """
    Missing events for critical contract parameters set by owners and used in access control
    """

    ARGUMENT = "HTLC-crosschain-asset-refund"
    HELP = "HTLC Crosschain asset refund"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    CROSSCHAINSENDSIGLIST = ["send(address,address,uint256)", "send2(address,address,uint256)"]
    CROSSCHAINRECEIVESIGLIST = ["receive(address,address,uint256)", "receive2(address,address,uint256)"]
    CROSSCHAINSENDEVENTLIST = ["eventsend", "eventsend2"]
    CROSSCHAINRECEIVEEVENTLIST = ["eventreceive", "eventreceive2"]
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
                func = node.function
                for ir in node.irs:
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

            # Check for any events in the function and skip if found
            # Note: not checking if event corresponds to critical parameter

            # if not any(ir for node in function.nodes for ir in node.irs if isinstance(ir, EventCall)):
            #     results.append(function)
            #     continue

            # eventSendNodeList = []
            # all_conditional_state_var = function.all_conditional_state_variables_read()
            # potential_process_call = []
            # vulnerable_process_call = []
            # missing_check_process_call = []

            #             if not len(node.local_variables_read) == 0:
            #                 for var in node.local_variables_read:
            #                     if is_tainted(var, function):
            #                         potential_process_call.append(node)
            # missing_check_process_call = potential_process_call
            # for call in potential_process_call:
            #     for dominator in call.dominators:
            #         if dominator.is_conditional():
            #             if len(dominator.state_variables_read):
            #                 missing_check_process_call.remove(call)
            #                 if any(state for state in dominator.state_variables_read if is_tainted(state, contract)):
            #                     if not call in vulnerable_process_call:
            #                         vulnerable_process_call.append(call)
            #
            # if len(potential_process_call) or len(missing_check_process_call):
            #     results.append(function)

            # if isinstance(ir, EventCall) and ir.name in crosschainreceiveeventlist:
            #     eventSendNodeList.append(node)

            # for eventNode in eventSendNodeList:
            #     for ir in eventNode.irs:
            #         if isinstance(ir, EventCall) and not any(arg for arg in ir.arguments if (
            #                 is_tainted(arg, function) or is_dependent(arg, SolidityVariableComposed("msg.sender"),
            #                                                           function))):
            #             results.append(function)

            # if len(eventSendNodeList) == 0:
            #     if len(function.all_state_variables_written()) != 0 or len(function.external_calls_as_expressions) != 0:
            #         results.append(function)
            #     continue
            # else:
            #     for eventSendNode in eventSendNodeList:
            #         if not any(ir for node in eventSendNode.dominators for ir in node.irs if (isinstance(ir, HighLevelCall) or isinstance(ir, LowLevelCall))):
            #             results.append(function)

            # Ignore constructors and private/internal functions
            # Heuristic-1: functions with critical operations are typically "protected". Skip unprotected functions.
            # if function.is_constructor or not function.is_protected():
            #     continue

            # Heuristic-2

            # Heuristic-2: Critical operations are where state variables are written and tainted
            # Heuristic-3: Variables of interest are address type that are used in modifiers i.e. access control
            # Heuristic-4: Critical operations present but no events in the function is not a good practice
            # for node in function.nodes:
            #     for sv in node.state_variables_written:
            #         if is_tainted(sv, function) and sv.type == ElementaryType("address"):
            #             for mod in function.contract.modifiers:
            #                 if sv in mod.state_variables_read:
            #                     nodes.append((node, sv, mod))
            # if nodes:
            #     results.append((function, nodes))
        # return results

    def _detect(self) -> List[Output]:
        """Detect missing events for critical contract parameters set by owners and used in access control
        Returns:
            list: {'(function, node)'}
        """

        # Check derived contracts for missing events
        results = []

        CROSSCHAINSIGLIST = self.CROSSCHAINRECEIVESIGLIST + self.CROSSCHAINSENDSIGLIST
        for contract in self.compilation_unit.contracts_derived:
            missing_send_events = self._detect_crosschain_asset_refund(contract, CROSSCHAINSIGLIST, self.TIMELOCKANDHASHLOCKRELATEDSTATE)
            if len(missing_send_events):
                for (function, node) in missing_send_events:
                    info: DETECTOR_INFO = ["crosschain asset refund", function, "\n"]
                    info += ["\t- ", node, " \n"]
                    res = self.generate_result(info)
                    results.append(res)
        return results

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


class IncompleteEvent(AbstractDetector):
    """
    Missing events for critical contract parameters set by owners and used in access control
    """

    ARGUMENT = "incomplete-event"
    HELP = "An incomplete event emitted in crosschain bridge"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    CROSSCHAINSENDSIGLIST = GCROSSCHAINSENDSIGLIST
    CROSSCHAINRECEIVESIGLIST = GCROSSCHAINRECEIVESIGLIST
    CROSSCHAINSENDEVENTLIST = GCROSSCHAINSENDEVENTLIST
    CROSSCHAINRECEIVEEVENTLIST = GCROSSCHAINRECEIVEEVENTLIST

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
    def _detect_incomplete_event(
            contract: Contract,
            crosschainsendsiglist: List,
            crosschaineventlist: List
    ) -> List[Tuple[FunctionContract, List[Tuple[Node, StateVariable, Modifier]]]]:
        """
        Detects if critical contract parameters set by owners and used in access control are missing events
         :return: Functions with nodes of critical operations but no events
        """
        results = []

        # pylint: disable=too-many-nested-blocks
        for function in contract.functions_entry_points:
            nodes = []

            # Skip non-send functions
            if function.solidity_signature not in crosschainsendsiglist:
                continue

            # Check for any events in the function and skip if found
            # Note: not checking if event corresponds to critical parameter

            # if not any(ir for node in function.nodes for ir in node.irs if isinstance(ir, EventCall)):
            #     results.append(function)
            #     continue

            eventSendNodeList = {}

            for node in function.nodes:
                for ir in node.irs:
                    if isinstance(ir, EventCall) and ir.name in crosschaineventlist:
                        eventSendNodeList.update({node: {"sourceToken": "", "sourceUser": "", "sourceAmount": ""}})

            for eventNode in eventSendNodeList.keys():
                # 1. check asset type; 2. check from address; 3. check other informations.
                transfer_functions = set()
                for dominator in list(eventNode.dominators) + list(eventNode.dominance_exploration_ordered):
                    slithir_opreation = []
                    for inter_call in dominator.internal_calls:
                        if isinstance(inter_call, Function):
                            slithir_opreation += inter_call.all_slithir_operations()
                    for ir in dominator.irs + slithir_opreation:
                        if isinstance(ir, (HighLevelCall, LowLevelCall, LibraryCall, Transfer, Send)):
                            if isinstance(ir, (HighLevelCall)):
                                if isinstance(ir.function, Function):
                                    if ir.function.full_name in ["transferFrom(address,address,uint256)" ]:
                                        if dominator not in transfer_functions:
                                            eventSendNodeList[eventNode]["sourceToken"] = ir.destination
                                            eventSendNodeList[eventNode]["sourceUser"] = ir.arguments[0]
                                            eventSendNodeList[eventNode]["sourceAmount"] = ir.arguments[2]

                                            transfer_functions.add(dominator)
                                    elif ir.function.solidity_signature in [
                                        "safeTransferFrom(address,address,address,uint256)"]:
                                        if dominator not in transfer_functions:
                                            eventSendNodeList[eventNode]["sourceToken"] = ir.arguments[0]
                                            eventSendNodeList[eventNode]["sourceUser"] = ir.arguments[1]
                                            eventSendNodeList[eventNode]["sourceAmount"] = ir.arguments[3]

                                            transfer_functions.add(dominator)

                            elif isinstance(ir, LibraryCall) and ir.function.solidity_signature in [
                                "safeTransferFrom(address,address,address,uint256)"]:
                                if dominator not in transfer_functions:
                                    eventSendNodeList[eventNode]["sourceToken"] = ir.arguments[0]
                                    eventSendNodeList[eventNode]["sourceUser"] = ir.arguments[1]
                                    eventSendNodeList[eventNode]["sourceAmount"] = ir.arguments[3]
                                    transfer_functions.add(dominator)
                            elif isinstance(ir, (Transfer, Send)):
                                if dominator not in transfer_functions:
                                    eventSendNodeList[eventNode]["sourceToken"] = "ETH"
                                    eventSendNodeList[eventNode]["sourceUser"] = SolidityVariableComposed("msg.sender")
                                    eventSendNodeList[eventNode]["sourceAmount"] = ir.call_value

                                    transfer_functions.add(dominator)


                if eventSendNodeList[eventNode]["sourceToken"] != "":
                    event_send_flag = [False, False, False]

                    for ir in eventNode.irs:
                        if isinstance(ir, EventCall):
                            if any(arg for arg in ir.arguments if is_dependent(arg, eventSendNodeList[eventNode]["sourceToken"], function)):
                                event_send_flag[0] = True

                            if any(arg for arg in ir.arguments if is_dependent(arg, eventSendNodeList[eventNode]["sourceUser"], function)):
                                event_send_flag[1] = True

                            if any(arg for arg in ir.arguments if is_dependent(arg, eventSendNodeList[eventNode]["sourceAmount"], function)):
                                event_send_flag[2] = True

                    if False in event_send_flag:
                        results.append((function, eventNode))

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
        return results

    def _detect(self) -> List[Output]:
        """Detect missing events for critical contract parameters set by owners and used in access control
        Returns:
            list: {'(function, node)'}
        """

        # Check derived contracts for missing events
        results = []
        for contract in self.compilation_unit.contracts_derived:
            incomplete_send_events = self._detect_incomplete_event(contract, self.CROSSCHAINSENDSIGLIST,
                                                                   self.CROSSCHAINSENDEVENTLIST)
            for (function, node) in incomplete_send_events:
                info: DETECTOR_INFO = ["Incomplete event ", function, "\n"]
                info += ["\t- ", node, " \n"]
                res = self.generate_result(info)
                results.append(res)
        return results

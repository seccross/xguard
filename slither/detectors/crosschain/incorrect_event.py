"""
Module detecting vulnerabilities in crosschain bridges

"""
from typing import List, Tuple
from .globalVar import GCROSSCHAINSENDSIGLIST, GCROSSCHAINRECEIVESIGLIST, GCROSSCHAINRECEIVEEVENTLIST, GCROSSCHAINSENDEVENTLIST
from slither.analyses.data_dependency.data_dependency import is_tainted
from slither.core.cfg.node import Node
from slither.core.declarations.contract import Contract, Function
from slither.core.declarations.function_contract import FunctionContract
from slither.core.declarations.modifier import Modifier
from slither.core.solidity_types.elementary_type import ElementaryType
from slither.core.variables.state_variable import StateVariable
from slither.detectors.abstract_detector import (
    AbstractDetector,
    DetectorClassification,
    DETECTOR_INFO,
)
from slither.slithir.operations.event_call import EventCall
from slither.slithir.operations import HighLevelCall, LibraryCall
from slither.slithir.operations.low_level_call import LowLevelCall
from slither.utils.output import Output


# T1:Inconsistency Behavior
class IncorrectEvent(AbstractDetector):
    """
    Missing events for critical contract parameters set by owners and used in access control
    """

    ARGUMENT = "incorrect-event"
    HELP = "An incorrect event emitted in crosschain bridge"
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.MEDIUM

    CROSSCHAINSENDSIGLIST = GCROSSCHAINSENDSIGLIST
    CROSSCHAINRECEIVESIGLIST = GCROSSCHAINRECEIVESIGLIST
    CROSSCHAINSENDEVENTLIST = GCROSSCHAINSENDEVENTLIST
    CROSSCHAINRECEIVEEVENTLIST = GCROSSCHAINRECEIVEEVENTLIST

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation#incorrect-event"
    WIKI_TITLE = "An incorrect event emitted in crosschain bridge"
    WIKI_DESCRIPTION = "An incorrect event emitted in crosschain bridge"

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
    def _detect_incorrect_events(
        contract: Contract,
        crosschainsendsiglist: List,
        crosschaineventlist:List,
        crosschainstoragelist:List
    ) -> List[Tuple[FunctionContract, List[Tuple[Node, StateVariable, Modifier]]]]:
        """
        Detects if critical contract parameters set by owners and used in access control are missing events
        :param contract: The contract to check
        :return: Functions with nodes of critical operations but no events
        """
        results = []

        # pylint: disable=too-many-nested-blocks
        for function in contract.functions_entry_points:
            nodes = []

            # Skip non-send functions
            if not function.solidity_signature in crosschainsendsiglist:
                continue

            # Check for any events in the function and skip if found
            # Note: not checking if event corresponds to critical parameter

            # if not any(ir for node in function.nodes for ir in node.irs if isinstance(ir, EventCall)):
            #     results.append(function)
            #     continue

            eventSendNodeList = []
            state_var_written = []
            external_call = []

            for node in function.nodes:
                slithir_operations = []
                for internal_call in node.internal_calls:
                    # Filter to Function, as internal_call can be a solidity call
                    if isinstance(internal_call, Function):
                        # for internal_node in internal_call.all_nodes():
                        #     for read in internal_node.state_variables_read:
                        #         state_vars_read[read].add(internal_node)
                        #     for write in internal_node.state_variables_written:
                        #         state_vars_written[write].add(internal_node)
                        slithir_operations += internal_call.all_slithir_operations()

                for ir in node.irs + slithir_operations:
                    if isinstance(ir, EventCall) and ir.name in crosschaineventlist:
                        eventSendNodeList.append(node)
                    if isinstance(ir, HighLevelCall) or isinstance(ir, LowLevelCall):
                        external_call.append(node)
                if len(node.state_variables_written):
                    state_var_written.append(node)
            # if not len(eventSendNodeList):
            #     for event in eventSendNodeList:

            if len(eventSendNodeList) == 0:
                if len(function.all_state_variables_written()) != 0 or len(external_call) != 0:
                    results.append(function)
                continue

            else:
                update_var = False
                for eventSendNode in eventSendNodeList:
                    for node in (eventSendNode.dominators or eventSendNode.dominance_exploration_ordered):
                        if node in state_var_written:
                            for var in node.state_variables_written:
                                if str(var) in crosschainstoragelist:
                                    update_var = True

                        if node in external_call:
                            if node.will_return is True:
                                update_var = True

                if update_var is False:
                    results.append(function)
                    # if not any(node for node in (eventSendNode.dominators or eventSendNode.dominance_exploration_ordered) if node in state_var_written or node in external_call):
                    #     results.append(function)
                    # if not any(ir for node in  for ir in node.irs if (isinstance(ir, HighLevelCall) or isinstance(ir, LowLevelCall))):







            # Ignore constructors and private/internal functions
            # Heuristic-1: functions with critical operations are typically "protected". Skip unprotected functions.
            if function.is_constructor or not function.is_protected():
                continue


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
            incorrect_events = self._detect_incorrect_events(contract, self.CROSSCHAINSENDSIGLIST, self.CROSSCHAINSENDEVENTLIST, self.CROSSCHAINRECEIVEEVENTLIST)
            for function in incorrect_events:
                info: DETECTOR_INFO = ["Incorrect event emit ", function, "\n"]
                res = self.generate_result(info)
                results.append(res)
        return results

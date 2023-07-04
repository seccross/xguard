"""
Module detecting vulnerabilities in crosschain bridges

"""
import copy
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
from slither.core.declarations.solidity_variables import (
    SolidityFunction,
    SolidityVariableComposed,
    SolidityVariable,
)
from slither.slithir.operations.event_call import EventCall
from slither.slithir.operations import HighLevelCall, LibraryCall, SolidityCall
from slither.slithir.operations.low_level_call import LowLevelCall
from slither.utils.output import Output


class MissingCrosschainCheck(AbstractDetector):
    """
    Missing events for critical contract parameters set by owners and used in access control
    """

    ARGUMENT = "miss-crosschain-data-check"
    HELP = "Missing crosschain data check on destination chain"
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
    def _detect_missing_crosschain_data_check(
            contract: Contract,
            crosschainreceivesiglist:List,
            crosschainreceiveeventlist: List
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
            if not function.solidity_signature in crosschainreceivesiglist:
                continue

            # Check for any events in the function and skip if found
            # Note: not checking if event corresponds to critical parameter

            # if not any(ir for node in function.nodes for ir in node.irs if isinstance(ir, EventCall)):
            #     results.append(function)
            #     continue

            # eventSendNodeList = []
            # all_conditional_state_var = function.all_conditional_state_variables_read()
            potential_process_call = set()
            vulnerable_process_call = set()
            missing_check_process_call = []

            for node in function.nodes:
                for ir in node.irs:
                    if isinstance(ir, HighLevelCall) or isinstance(ir, LowLevelCall):
                        if not len(node.local_variables_read) == 0:
                            for var in node.local_variables_read:
                                if is_tainted(var, function):
                                    potential_process_call.add(node)
            missing_check_process_call = copy.deepcopy(potential_process_call)

            for call in potential_process_call:
                for dominator in call.dominators:
                    if dominator.is_conditional():
                        if len(dominator.state_variables_read) and call in missing_check_process_call:
                            missing_check_process_call.remove(call)
                            if any(state for state in dominator.state_variables_read if is_tainted(state, contract, True)):
                                if not call in vulnerable_process_call:
                                    vulnerable_process_call.add(call)
                    else:
                        for ir in dominator.irs:
                            if isinstance(ir, SolidityCall):
                                if ir.function == SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)") and call in missing_check_process_call:
                                    missing_check_process_call.remove(call)

            if len(potential_process_call) or len(missing_check_process_call):
                results.append(function)




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
            missing_crosschain_data_checks = self._detect_missing_crosschain_data_check(contract, self.CROSSCHAINRECEIVESIGLIST, self.CROSSCHAINRECEIVEEVENTLIST)
            for function in missing_crosschain_data_checks:
                info: DETECTOR_INFO = ["Missing Crosschain Check ", function, "\n"]
                res = self.generate_result(info)
                results.append(res)
        return results

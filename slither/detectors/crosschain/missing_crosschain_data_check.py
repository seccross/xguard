"""
Module detecting vulnerabilities in crosschain bridges

"""
import copy
import networkx as nx
from typing import List, Tuple
from .globalVar import GCROSSCHAINSENDSIGLIST, GCROSSCHAINRECEIVESIGLIST, GCROSSCHAINRECEIVEEVENTLIST, \
    GCROSSCHAINSENDEVENTLIST, XGRAPH
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
from slither.slithir.operations import HighLevelCall, LibraryCall, SolidityCall, InternalCall
from slither.slithir.operations.low_level_call import LowLevelCall
from slither.utils.output import Output

from collections import defaultdict
from typing import Optional, Union, Dict, Set, Tuple, Sequence
import copy
import networkx as nx
from slither.detectors.crosschain.globalVar import XGRAPH

from slither.core.declarations import Contract, FunctionContract
from slither.core.declarations.function import Function
from slither.core.declarations.solidity_variables import SolidityFunction
from slither.core.variables.variable import Variable
from slither.printers.abstract_printer import AbstractPrinter
from slither.utils.output import Output


def _contract_subgraph(contract: Contract) -> str:
    return f"cluster_{contract.id}_{contract.name}"


# return unique id for contract function to use as node name
def _function_node(contract: Contract, function: Union[Function, Variable]) -> str:
    return f"{contract.id}_{function.name}"


# return unique id for solidity function to use as node name
def _solidity_function_node(solidity_function: SolidityFunction) -> str:
    return f"{solidity_function.name}"


# return dot language string to add graph edge
def _edge(from_node: str, to_node: str) -> str:
    return f'"{from_node}" -> "{to_node}"'


# return dot language string to add graph node (with optional label)
def _node(node: str, label: Optional[str] = None) -> str:
    return " ".join(
        (
            f'"{node}"',
            f'[label="{label}"]' if label is not None else "",
        )
    )


# pylint: disable=too-many-arguments
def _process_internal_call(
        contract: Contract,
        function: Function,
        internal_call: Union[Function, SolidityFunction],
        contract_calls: Dict[Contract, Set[str]],
        solidity_functions: Set[str],
        solidity_calls: Set[str],
        dependency_dict: Dict[str, Set[str]],
        dependency_graph,
) -> None:
    if isinstance(internal_call, (Function)):
        contract_calls[contract].add(
            _edge(
                _function_node(contract, function),
                _function_node(contract, internal_call),
            )
        )
        if function.name not in dependency_dict:
            dependency_dict[function.name] = set()
        if function.name != internal_call.name:
            dependency_dict[function.name].add(internal_call.name)
        dependency_graph.add_nodes_from([function.name, internal_call.name])
        if function.name != internal_call.name:
            dependency_graph.add_edge(function.name, internal_call.name)

    elif isinstance(internal_call, (SolidityFunction)):
        solidity_functions.add(
            _node(_solidity_function_node(internal_call)),
        )
        solidity_calls.add(
            _edge(
                _function_node(contract, function),
                _solidity_function_node(internal_call),
            )
        )
        if function.name not in dependency_dict:
            dependency_dict[function.name] = set()
        if function.name != internal_call.name:
            dependency_dict[function.name].add(internal_call.name)
        dependency_graph.add_nodes_from([function.name, internal_call.name])
        if function.name != internal_call.name:
            dependency_graph.add_edge(function.name, internal_call.name)


def _render_external_calls(external_calls: Set[str]) -> str:
    return "\n".join(external_calls)


def _render_internal_calls(
        contract: Contract,
        contract_functions: Dict[Contract, Set[str]],
        contract_calls: Dict[Contract, Set[str]],
) -> str:
    lines = []

    lines.append(f"subgraph {_contract_subgraph(contract)} {{")
    lines.append(f'label = "{contract.name}"')

    lines.extend(contract_functions[contract])
    lines.extend(contract_calls[contract])

    lines.append("}")

    return "\n".join(lines)


def _render_solidity_calls(solidity_functions: Set[str], solidity_calls: Set[str]) -> str:
    lines = []

    lines.append("subgraph cluster_solidity {")
    lines.append('label = "[Solidity]"')

    lines.extend(solidity_functions)
    lines.extend(solidity_calls)

    lines.append("}")

    return "\n".join(lines)


def _process_external_call(
        contract: Contract,
        function: Function,
        external_call: Tuple[Contract, Union[Function, Variable]],
        contract_functions: Dict[Contract, Set[str]],
        external_calls: Set[str],
        all_contracts: Set[Contract],
        dependency_dict: Dict[str, Set[str]],
        dependency_graph,
) -> None:
    external_contract, external_function = external_call

    if not external_contract in all_contracts:
        return

    # add variable as node to respective contract
    if isinstance(external_function, (Variable)):
        contract_functions[external_contract].add(
            _node(
                _function_node(external_contract, external_function),
                external_function.name,
            )
        )

    external_calls.add(
        _edge(
            _function_node(contract, function),
            _function_node(external_contract, external_function),
        )
    )
    if function.name not in dependency_dict:
        dependency_dict[function.name] = set()
    if function.name != external_function.name:
        dependency_dict[function.name].add(external_function.name)
    dependency_graph.add_nodes_from([function.name, external_function.name])
    if function.name != external_function.name:
        dependency_graph.add_edge(function.name, external_function.name)


# pylint: disable=too-many-arguments
def _process_function(
        contract: Contract,
        function: Function,
        contract_functions: Dict[Contract, Set[str]],
        contract_calls: Dict[Contract, Set[str]],
        solidity_functions: Set[str],
        solidity_calls: Set[str],
        external_calls: Set[str],
        all_contracts: Set[Contract],
        dependency_dict: Dict[str, Set[str]],
        dependency_graph
) -> None:
    contract_functions[contract].add(
        _node(_function_node(contract, function), function.name),
    )

    for internal_call in function.internal_calls:
        _process_internal_call(
            contract,
            function,
            internal_call,
            contract_calls,
            solidity_functions,
            solidity_calls,
            dependency_dict,
            dependency_graph,
        )
    for external_call in function.high_level_calls:
        _process_external_call(
            contract,
            function,
            external_call,
            contract_functions,
            external_calls,
            all_contracts,
            dependency_dict,
            dependency_graph,
        )


def _process_functions(functions: Sequence[Function], dependency_list, dependency_graph) -> str:
    # TODO  add support for top level function

    contract_functions: Dict[Contract, Set[str]] = defaultdict(
        set
    )  # contract -> contract functions nodes
    contract_calls: Dict[Contract, Set[str]] = defaultdict(set)  # contract -> contract calls edges

    solidity_functions: Set[str] = set()  # solidity function nodes
    solidity_calls: Set[str] = set()  # solidity calls edges
    external_calls: Set[str] = set()  # external calls edges

    all_contracts = set()

    for function in functions:
        if isinstance(function, FunctionContract):
            all_contracts.add(function.contract_declarer)
    for function in functions:
        if isinstance(function, FunctionContract):
            _process_function(
                function.contract_declarer,
                function,
                contract_functions,
                contract_calls,
                solidity_functions,
                solidity_calls,
                external_calls,
                all_contracts,
                dependency_list,
                dependency_graph
            )

    render_internal_calls = ""
    for contract in all_contracts:
        render_internal_calls += _render_internal_calls(
            contract, contract_functions, contract_calls
        )

    render_solidity_calls = _render_solidity_calls(solidity_functions, solidity_calls)

    render_external_calls = _render_external_calls(external_calls)

    return render_internal_calls + render_solidity_calls + render_external_calls


# T2:Inconsistency Behavior
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
    dependency_relation = {}
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
            crosschainreceivesiglist: List,
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
            # if nx.has_path(XGRAPH, function.name, "ecrecover(bytes32,uint8,bytes32,bytes32)"):
            #     continue

            # Check for any events in the function and skip if found
            # Note: not checking if event corresponds to critical parameter

            # if not any(ir for node in function.nodes for ir in node.irs if isinstance(ir, EventCall)):
            #     results.append(function)
            #     continue

            # eventSendNodeList = []
            # all_conditional_state_var = function.all_conditional_state_variables_read()
            potential_process_call = []
            vulnerable_process_call = []
            missing_check_process_call = {}

            for node in function.nodes:
                slithir_operation = []
                for inter_call in node.internal_calls:
                    if isinstance(inter_call, Function):
                        slithir_operation += inter_call.all_slithir_operations()

                for ir in node.irs + slithir_operation:
                    if isinstance(ir, HighLevelCall) or isinstance(ir, LowLevelCall):
                        if not len(node.local_variables_read) == 0:
                            for var in node.local_variables_read:
                                if is_tainted(var, function) and node not in potential_process_call:
                                    potential_process_call.append(node)
                # for internal_call in node.internal_calls:
                #     if isinstance(internal_call, Function):
                #         for internal_node in internal_call.all_nodes():
                #             if len(internal_node.high_level_calls) or len(internal_node.low_level_calls):
                #                 potential_process_call.add(node)

            # missing_check_process_call = copy.deepcopy(potential_process_call)

            # while len(potential_process_call) > 0:
            #     potential_process_call_len = len(potential_process_call)

            for call in potential_process_call:
                if call not in missing_check_process_call:
                    missing_check_process_call[call] = False
                for dominator in call.dominators:
                    if dominator.is_conditional():
                        if len(dominator.state_variables_read) and not any(
                                state for state in dominator.state_variables_read if is_tainted(state, contract, True)):
                            # if call in missing_check_process_call:
                            missing_check_process_call[call] = True
                        # if :
                        #     if not call in vulnerable_process_call:
                        #         vulnerable_process_call.add(call)

                    for ir in dominator.irs:
                        if isinstance(ir, SolidityCall) and ir.function == SolidityFunction(
                                "ecrecover(bytes32,uint8,bytes32,bytes32)"):
                            if call in missing_check_process_call:
                                missing_check_process_call[call] = True
                        if isinstance(ir, InternalCall) and "ecrecover(bytes32,uint8,bytes32,bytes32)" in list(XGRAPH.nodes):
                            if nx.has_path(XGRAPH, ir.function.name,
                                           "ecrecover(bytes32,uint8,bytes32,bytes32)") and call in missing_check_process_call:
                                # if ir.function == SolidityFunction("ecrecover(bytes32,uint8,bytes32,bytes32)") and call in missing_check_process_call:
                                if call in missing_check_process_call:
                                    missing_check_process_call[call] = True

            for key in missing_check_process_call.keys():
                if not missing_check_process_call[key]:
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
        for derived_contract in self.slither.contracts_derived:
            _process_functions(derived_contract.functions, self.dependency_relation, XGRAPH)

        for contract in self.compilation_unit.contracts_derived:
            missing_crosschain_data_checks = self._detect_missing_crosschain_data_check(contract,
                                                                                        self.CROSSCHAINRECEIVESIGLIST,
                                                                                        self.CROSSCHAINRECEIVEEVENTLIST)
            for function in missing_crosschain_data_checks:
                info: DETECTOR_INFO = ["Missing Crosschain Check ", function, "\n"]
                res = self.generate_result(info)
                results.append(res)
        return results

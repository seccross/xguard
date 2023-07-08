import networkx as nx
# def _init():
#     global CROSSCHAINSENDSIGLIST
#
#     global CROSSCHAINRECEIVESIGLIST
#
#     global CROSSCHAINSENDEVENTLIST
#     ST
#     global CROSSCHAINRECEIVEEVENTLI


    # For Polygon
# GCROSSCHAINSENDSIGLIST = ["lockTokens(address,address,address,bytes)"]
# GCROSSCHAINRECEIVESIGLIST = ["exitTokens(address,address,bytes)", "receive2(address,address,uint256)"]
# GCROSSCHAINSENDEVENTLIST = ["LockedEther", "eventsend2"]
# GCROSSCHAINRECEIVEEVENTLIST = ["ExitedEther", "eventreceive2"]



    # For cBridgev2
# GCROSSCHAINSENDSIGLIST = ["send(address,address,uint256,uint64,uint64,uint32)", "sendNative(address,uint256,uint64,uint64,uint32)"]
# GCROSSCHAINRECEIVESIGLIST = ["relay(bytes,bytes[],address[],uint256[])"]
# GCROSSCHAINSENDEVENTLIST = ["Send"]
# GCROSSCHAINRECEIVEEVENTLIST = ["Relay"]
# XGRAPH = nx.Graph()
    #
GCROSSCHAINSENDSIGLIST = ["send(address,address,address,uint256,uint256)", "sendNative(address,uint256,uint64,uint64,uint32)"]
GCROSSCHAINRECEIVESIGLIST = ["relay(bytes,bytes[],address[],uint256[])"]
GCROSSCHAINSENDEVENTLIST = ["eventsend2"]
GCROSSCHAINRECEIVEEVENTLIST = ["Relay"]
XGRAPH = nx.Graph()

# def get_crosschain_send_sig_list():
#     return CROSSCHAINSENDSIGLIST
#
#
# def get_crosschain_receive_sig_list():
#     return CROSSCHAINRECEIVESIGLIST
#
#
# def get_crosschain_send_event_list():
#     return CROSSCHAINSENDEVENTLIST
#
#
# def get_crosschain_receive_event_list():
#     return CROSSCHAINRECEIVEEVENTLIST


# def _init():
#     global CROSSCHAINSENDSIGLIST
#
#     global CROSSCHAINRECEIVESIGLIST
#
#     global CROSSCHAINSENDEVENTLIST
#     ST
#     global CROSSCHAINRECEIVEEVENTLI


    # For Polygon
GCROSSCHAINSENDSIGLIST = ["lockTokens(address,address,address,bytes)"]
GCROSSCHAINRECEIVESIGLIST = ["exitTokens(address,address,bytes)", "receive2(address,address,uint256)"]
GCROSSCHAINSENDEVENTLIST = ["LockedEther", "eventsend2"]
GCROSSCHAINRECEIVEEVENTLIST = ["ExitedEther", "eventreceive2"]

    #


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

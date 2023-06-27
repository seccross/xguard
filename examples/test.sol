

pragma solidity 0.5.0;

//library SafeERC20 {
//    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {}
//}
//
//interface IERC20 {
//    function transferFrom(address, address, uint256) external returns(bool);
//}

contract ERC20 {
     mapping(address => uint256) private _balances;
    function transferFrom(address from, address to, uint256 amount) external returns(bool) {
        _balances[from] = _balances[from] - amount;
        _balances[to] = _balances[to] + amount;
        return true;
    }
}

contract C {
//    using SafeERC20 for IERC20;

    ERC20 erc20;
    address notsend;
    address sender;

    event eventsend(address, address, uint);

    event eventsend2(address, address, uint);

    event eventreceive(address, address, uint);

    event eventreceive2(address, address, uint);

    constructor() public {
        erc20 = new ERC20();
        notsend = address(0x3);
        sender = msg.sender;
    }

//    function good1(address to, uint256 am) public {
//        address from_msgsender = msg.sender;
//        erc20.transferFrom(from_msgsender, to, am);
//    }
//
//    function bad1(address to, uint256 am) public {
//        erc20.transferFrom(notsend, to, am);
//    }
//
//    function good2(address to, uint256 am) public {
//        address from_msgsender = msg.sender;
//        int_transferFrom(from_msgsender, to, am);
//    }

    function send(address from, address to, uint256 am) public payable{
        if (from == sender)
        {
//            if (to == send)
//            {
//                return;
//            }
         erc20.transferFrom(from, to, am);

        }
        emit eventsend2(from, to, am);

    }

    function receive(address from, address to, uint256 am) public {
        if(msg.sender == sender)
        {
            erc20.transferFrom(from, to, am);
            emit eventreceive(from, to, am);
        }

        emit eventreceive2(from, to, am);
    }


    // This is not detected
//    function bad2(address from, address to, uint256 am) public {
//        int_transferFrom(from, to, am);
//    }
//
//    function int_transferFrom(address from, address to, uint256 amount) internal {
//        erc20.transferFrom(from, to, amount);
//    }
//
//    function good3(address to, uint256 amount) external {
//        erc20.safeTransferFrom(msg.sender, to, amount);
//    }
//
//    function bad3(address from, address to, uint256 amount) external {
//        erc20.safeTransferFrom(from, to, amount);
//    }
//
//    function good4(address to, uint256 amount) external {
//        SafeERC20.safeTransferFrom(erc20, msg.sender, to, amount);
//    }
//
//    function bad4(address from, address to, uint256 amount) external {
//        SafeERC20.safeTransferFrom(erc20, from, to, amount);
//    }
//
//    function good5(address to, uint256 amount) external {
//        SafeERC20.safeTransferFrom(erc20, address(this), to, amount);
//    }
//
//    function good6(address from, address to, uint256 amount) external {
//        erc20.safeTransferFrom(address(this), to, amount);
//    }

}

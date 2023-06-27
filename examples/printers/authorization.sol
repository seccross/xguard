contract Owner{

    address a;

    modifier onlyOwner(){
        require(msg.sender == a);
        _;
    }

}

contract MyContract is Owner{

    mapping(address => uint) balances;

    constructor() public{
        a = msg.sender;
    }

    function mint(uint value) onlyOwner public{
        balances[msg.sender] += value;
    }    

}

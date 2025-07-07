contract Example {
    uint256 public constant bar = 10;
    uint256 public rate = 1;
    mapping(address => uint256) public balances;

    constructor() payable {}
    
    function increase(uint256 x) public {
        require(x <= rate);
        rate += 1;
    }

    function decrease(uint256 x) public {
        require(x >= rate);
        rate -= 1;
    }

    function deposit() payable public {
        balances[msg.sender] += msg.value;
    }

    function withdraw() public {
        uint256 amount = (rate * balances[msg.sender])/bar;
        // uint256 amount = balances[msg.sender] * (rate / bar);
        payable(msg.sender).transfer(amount);
        balances[msg.sender] = 0;
    }
}
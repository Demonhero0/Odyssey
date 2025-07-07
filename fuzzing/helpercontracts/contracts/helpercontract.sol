interface IUniswapV2Router {
    function swapETHForExactTokens(uint amountOut, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts);
    function swapExactETHForTokens(uint amountOutMin, address[] calldata path, address to, uint deadline) external payable returns (uint[] memory amounts);
    function factory() external view returns (address);
}

interface IUniswapV2Factory {
    function getPair(address, address) external view returns (address);
}

interface IUniswapV1Factory {
    function getExchange(address) external view returns (address);
}

interface IERC1820Registry {
    function setInterfaceImplementer(address _addr, bytes32 _interfaceHash, address _implementer) external;
    function getInterfaceImplementer(address _addr, bytes32 _interfaceHash) external returns (address);
}

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
    function transferFrom(address, address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

interface IUniswapV1Pair {
    function getTokenToEthInputPrice(uint256) external view returns (uint256);
    function ethToTokenSwapInput(uint256, uint256) payable external returns (uint256);
    function tokenToEthSwapInput(uint256 tokens_sold, uint256 min_eth, uint256 deadline) external returns (uint256);
}

interface IUniswapV2Pair {
    event Approval(address indexed owner, address indexed spender, uint value);
    event Transfer(address indexed from, address indexed to, uint value);

    function name() external pure returns (string memory);
    function symbol() external pure returns (string memory);
    function decimals() external pure returns (uint8);
    function totalSupply() external view returns (uint);
    function balanceOf(address owner) external view returns (uint);
    function allowance(address owner, address spender) external view returns (uint);

    function approve(address spender, uint value) external returns (bool);
    function transfer(address to, uint value) external returns (bool);
    function transferFrom(address from, address to, uint value) external returns (bool);

    function DOMAIN_SEPARATOR() external view returns (bytes32);
    function PERMIT_TYPEHASH() external pure returns (bytes32);
    function nonces(address owner) external view returns (uint);

    function permit(address owner, address spender, uint value, uint deadline, uint8 v, bytes32 r, bytes32 s) external;

    event Mint(address indexed sender, uint amount0, uint amount1);
    event Burn(address indexed sender, uint amount0, uint amount1, address indexed to);
    event Swap(
        address indexed sender,
        uint amount0In,
        uint amount1In,
        uint amount0Out,
        uint amount1Out,
        address indexed to
    );
    event Sync(uint112 reserve0, uint112 reserve1);

    function MINIMUM_LIQUIDITY() external pure returns (uint);
    function factory() external view returns (address);
    function token0() external view returns (address);
    function token1() external view returns (address);
    function getReserves() external view returns (uint112 reserve0, uint112 reserve1, uint32 blockTimestampLast);
    function price0CumulativeLast() external view returns (uint);
    function price1CumulativeLast() external view returns (uint);
    function kLast() external view returns (uint);

    function mint(address to) external returns (uint liquidity);
    function burn(address to) external returns (uint amount0, uint amount1);
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function skim(address to) external;
    function sync() external;

    function initialize(address, address) external;
}

library SafeMath {
    function add(uint x, uint y) internal pure returns (uint z) {
        require((z = x + y) >= x, 'ds-math-add-overflow');
    }

    function sub(uint x, uint y) internal pure returns (uint z) {
        require((z = x - y) <= x, 'ds-math-sub-underflow');
    }

    function mul(uint x, uint y) internal pure returns (uint z) {
        require(y == 0 || (z = x * y) / y == x, 'ds-math-mul-overflow');
    }
}

library UniswapV2Library {
    using SafeMath for uint;

    // returns sorted token addresses, used to handle return values from pairs sorted in this order
    function sortTokens(address tokenA, address tokenB) internal pure returns (address token0, address token1) {
        require(tokenA != tokenB, 'UniswapV2Library: IDENTICAL_ADDRESSES');
        (token0, token1) = tokenA < tokenB ? (tokenA, tokenB) : (tokenB, tokenA);
        require(token0 != address(0), 'UniswapV2Library: ZERO_ADDRESS');
    }

    // calculates the CREATE2 address for a pair without making any external calls
    function pairFor(address factory, address tokenA, address tokenB) internal pure returns (address pair) {
        (address token0, address token1) = sortTokens(tokenA, tokenB);
        pair = address(uint160(uint(keccak256(abi.encodePacked(
                hex'ff',
                factory,
                keccak256(abi.encodePacked(token0, token1)),
                hex'96e8ac4277198ff8b6f785478aa9a39f403cb768dd02cbee326c3e7da348845f' // init code hash
            )))));
    }

    // fetches and sorts the reserves for a pair
    function getReserves(address factory, address tokenA, address tokenB) internal view returns (uint reserveA, uint reserveB) {
        (address token0,) = sortTokens(tokenA, tokenB);
        (uint reserve0, uint reserve1,) = IUniswapV2Pair(pairFor(factory, tokenA, tokenB)).getReserves();
        (reserveA, reserveB) = tokenA == token0 ? (reserve0, reserve1) : (reserve1, reserve0);
    }

    // given some amount of an asset and pair reserves, returns an equivalent amount of the other asset
    function quote(uint amountA, uint reserveA, uint reserveB) internal pure returns (uint amountB) {
        require(amountA > 0, 'UniswapV2Library: INSUFFICIENT_AMOUNT');
        require(reserveA > 0 && reserveB > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
        amountB = amountA.mul(reserveB) / reserveA;
    }

    // given an input amount of an asset and pair reserves, returns the maximum output amount of the other asset
    function getAmountOut(uint amountIn, uint reserveIn, uint reserveOut) internal pure returns (uint amountOut) {
        require(amountIn > 0, 'UniswapV2Library: INSUFFICIENT_INPUT_AMOUNT');
        require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
        uint amountInWithFee = amountIn.mul(997);
        uint numerator = amountInWithFee.mul(reserveOut);
        uint denominator = reserveIn.mul(1000).add(amountInWithFee);
        amountOut = numerator / denominator;
    }

    // given an output amount of an asset and pair reserves, returns a required input amount of the other asset
    function getAmountIn(uint amountOut, uint reserveIn, uint reserveOut) internal pure returns (uint amountIn) {
        require(amountOut > 0, 'UniswapV2Library: INSUFFICIENT_OUTPUT_AMOUNT');
        require(reserveIn > 0 && reserveOut > 0, 'UniswapV2Library: INSUFFICIENT_LIQUIDITY');
        uint numerator = reserveIn.mul(amountOut).mul(1000);
        uint denominator = reserveOut.sub(amountOut).mul(997);
        amountIn = (numerator / denominator).add(1);
    }

    // performs chained getAmountOut calculations on any number of pairs
    function getAmountsOut(address factory, uint amountIn, address[] memory path) internal view returns (uint[] memory amounts) {
        require(path.length >= 2, 'UniswapV2Library: INVALID_PATH');
        amounts = new uint[](path.length);
        amounts[0] = amountIn;
        for (uint i; i < path.length - 1; i++) {
            (uint reserveIn, uint reserveOut) = getReserves(factory, path[i], path[i + 1]);
            amounts[i + 1] = getAmountOut(amounts[i], reserveIn, reserveOut);
        }
    }

    // performs chained getAmountIn calculations on any number of pairs
    function getAmountsIn(address factory, uint amountOut, address[] memory path) internal view returns (uint[] memory amounts) {
        require(path.length >= 2, 'UniswapV2Library: INVALID_PATH');
        amounts = new uint[](path.length);
        amounts[amounts.length - 1] = amountOut;
        for (uint i = path.length - 1; i > 0; i--) {
            (uint reserveIn, uint reserveOut) = getReserves(factory, path[i - 1], path[i]);
            amounts[i - 1] = getAmountIn(amounts[i], reserveIn, reserveOut);
        }
    }
}

contract Utils {
    using SafeMath for uint;
    function swapExactTokensForETHWithUniswapV2(address token, uint256 amountIn) external view returns (uint256) {
        address wethAddress = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2; // weth
        // IUniswapV2 v2 = IUniswapV2(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
        // address factory = v2.factory();
        address factory = 0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f; // v2 factory
        (uint reserveIn, uint reserveOut) = UniswapV2Library.getReserves(factory, token, wethAddress);
        uint256 amount = UniswapV2Library.getAmountOut(amountIn, reserveIn, reserveOut);
        return amount;
    }

    function swapExactTokensForETHWithUniswapV1(address token, uint256 amountIn) external view returns (uint256) {
        IUniswapV1Factory factory = IUniswapV1Factory(0xc0a47dFe034B400B47bDaD5FecDa2621de6c4d95);
        address pairAddress = factory.getExchange(token);
        if (pairAddress == address(0x00)) {
            return 0;
        }
        IUniswapV1Pair pair = IUniswapV1Pair(pairAddress);
        uint256 amount = pair.getTokenToEthInputPrice(amountIn);
        return amount;
    }

    function swapTest(address token, uint256 amount) payable external returns (uint256) {
        IUniswapV1Factory factory = IUniswapV1Factory(0xc0a47dFe034B400B47bDaD5FecDa2621de6c4d95);
        address pairAddress = factory.getExchange(token);
        if (pairAddress == address(0x00)) {
            return 0;
        }
        IUniswapV1Pair pair = IUniswapV1Pair(pairAddress);
        pair.ethToTokenSwapInput{value: msg.value}(1, 1587681607);
    }
}

contract HelperContractOffChain {

}

contract HelperContract {
    address public owner;

    constructor (address[] memory targetAddresses) payable {
        owner = msg.sender;
        approveForTargetAddresses(targetAddresses);
        swapTokens(targetAddresses);

        if (isContract(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24)) {
            IERC1820Registry _erc1820 = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);
            _erc1820.setInterfaceImplementer(address(this), keccak256("ERC777TokensSender"), address(this));
            _erc1820.setInterfaceImplementer(address(this), keccak256("ERC777TokensRecipient"), address(this));
            _erc1820.setInterfaceImplementer(address(this), keccak256("ERC20Token"), address(this));
            _erc1820.setInterfaceImplementer(address(this), keccak256("ERC777Token"), address(this));
        }
    }

    function approveForTargetAddresses(address[] memory targetAddresses) internal {
        for(uint i=0; i < targetAddresses.length; i ++) {
            address targetAddress = targetAddresses[i];
            for (uint j=0; j < targetAddresses.length; j ++) {
                targetAddresses[j].call(abi.encodeWithSelector(IERC20.approve.selector, targetAddress, type(uint256).max));
            }
        }
    } 

    function swapTokens(address[] memory targetAddresses) public payable {
        address wethAddress = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;
        IUniswapV2Factory factoryV2;
        IUniswapV2Router routerV2;
        bool existV2;
        if (isContract(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D)) {
            routerV2 = IUniswapV2Router(0x7a250d5630B4cF539739dF2C5dAcb4c659F2488D);
            factoryV2 = IUniswapV2Factory(routerV2.factory());
            existV2 = true;
        }

        IUniswapV1Factory factoryV1;
        bool existV1;
        if (isContract(0xc0a47dFe034B400B47bDaD5FecDa2621de6c4d95)) {
            factoryV1 = IUniswapV1Factory(0xc0a47dFe034B400B47bDaD5FecDa2621de6c4d95);
            existV1 = true;
        }
        
        for(uint i=0; i < targetAddresses.length; i++) {
            // uniswap v2
            address tokenAddress = targetAddresses[i];
            if (existV2) {
                address pair2Addr = factoryV2.getPair(wethAddress, tokenAddress);
                if (pair2Addr != address(0x00)) {
                    IUniswapV2Pair pairContract = IUniswapV2Pair(pair2Addr);
                    if (pairContract.totalSupply() > 0) {
                        address[] memory path = new address[](2);
                        path[0] = wethAddress;
                        path[1] = tokenAddress;
                        routerV2.swapExactETHForTokens{value: 5 ether}(0, path, address(this), block.timestamp + 1);
                        routerV2.swapExactETHForTokens{value: 5 ether}(0, path, msg.sender, block.timestamp + 1);
                    }
                }
            } else if (existV1) {
                address pairAddress = factoryV1.getExchange(tokenAddress);
                if (pairAddress != address(0x00)) {
                    uint256 amount = IUniswapV1Pair(pairAddress).ethToTokenSwapInput{value: 10 ether}(1, block.timestamp + 1);
                    IERC20(tokenAddress).transfer(msg.sender, amount/2);
                }
            }
        }
    }

    function isContract(address addr) internal view returns (bool) {
        uint256 size;
        assembly { size := extcodesize(addr) }
        return size > 0;
    }

    function approve(address tokenAddr, address spender) payable external {
        IERC20 token = IERC20(tokenAddr);
        token.approve(spender, type(uint256).max);
    }

    function sendMsgUtil(address to, bytes memory data) payable external returns (bool) {
        (bool success, ) = to.call{value: msg.value}(data);
        if (!success) {
            revert("revert contract call");
        }
        return success;
    } 

    function tokensToSend(address, address, address, uint256, bytes calldata, bytes calldata) external {

    }

    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external {

    }

    receive() external payable {}
}
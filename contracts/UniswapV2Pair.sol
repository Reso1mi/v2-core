pragma solidity =0.5.16;

import {UniswapV2ERC20} from "./UniswapV2ERC20.sol";
import {IERC20} from "./interfaces/IERC20.sol";
import {IUniswapV2Callee} from "./interfaces/IUniswapV2Callee.sol";
import {IUniswapV2Factory} from "./interfaces/IUniswapV2Factory.sol";
import {IUniswapV2Pair} from "./interfaces/IUniswapV2Pair.sol";
import {Math} from "./libraries/Math.sol";
import {SafeMath} from "./libraries/SafeMath.sol";
import {UQ112x112} from "./libraries/UQ112x112.sol";

/**
 * @title UniswapV2Pair
 * @notice Uniswap V2 交易对合约
 * @dev 实现恒定乘积做市商 (CPMM) 公式：x * y = k
 *
 * 核心功能：
 * 1. 流动性管理 (mint/burn)
 * 2. 代币交换 (swap) - 支持 Flash Swap（闪电贷）
 * 3. 价格预言机 (TWAP)
 * 4. 手续费收取
 */
contract UniswapV2Pair is IUniswapV2Pair, UniswapV2ERC20 {
    using SafeMath  for uint;
    using UQ112x112 for uint224;

    /// @notice 最小流动性数量（永久锁定，防止首次铸造攻击）
    uint public constant MINIMUM_LIQUIDITY = 10**3;

    /// @notice transfer 函数选择器，用于安全转账
    bytes4 private constant SELECTOR = bytes4(keccak256(bytes('transfer(address,uint256)')));

    /// @notice 工厂合约地址
    address public factory;

    /// @notice 交易对的两个代币地址（按地址大小排序，token0 < token1）
    address public token0;
    address public token1;

    /**
     * @notice 储备量（使用单个存储槽优化）
     * @dev reserve0 和 reserve1 各 112 位，blockTimestampLast 32 位
     *      总共 256 位（1 个存储槽）
     */
    uint112 private reserve0;           // token0 储备量
    uint112 private reserve1;           // token1 储备量
    uint32  private blockTimestampLast; // 上次更新储备量的区块时间戳

    /**
     * @notice 价格累计值（用于 TWAP 预言机）
     * @dev price0CumulativeLast: Σ(reserve1 / reserve0) * timeElapsed
     *      price1CumulativeLast: Σ(reserve0 / reserve1) * timeElapsed
     */
    uint public price0CumulativeLast;
    uint public price1CumulativeLast;

    /**
     * @notice 上次流动性操作时的 K 值（reserve0 * reserve1）
     * @dev 用于协议手续费计算，仅在手续费开启时使用
     */
    uint public kLast;

    /**
     * @notice 重入锁状态（1=未锁定，0=已锁定）
     * @dev 防止重入攻击，特别是在回调期间
     */
    uint private unlocked = 1;

    /**
     * @notice 重入锁修饰器
     * @dev 为什么需要重入锁？
     *      因为 Pool 使用余额检查来验证支付：
     *      1. 记录转账前余额/储备量
     *      2. 调用回调函数（外部调用！）
     *      3. 检查转账后余额
     *
     *      如果没有重入锁，恶意合约可以在回调中再次调用 Pool，
     *      导致余额检查失效。
     */
    modifier lock() {
        require(unlocked == 1, 'UniswapV2: LOCKED');  // 检查是否已锁定
        unlocked = 0;                                 // 上锁
        _;                                            // 执行函数
        unlocked = 1;                                 // 解锁
    }

    /**
     * @notice 获取当前储备量和时间戳
     * @return _reserve0 token0 储备量
     * @return _reserve1 token1 储备量
     * @return _blockTimestampLast 上次更新的时间戳
     */
    function getReserves() public view returns (uint112 _reserve0, uint112 _reserve1, uint32 _blockTimestampLast) {
        _reserve0 = reserve0;
        _reserve1 = reserve1;
        _blockTimestampLast = blockTimestampLast;
    }

    /**
     * @notice 安全转账（兼容非标准 ERC20）
     * @param token 代币地址
     * @param to 接收地址
     * @param value 转账金额
     * @dev 使用低级 call 而非 transfer，兼容返回值不标准的代币
     */
    function _safeTransfer(address token, address to, uint value) private {
        (bool success, bytes memory data) = token.call(abi.encodeWithSelector(SELECTOR, to, value));
        require(success && (data.length == 0 || abi.decode(data, (bool))), 'UniswapV2: TRANSFER_FAILED');
    }

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

    /**
     * @notice 构造函数
     * @dev 工厂合约部署此合约，msg.sender 是工厂地址
     */
    constructor() public {
        factory = msg.sender;
    }

    /**
     * @notice 初始化交易对（由工厂合约调用一次）
     * @param _token0 第一个代币地址（较小的地址）
     * @param _token1 第二个代币地址（较大的地址）
     * @dev 只能由工厂合约调用，且只能调用一次
     */
    // called once by the factory at time of deployment
    function initialize(address _token0, address _token1) external {
        require(msg.sender == factory, 'UniswapV2: FORBIDDEN'); // sufficient check
        token0 = _token0;
        token1 = _token1;
    }

    /**
     * @notice 更新储备量和价格累计值
     * @param balance0 当前 token0 余额
     * @param balance1 当前 token1 余额
     * @param _reserve0 更新前的 token0 储备量
     * @param _reserve1 更新前的 token1 储备量
     * @dev
     *      1. 检查余额溢出（不能超过 uint112 最大值）
     *      2. 如果是区块内首次调用，更新价格累计值（TWAP 预言机）
     *      3. 更新储备量
     */
    // update reserves and, on the first call per block, price accumulators
    function _update(uint balance0, uint balance1, uint112 _reserve0, uint112 _reserve1) private {
        require(balance0 <= uint112(-1) && balance1 <= uint112(-1), 'UniswapV2: OVERFLOW');
        uint32 blockTimestamp = uint32(block.timestamp % 2**32);
        uint32 timeElapsed = blockTimestamp - blockTimestampLast; // overflow is desired

        // 只有在时间流逝且储备量非零时才更新价格累计值
        if (timeElapsed > 0 && _reserve0 != 0 && _reserve1 != 0) {
            // * never overflows, and + overflow is desired
            // price0 = reserve1 / reserve0 (每个 token0 值多少 token1)
            price0CumulativeLast += uint(UQ112x112.encode(_reserve1).uqdiv(_reserve0)) * timeElapsed;
            // price1 = reserve0 / reserve1 (每个 token1 值多少 token0)
            price1CumulativeLast += uint(UQ112x112.encode(_reserve0).uqdiv(_reserve1)) * timeElapsed;
        }

        reserve0 = uint112(balance0);
        reserve1 = uint112(balance1);
        blockTimestampLast = blockTimestamp;
        emit Sync(reserve0, reserve1);
    }

    /**
     * @notice 如果协议手续费开启，铸造手续费流动性给协议
     * @param _reserve0 当前 token0 储备量
     * @param _reserve1 当前 token1 储备量
     * @return feeOn 手续费是否开启
     * @dev
     *      协议手续费 = 流动性增长的 1/6
     *      计算公式：liquidity = totalSupply * (rootK - rootKLast) / (rootK * 5 + rootKLast)
     */
    // if fee is on, mint liquidity equivalent to 1/6th of the growth in sqrt(k)
    function _mintFee(uint112 _reserve0, uint112 _reserve1) private returns (bool feeOn) {
        address feeTo = IUniswapV2Factory(factory).feeTo();
        feeOn = feeTo != address(0);  // feeTo 不为零地址表示手续费开启

        uint _kLast = kLast; // gas savings

        if (feeOn) {
            if (_kLast != 0) {
                // 计算 K 值的平方根
                uint rootK = Math.sqrt(uint(_reserve0).mul(_reserve1));
                uint rootKLast = Math.sqrt(_kLast);

                // 只有 K 值增长时才收取手续费
                if (rootK > rootKLast) {
                    // 流动性增长量 * 1/6
                    uint numerator = totalSupply.mul(rootK.sub(rootKLast));
                    uint denominator = rootK.mul(5).add(rootKLast);
                    uint liquidity = numerator / denominator;

                    if (liquidity > 0) _mint(feeTo, liquidity);
                }
            }
        } else if (_kLast != 0) {
            // 手续费关闭时，重置 kLast
            kLast = 0;
        }
    }

    /**
     * @notice 铸造流动性代币（添加流动性）
     * @param to 接收流动性代币的地址
     * @return liquidity 铸造的流动性数量
     * @dev
     *      首次添加：liquidity = sqrt(amount0 * amount1) - MINIMUM_LIQUIDITY
     *      后续添加：liquidity = min(amount0 * totalSupply / reserve0, amount1 * totalSupply / reserve1)
     */
    // this low-level function should be called from a contract which performs important safety checks
    function mint(address to) external lock returns (uint liquidity) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves(); // gas savings
        uint balance0 = IERC20(token0).balanceOf(address(this));
        uint balance1 = IERC20(token1).balanceOf(address(this));

        // 计算存入的代币数量（当前余额 - 储备量）
        uint amount0 = balance0.sub(_reserve0);
        uint amount1 = balance1.sub(_reserve1);

        // 先处理协议手续费
        bool feeOn = _mintFee(_reserve0, _reserve1);
        uint _totalSupply = totalSupply; // gas savings, must be defined here since totalSupply can update in _mintFee

        if (_totalSupply == 0) {
            // 首次添加流动性
            liquidity = Math.sqrt(amount0.mul(amount1)).sub(MINIMUM_LIQUIDITY);
            // 永久锁定最小流动性，防止攻击者向空池发送代币后操纵价格
           _mint(address(0), MINIMUM_LIQUIDITY); // permanently lock the first MINIMUM_LIQUIDITY tokens
        } else {
            // 后续添加流动性：按比例计算
            // 取较小值确保两种代币按正确比例添加
            liquidity = Math.min(amount0.mul(_totalSupply) / _reserve0, amount1.mul(_totalSupply) / _reserve1);
        }

        require(liquidity > 0, 'UniswapV2: INSUFFICIENT_LIQUIDITY_MINTED');
        _mint(to, liquidity);

        _update(balance0, balance1, _reserve0, _reserve1);
        if (feeOn) kLast = uint(reserve0).mul(reserve1); // reserve0 and reserve1 are up-to-date
        emit Mint(msg.sender, amount0, amount1);
    }

    /**
     * @notice 销毁流动性代币（移除流动性）
     * @param to 接收代币的地址
     * @return amount0 收到的 token0 数量
     * @return amount1 收到的 token1 数量
     * @dev
     *      按流动性份额比例计算：
     *      amount0 = liquidity * balance0 / totalSupply
     *      amount1 = liquidity * balance1 / totalSupply
     */
    // this low-level function should be called from a contract which performs important safety checks
    function burn(address to) external lock returns (uint amount0, uint amount1) {
        (uint112 _reserve0, uint112 _reserve1,) = getReserves(); // gas savings
        address _token0 = token0;                                // gas savings
        address _token1 = token1;                                // gas savings

        uint balance0 = IERC20(_token0).balanceOf(address(this));
        uint balance1 = IERC20(_token1).balanceOf(address(this));
        uint liquidity = balanceOf[address(this)];

        // 先处理协议手续费
        bool feeOn = _mintFee(_reserve0, _reserve1);
        uint _totalSupply = totalSupply; // gas savings, must be defined here since totalSupply can update in _mintFee

        // 按份额比例计算应得的代币数量
        amount0 = liquidity.mul(balance0) / _totalSupply; // using balances ensures pro-rata distribution
        amount1 = liquidity.mul(balance1) / _totalSupply; // using balances ensures pro-rata distribution

        require(amount0 > 0 && amount1 > 0, 'UniswapV2: INSUFFICIENT_LIQUIDITY_BURNED');

        // 销毁流动性代币
        _burn(address(this), liquidity);

        // 转账给用户
        _safeTransfer(_token0, to, amount0);
        _safeTransfer(_token1, to, amount1);

        // 更新余额（转账后）
        balance0 = IERC20(_token0).balanceOf(address(this));
        balance1 = IERC20(_token1).balanceOf(address(this));

        _update(balance0, balance1, _reserve0, _reserve1);
        if (feeOn) kLast = uint(reserve0).mul(reserve1); // reserve0 and reserve1 are up-to-date
        emit Burn(msg.sender, amount0, amount1, to);
    }

    /**
     * @notice 代币交换（支持 Flash Swap 闪电贷）
     * @param amount0Out 要转出的 token0 数量
     * @param amount1Out 要转出的 token1 数量
     * @param to 接收代币的地址
     * @param data 回调数据（用于 Flash Swap）
     * @dev
     *      ====== Flash Swap 原理 ======
     *
     *      1. 检查参数：至少有一个输出 > 0
     *      2. 获取当前储备量 _reserve0, _reserve1
     *      3. 检查流动性：转出量必须小于储备量
     *      4. 乐观转账：先转出代币给接收者
     *      5. 回调：如果有 data，调用 uniswapV2Call
     *      6. 计算净输入量：amountIn = balance - (reserve - amountOut)
     *      7. K 值校验：扣除 0.3% 手续费后，K 值不能减少
     *
     *      ====== K 值校验详解 ======
     *
     *      balance0Adjusted = balance0 * 1000 - amount0In * 3
     *      balance1Adjusted = balance1 * 1000 - amount1In * 3
     *
     *      校验：balance0Adjusted * balance1Adjusted >= reserve0 * reserve1 * 1000²
     *
     *      含义：扣除 0.3% 手续费后 (3/1000)，K 值不能减少
     *
     */
    // this low-level function should be called from a contract which performs important safety checks
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external lock {
        // ====== 步骤1: 检查参数 ======
        require(amount0Out > 0 || amount1Out > 0, 'UniswapV2: INSUFFICIENT_OUTPUT_AMOUNT');

        // ====== 步骤2: 获取当前储备量 ======
        (uint112 _reserve0, uint112 _reserve1,) = getReserves(); // gas savings

        // ====== 步骤3: 检查有足够流动性 ======
        require(amount0Out < _reserve0 && amount1Out < _reserve1, 'UniswapV2: INSUFFICIENT_LIQUIDITY');

        uint balance0;
        uint balance1;
        { // scope for _token{0,1}, avoids stack too deep errors
        address _token0 = token0;
        address _token1 = token1;
        require(to != _token0 && to != _token1, 'UniswapV2: INVALID_TO');

        // ====== 步骤4: 乐观转账（Flash Swap 借出） ======
        if (amount0Out > 0) _safeTransfer(_token0, to, amount0Out); // optimistically transfer tokens
        if (amount1Out > 0) _safeTransfer(_token1, to, amount1Out); // optimistically transfer tokens

        // ====== 步骤5: 回调（Flash Swap 执行用户逻辑） ======
        if (data.length > 0) IUniswapV2Callee(to).uniswapV2Call(msg.sender, amount0Out, amount1Out, data);

        // ====== 步骤6: 获取回调后的余额 ======
        balance0 = IERC20(_token0).balanceOf(address(this));
        balance1 = IERC20(_token1).balanceOf(address(this));
        }

        // ====== 步骤7: 计算净输入量（用户归还的金额） ======
        // amount0In = balance0 - (_reserve0 - amount0Out)
        //           = balance0 - reserve0 + amount0Out
        //           = (归还后的余额 - 原始余额) + 借出量
        //           = 实际归还量
        uint amount0In = balance0 > _reserve0 - amount0Out ? balance0 - (_reserve0 - amount0Out) : 0;
        uint amount1In = balance1 > _reserve1 - amount1Out ? balance1 - (_reserve1 - amount1Out) : 0;

        // 至少要归还一些代币（不能只借不还）
        require(amount0In > 0 || amount1In > 0, 'UniswapV2: INSUFFICIENT_INPUT_AMOUNT');

        // ====== 步骤8: K 值校验（核心还款验证！） ======
        { // scope for reserve{0,1}Adjusted, avoids stack too deep errors
        // 调整后的余额 = 余额 * 1000 - 输入 * 3
        // 这样相当于扣除了 0.3% 的手续费 (3/1000)
        //
        // 数学推导：
        // 原始 K = reserve0 * reserve1
        // 扣除手续费后的 K = (reserve0 - amount0Out + amount0In * 0.997) * (reserve1 - amount1Out + amount1In * 0.997)
        //
        // 代码巧妙写法：
        // balance0Adjusted = balance0 * 1000 - amount0In * 3
        //                 = (reserve0 - amount0Out + amount0In) * 1000 - amount0In * 3
        //                 = reserve0 * 1000 - amount0Out * 1000 + amount0In * 997
        //                 = 1000 * (reserve0 - amount0Out + amount0In * 0.997)
        //
        // 校验条件：balance0Adjusted * balance1Adjusted >= reserve0 * reserve1 * 1000²
        // 两边同除以 1000²：(reserve0 - amount0Out + amount0In * 0.997) * (...) >= reserve0 * reserve1
        //
        // 含义：扣除 0.3% 手续费后，K 值不能减少！
        uint balance0Adjusted = balance0.mul(1000).sub(amount0In.mul(3));
        uint balance1Adjusted = balance1.mul(1000).sub(amount1In.mul(3));
        require(balance0Adjusted.mul(balance1Adjusted) >= uint(_reserve0).mul(_reserve1).mul(1000**2), 'UniswapV2: K');
        }

        // ====== 步骤9: 更新储备量 ======
        _update(balance0, balance1, _reserve0, _reserve1);

        // ====== 步骤10: 发出事件 ======
        emit Swap(msg.sender, amount0In, amount1In, amount0Out, amount1Out, to);
    }

    /**
     * @notice 强制余额匹配储备量（提取多余代币）
     * @param to 接收多余代币的地址
     * @dev
     *      当池子余额大于储备量时（如有人直接转账给池子），
     *      可以调用此函数提取差额。
     *
     *      用途：
     *      1. 修复由于直接转账导致的余额不一致
     *      2. 提取误转入池子的代币
     */
    // force balances to match reserves
    function skim(address to) external lock {
        address _token0 = token0; // gas savings
        address _token1 = token1; // gas savings
        _safeTransfer(_token0, to, IERC20(_token0).balanceOf(address(this)).sub(reserve0));
        _safeTransfer(_token1, to, IERC20(_token1).balanceOf(address(this)).sub(reserve1));
    }

    /**
     * @notice 强制储备量匹配余额（同步储备量）
     * @dev
     *      当池子余额被外部修改（如通过直接转账）后，
     *      调用此函数更新储备量以匹配当前余额。
     *
     *      用途：
     *      1. 修复由于直接转账导致的储备量不一致
     *      2. 确保 K 值计算使用正确的储备量
     */
    // force reserves to match balances
    function sync() external lock {
        _update(IERC20(token0).balanceOf(address(this)), IERC20(token1).balanceOf(address(this)), reserve0, reserve1);
    }
}
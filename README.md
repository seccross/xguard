# XGUARD: guard for cross-chain.

XGuard is a static static analyzer developed based on [*Slither*](https://github.com/crytic/slither), designed to detect inconsistency behaviors in cross-chain bridge contracts.

## Related works

[1]  [*Mythril*](https://github.com/Consensys/mythri) is a security analysis tool for EVM bytecode, It detects security vulnerabilities in smart contracts.

[2] [*Manticore*](https://ieeexplore.ieee.org/document/8952204) is a symbolic execution tool for the analysis of smart contracts and binaries. 

[3] [*Xscope*](https://dl.acm.org/doi/abs/10.1145/3551349.3559520)  defines three types of crosschain-specific security issues and proposes a tool to identify vulnerable crosschain bridges by analyzing corresponding historical crosschain transactions. 

[1] and [2] can only capture normal smart contract vulnerabilities, such as reentrancy and overflow, but fail to against crosschain-specific security issues. [3] requires a considerable number of crosschain transactions to identify the security of crosschain bridges and fails to identify the root cause of security issues in crosschain bridges and how it affects crosschain behavior. 

## How to install

> **Note** <br />
> Xguard requires Python 3.8+.
If you're **not** going to use one of the [supported compilation frameworks](https://github.com/crytic/crytic-compile), you need [solc](https://github.com/ethereum/solidity/), the Solidity compiler; we recommend using [solc-select](https://github.com/crytic/solc-select) to conveniently switch between solc versions.

```bash
pip3 install slither-analyzer
git clone git@github.com:seccross/xguard.git && cd xguard
python3 setup.py install
```

We recommend using a Python virtual environment, as detailed in the [Developer Installation Instructions](https://github.com/trailofbits/slither/wiki/Developer-installation), if you prefer to install XGuard via git.

## Usage

You can use it via command:

```bash
SEND_FUNCS='xxx;xxx' RECEIVE_FUNCS='xxx;xxxx' EVENTS='xxx;xxx' SEND_STORES='xxx;xxx' \
xguard bridge.sol \
--detect incomplete-event,incorrect-event,miss-crosschain-data-check,crosschain-message-injection
```

or use the online platform:

[xguard.sh](https://xguard.sh)
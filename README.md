# XGUARD: a static analyzer designed to detect inconsistency behaviors in cross-chain bridge contracts.

## How to install

> **Note** <br />
> Xguard requires Python 3.8+.
If you're **not** going to use one of the [supported compilation frameworks](https://github.com/crytic/crytic-compile), you need [solc](https://github.com/ethereum/solidity/), the Solidity compiler; we recommend using [solc-select](https://github.com/crytic/solc-select) to conveniently switch between solc versions.

```bash
git clone git@github.com:seccross/xguard.git && cd xguard
python3 setup.py install
```

We recommend using a Python virtual environment, as detailed in the [Developer Installation Instructions](https://github.com/trailofbits/slither/wiki/Developer-installation), if you prefer to install XGuard via git.


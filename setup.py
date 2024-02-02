from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as f:
    long_description = f.read()

setup(
    name="xguard-analyzer",
    description="XGuard is a static analyzer to find the inconsistency behavior of cross-chain bridges in the real world.",
    url="https://github.com/seccross/xguard",
    author="Trail of Bits",
    version="0.10.0",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[
        "packaging",
        "prettytable>=3.3.0",
        "pycryptodome>=3.4.6",
        "crytic-compile>=0.3.5,<0.4.0",
        # "crytic-compile@git+https://github.com/crytic/crytic-compile.git@master#egg=crytic-compile",
        "web3>=6.0.0",
        "eth-abi>=4.0.0",
        "eth-typing>=3.0.0",
        "eth-utils>=2.1.0",
    ],
    extras_require={
        "lint": [
            "black==22.3.0",
            "pylint==2.13.4",
        ],
        "test": [
            "pytest",
            "pytest-cov",
            "pytest-xdist",
            "deepdiff",
            "numpy",
            "coverage[toml]",
            "filelock",
            "pytest-insta",
        ],
        "doc": [
            "pdoc",
        ],
        "dev": [
            "slither-analyzer[lint,test,doc]",
            "openai",
        ],
    },
    license="AGPL-3.0",
    long_description=long_description,
    long_description_content_type="text/markdown",
    entry_points={
        "console_scripts": [
            "xguard = slither.__main__:main",
            "xguard-check-upgradeability = slither.tools.upgradeability.__main__:main",
            "xguard-find-paths = slither.tools.possible_paths.__main__:main",
            "xguard-simil = slither.tools.similarity.__main__:main",
            "xguard-flat = slither.tools.flattening.__main__:main",
            "xguard-format = slither.tools.slither_format.__main__:main",
            "xguard-check-erc = slither.tools.erc_conformance.__main__:main",
            "xguard-check-kspec = slither.tools.kspec_coverage.__main__:main",
            "xguard-prop = slither.tools.properties.__main__:main",
            "xguard-mutate = slither.tools.mutator.__main__:main",
            "xguard-read-storage = slither.tools.read_storage.__main__:main",
            "xguard-doctor = slither.tools.doctor.__main__:main",
            "xguard-documentation = slither.tools.documentation.__main__:main",
            "xguard-interface = slither.tools.interface.__main__:main",
        ]
    },
)

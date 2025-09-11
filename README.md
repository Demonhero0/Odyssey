# Odyssey

A state-aware fuzzer for smart contract.

## Setup

Prepare on-chain execution backend in `geth-onchain-execution`
```
unzip -o geth-onchain-execution.zip -d geth-onchain-execution
```

Installing "crytic-compile"
```
pip install crytic-compile
```

## Usage

Building the project
```
bash build.sh
```

### Running fuzzer off-chain

In this way, the tool first compiles the target contract and deploys it to a local chain, then perform testing. Users should use `--compilation-target` to specify the path of compiled contract and `target-contracts` to specify the name of target contract.

Use `./odyssey fuzz -h` to show the guidelines.
```
Starts a fuzzing campaign

Usage:
  odyssey fuzz [flags]

Flags:
      --config string               path to config file
      --compilation-target string   target contract or directory to compile
      --workers int                 number of fuzzer workers (unless a config file is provided, default is 10)
      --timeout int                 number of seconds to run the fuzzer campaign for (unless a config file is provided, default is 0). 0 means that timeout is not enforced
      --test-limit uint             number of transactions to test before exiting (unless a config file is provided, default is 0). 0 means that test limit is not enforced
      --seq-len int                 maximum transactions to run in sequence (unless a config file is provided, default is 100)
      --target-contracts strings    target contracts for fuzz testing (unless a config file is provided, default is [])
      --corpus-dir string           directory path for corpus items and coverage reports (unless a config file is provided, default is "")
      --senders strings             account address(es) used to send state-changing txns
      --deployer string             account address used to deploy contracts
      --trace-all                   print the execution trace for every element in a shrunken call sequence instead of only the last element (unless a config file is provided, default is false)
      --no-color                    disabled colored terminal output
      --coverage-guide              enable coverage-guide
      --state-guide                 enable state guide
  -h, --help                        help for fuzz
```

Running the example case in the paper.
```
./odyssey fuzz --config example/config.json --compilation-target example.sol --target-contracts Example --workers 1 --state-guide
```

### Running fuzzer on-chain
In this way, the tool can test the contract of the specified address in a simulated on-chain environment. Users should use `--node-url` to specify the url of rpc node and `target-addresses` to speficy the address of the target contracts.

Use `./odyssey fuzz-on-chain -h` to show the guidelines.
```
Starts a fuzzing campaign

Usage:
  odyssey fuzz-on-chain [flags]

Flags:
      --config string              path to config file
      --target-addresses strings   target addresses for fuzz testing
      --blocknumber int            block height for testing
      --node-url string            url of on-chain node
      --etherscan-api-key string   api key of etherscan
      --invariant-guided           turn on invariant-guided mode
      --workers int                number of fuzzer workers (unless a config file is provided, default is 10)
      --trace-all                  print the execution trace for every element in a shrunken call sequence instead of only the last element (unless a config file is provided, default is false)
      --corpus-dir string          directory path for corpus items and coverage reports (unless a config file is provided, default is "")
      --coverage-guide             enable coverage-guide
      --state-guide                enable state guide
      --state-construction         enable state construction
      --state-division             enable state division
      --output string              path to output file
  -h, --help                       help for fuzz-on-chain
```

Running the example case.
```
./odyssey fuzz-on-chain --config example_onchain/config.json
```

## Dataset
The dataset is stored in `./data`, where `real_world_hacking_dataset.csv` is the list of dapps and `dataset` contains the `config.json` of each dapp.
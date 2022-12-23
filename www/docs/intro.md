# StarkNet Hardhat Plugin

[![npm package](https://img.shields.io/npm/v/@shardlabs/starknet-hardhat-plugin?color=blue)](https://www.npmjs.com/package/@shardlabs/starknet-hardhat-plugin)

If you've used Hardhat 👷‍♀️👷‍♂️ and want to develop for StarkNet <img src="https://starkware.co/wp-content/uploads/2021/07/Group-177.svg" alt="starknet" width="18"/>, this plugin might come in hand. If you've never set up a Hardhat project, check out [this guide](https://hardhat.org/tutorial/creating-a-new-hardhat-project.html).

## Contents

-   [Install](#install)
-   [CLI commands](#cli-commands)
-   [API](#api)
-   [Testing](#test)
    -   [Important notes](#important-notes)
    -   [Examples](#test-examples)
    -   [Devnet examples](#devnet-examples)
-   [Configure the plugin](#configure-the-plugin)
-   [Account support](#account)
-   [More examples](#more-examples)
-   [Contribute](#contribute)

## Install

```
npm i @shardlabs/starknet-hardhat-plugin --save-dev
```

For the latest unstable version, use

```
npm i @shardlabs/starknet-hardhat-plugin@alpha --save-dev
```

Add the following line to the top of your `hardhat.config.ts` (or `hardhat.config.js`):

```typescript
import "@shardlabs/starknet-hardhat-plugin";
// or
require("@shardlabs/starknet-hardhat-plugin");
```

### Requirements

This plugin was tested with:

-   Node.js v14.17.3
-   npm/npx v7.19.1
-   Docker v20.10.8 (optional):
    -   Since plugin version 0.3.4, Docker is no longer necessary if you opt for a Python environment (more info in [Config](#cairo-version)).
    -   If you opt for the containerized version, make sure you have a running Docker daemon.
    -   If you're experiencing Docker access issues, check [this](https://stackoverflow.com/questions/52364905/after-executing-following-code-of-dockerode-npm-getting-error-connect-eacces-v).
-   Linux / macOS:
    -   On Windows, we recommend using [WSL 2](https://learn.microsoft.com/en-us/windows/wsl/install) with Docker instance installed on [WSL 2](https://learn.microsoft.com/en-us/windows/wsl/install) instead of using Docker Desktop on your windows. Example installation for Ubuntu can be found [here](https://docs.docker.com/engine/install/ubuntu/).

## CLI commands

This plugin defines the following Hardhat commands (also called tasks):

### `starknet-compile`

```
$ npx hardhat starknet-compile [PATH...] [--cairo-path "<LIB_PATH1>:<LIB_PATH2>:..."] [--account-contract] [--disable-hint-validation]
```

If no paths are provided, all StarkNet contracts in the default contracts directory are compiled. Paths can be files and directories.

`--cairo-path` allows specifying the locations of imported files, if necessary. Separate them with a colon (:), e.g. `--cairo-path='path/to/lib1:path/to/lib2'`

`--account-contract` allows compiling an account contract.

`--disable-hint-validation` allows compiling a contract without hint validation (any python code is allowed in hints, ex: print ...).

### `starknet-verify`

```
$ npx hardhat starknet-verify [--starknet-network <NAME>] [--path <PATH>] [<DEPENDENCY_PATH> ...] [--address <CONTRACT_ADDRESS>] [--compiler-version <COMPILER_VERSION>] [--license <LICENSE_SCHEME>] [--contract-name <CONTRACT_NAME>] [--acount-contract]
```

Queries [Voyager](https://voyager.online/) to [verify the contract](https://voyager.online/verifyContract) deployed at `<CONTRACT_ADDRESS>` using the source files at `<PATH>` and any number of `<DEPENDENCY_PATH>`.

Like in the previous command, this plugin relies on `--starknet-network`, but will default to 'alphaGoerli' network in case this parameter is not passed.

The verifier expects `<COMPILER_VERSION>` to be passed on request. Supported compiler versions are listed [here](https://voyager.online/verifyContract) in the dropdown menu.

We pass `--acount-contract` to tell the verifier that the contract is of type account.

For `<LICENSE_SCHEME>` the command takes [_No License (None)_](https://github.com/github/choosealicense.com/blob/a40ef42140d137770161addf4fefc715709d8ccd/no-permission.md) as default license scheme. [Here](https://goerli.voyager.online/cairo-licenses) is a list of available options.

### `starknet-new-account`

**ATTENTION!** Use this only if you want to achieve compatibility with the wallet used in Starknet CLI. For all other uses, [these accounts](#account) should suffice.

```
$ npx hardhat starknet-new-account [--starknet-network <NAME>] [--wallet <WALLET_NAME>]
```

Initializes a wallet `wallets["WALLET_NAME"]` configured in the `hardhat.config` file, which should then be followed by the command `starknet-deploy-account`. Uses the modified OZ implementation used by StarkNet CLI.

### `starknet-deploy-account`

```
$ npx hardhat starknet-deploy-account [--starknet-network <NAME>] [--wallet <WALLET_NAME>]
```

Deploys the wallet `wallets["WALLET_NAME"]` configured in the `hardhat.config` file. Uses the modified OZ implementation used by StarkNet CLI. _Needs to be funded before deploying it._

```
$ npx hardhat starknet-deploy-account --starknet-network myNetwork --wallet MyWallet
```

### `starknet-plugin-version`

```
$ npx hardhat starknet-plugin-version
```

Prints the version of the plugin.

### `migrate`

```
$ npx hardhat migrate [PATH...] [--inplace]
```

Converts old cairo code to the new (cairo-lang 0.10.0) syntax. The `--inplace` flag will change the contract file in place.

```
$ npx hardhat migrate --inplace contract/contract.cairo
```

### `run`

Using `--starknet-network` with `hardhat run` currently does not have effect. Use the `network` property of the `starknet` object in your hardhat config file.

### `test`

Introduces the `--starknet-network` option to the existing `hardhat test` task.

## API

Adding this plugin to your project expands Hardhat's runtime with a `starknet` object. It can be imported with:

```typescript
import { starknet } from "hardhat";
// or
const starknet = require("hardhat").starknet;
```

To see all the utilities introduced by the `starknet` object, check [this](https://github.com/Shard-Labs/starknet-hardhat-plugin/blob/master/src/type-extensions.ts#L182) out.

## Testing

Relying on the above described API makes it easier to interact with your contracts and test them.

To test StarkNet contracts with Mocha, use the regular Hardhat `test` task which expects test files in your designated test directory:

```
$ npx hardhat test
```

Read more about the network used in tests in the [Runtime network](#runtime-network) section.
These examples are inspired by the official [StarkNet Python tutorial](https://www.cairo-lang.org/docs/hello_starknet/unit_tests.html).

### Important notes

-   `BigInt` is used because `felt` may be too big for javascript. Use it like `BigInt("10")` or, since ES2020, like `10n`.
-   All function names, argument names and return value names should be referred to by the names specified in contract source files.
-   The argument of `getContractFactory` is the **name** or the **path** of the source of the target contract:
    -   if providing a path, it should be relative to the project root or the contracts directory:
        -   `getContractFactory("contracts/subdir/MyContract.cairo")`
        -   `getContractFactory("subdir/MyContract.cairo")`
    -   the extension can be omitted:
        -   `getContractFactory("subdir/MyContract")`
        -   `getContractFactory("MyContract")`

### Test examples

#### Setup

```typescript
import { expect } from "chai";
import { starknet } from "hardhat";
// or
const expect = require("chai").expect;
const starknet = require("hardhat").starknet;

describe("My Test", function () {
  this.timeout(...);  // Recommended to use a big value if interacting with Alpha Goerli
```

#### Deploy / load contract

```typescript
  /**
   * Assumes there is a file MyContract.cairo whose compilation artifacts have been generated.
   * The contract is assumed to have:
   * - constructor function constructor(initial_balance: felt)
   * - external function increase_balance(amount: felt) -> (res: felt)
   * - view function get_balance() -> (res: felt)
   */
  it("should load a previously deployed contract", async function () {
    const contractFactory = await starknet.getContractFactory("MyContract");
    const contract = contractFactory.getContractAt("0x123..."); // address of a previously deployed contract
  });

  it("should declare and deploy", async function() {
    const account = await starknet.OpenZeppelinAccount.getAccountFromAddress(...);
    const contractFactory = await starknet.getContractFactory("MyContract");
    const classHash = await account.declare(contractFactory);

    // two ways to obtain the class hash
    expect(classHash).to.equal(await contractFactory.getClassHash());

    const constructorArgs = { initial_balance: 0 };
    const options = { maxFee: ... };
    // implicitly invokes UDC
    const contract = await account.deploy(contractFactory, constructorArgs, options);
  });
```

#### Arrays

```typescript
/**
 * The contract is assumed to have:
 * - view function sum_array(a_len: felt, a: felt*) -> (res: felt)
 */
it("should work with arrays", async function () {
    const contract = ...;
    // you don't have to specify the array length separately
    const { res } = await contract.call("sum_array", { a: [1, 2, 3] });
    expect(res).to.deep.equal(BigInt(6));
});
```

#### Tuples

```typescript
/**
 * The contract is assumed to have:
 * - view function sum_pair(pair: (felt, felt)) -> (res : felt)
 * - view func sum_named_pair(pair : (x : felt, y : felt) -> (res : felt)
 * - using PairAlias = (x : felt, y : felt)
 * - view func sum_type_alias(pair : PairAlias) -> (res : felt)
 */
it("should work with tuples", async function () {
    const contract = ...;
    // notice how the pair tuple is passed as javascript array
    const { res } = await contract.call("sum_pair", { pair: [10, 20] });
    ... = await contract.call("sum_named_pair", { pair: { x: 10, y: 20 } });
    ... = await contract.call("sum_type_alias", { pair: { x: 10, y: 20 } });
    expect(res).to.deep.equal(BigInt(30));
});
```

#### Fee estimation

```typescript
it("should estimate fee", async function () {
    const fee = await account.estimateFee(contract, "increase_balance", { amount: 10n });
    console.log("Estimated fee:", fee.amount, fee.unit, fee.gas_price, fee.gas_amount);
});
```

#### Delegate Proxy

```typescript
it("should forward to the implementation contract", async function () {
    const implementationFactory = await starknet.getContractFactory("contract");
    const account = ...;
    const implementationClassHash = await account.declare(implementationFactory);

    const proxyFactory = await starknet.getContractFactory("delegate_proxy");
    await account.declare(proxyFactory);
    const proxy = await account.deploy(proxyFactory, {
        implementation_hash_: implementationClassHash
    });

    proxy.setImplementation(implementationFactory);
    const { res: initialProxyBalance } = await proxy.call("get_balance");
});
```

#### Transaction information and receipt with events

```typescript
it("should return transaction data and transaction receipt", async function () {
    const contract: StarknetContract = ...;
    console.log("Deployment transaction hash:", contract.deployTxHash);

    const transaction = await starknet.getTransaction(contract.deployTxHash);
    console.log(transaction);

    const account = ...;
    const txHash = await account.invoke(contract, "increase_balance", { amount: 10 });

    const receipt = await starknet.getTransactionReceipt(txHash);
    const decodedEvents = contract.decodeEvents(receipt.events);

    const txTrace = await starknet.getTransactionTrace(txHash);
    // decodedEvents contains hex data array converted to a structured object
    // { name: "increase_balance_called", data: { current_balance: 0n, amount: 10n } }
});
```

For more usage examples, including tuple, array and struct support, as well as Starknet CLI wallet support, check [sample-test.ts](https://github.com/Shard-Labs/starknet-hardhat-example/blob/master/test/sample-test.ts) of [starknet-hardhat-example](https://github.com/Shard-Labs/starknet-hardhat-example).

### Devnet examples

#### L1-L2 communication (Postman message exchange with Devnet)

Exchanging messages between L1 ([Ganache](https://www.npmjs.com/package/ganache), [Hardhat node](https://hardhat.org/hardhat-network/#running-stand-alone-in-order-to-support-wallets-and-other-software), Ethereum testnet) and L2 (only supported for [starknet-devnet](https://github.com/Shard-Labs/starknet-devnet)) can be done using this plugin:

-   Ensure there is an available L1 network and that you know its RPC endpoint URL.
-   Load an L1 Messaging contract using `starknet.devnet.loadL1MessagingContract`.
-   Call `starknet.devnet.flush` after you `invoke` your contract and want to propagate your message.
-   When running a hardhat test or script which relies on `network["config"]`, specify the name of an L1 network you defined in `hardhat.config`. Use `npx hardhat test --network <NETWORK_NAME>`. Network `localhost` is predefined in hardhat so `--network localhost` should work if you're using e.g. `npx hardhat node` as the L1 network.
-   Check [this example](https://github.com/Shard-Labs/starknet-hardhat-example/blob/master/test/postman.test.ts#L98) for more info.

```typescript
  it("should exchange messages with Devnet", async function() {
    await starknet.devnet.loadL1MessagingContract(...);
    const l1contract = ...;
    const l2contract = ...;

    await l1contract.send(...); // depending on your L1 contract interaction library
    await starknet.devnet.flush();

    const account = ...;
    await account.invoke(l2contract, ...);
    await starknet.devnet.flush();
  });
```

#### Restart

Devnet can be restarted by calling `starknet.devnet.restart()`. All of the deployed contracts, blocks and storage updates will be restarted to the empty state.

```typescript
await starknet.devnet.restart();
```

#### Dumping

Use `starknet.devnet.dump()` to maintain the Devnet instance from the plugin.

```typescript
await starknet.devnet.dump(path); // path to dump file (eg. dump.pkl)
```

#### Loading

Dumped Devnet instance can be loaded using `starknet.devnet.load()`.

```typescript
await starknet.devnet.load(path); // path for dump file (eg. dump.pkl)
```

#### Advancing time

The plugin comes with support for [Devnet's timestamp management](https://shard-labs.github.io/starknet-devnet/docs/guide/advancing-time).
The time offset for each generated block can be increased by calling `starknet.devnet.increaseTime()`. The time for the next block can be set by calling `starknet.devnet.setTime()`, with subsequent blocks keeping the set offset.

Warning: _block time can be set in the past and lead to unexpected behaviour!_

```typescript
await starknet.devnet.setTime(1000); // time in seconds
await starknet.devnet.increaseTime(1000); // time in seconds
```

#### Creating an empty block

Devnet offers [empty block creation](https://shard-labs.github.io/starknet-devnet/docs/guide/blocks#create-an-empty-block). It can be useful to make available those changes that take effect with the next block.

```typescript
const emptyBlock = await starknet.devnet.createBlock();
```

## Configure the plugin

Specify custom configuration by editing your project's `hardhat.config.ts` (or `hardhat.config.js`).

### Cairo version

Use this configuration option to select the `cairo-lang`/`starknet` version used by the underlying Docker container.

A Docker image tailored to the machine will be pulled. The `-arm` suffix will be applied to the version name, if it's not applied on `hardhat.config.ts`, if the device's architecture is `arm64`. (e.g. `dockerizedVersion: "0.8.1-arm"` and `dockerizedVersion: "0.8.1"` both will work).

If you specify neither `dockerizedVersion` nor [venv](#existing-virtual-environment), the latest dockerized version is used.

A list of available dockerized versions can be found [here](https://hub.docker.com/r/shardlabs/cairo-cli/tags).

```javascript
module.exports = {
  starknet: {
    dockerizedVersion: "0.8.1"
  }
  ...
};
```

### Existing virtual environment

If you want to use an existing Python virtual environment (pyenv, poetry, conda, miniconda), specify it by using `starknet["venv"]`.

To use the currently activated environment (or if you have the starknet commands globally installed), set `venv` to `"active"`.

In any case, the specified environment is expected to contain the `python3` command.

If you are on a Mac, you may experience Docker-related issues, so this may be the only way to run the plugin.

If you specify neither [dockerizedVersion](#cairo-version) nor `venv`, the latest dockerized version is used.

```typescript
module.exports = {
    starknet: {
        // venv: "active" <- for the active virtual environment
        // venv: "path/to/my-venv" <- for env created with e.g. `python -m venv path/to/my-venv`
        venv: "<VENV_PATH>"
    }
};
```

### Paths

```typescript
module.exports = {
  paths: {
    // Defaults to "contracts" (the same as `paths.sources`).
    starknetSources: "my-own-starknet-path",

    // Defaults to "starknet-artifacts".
    // Has to be different from the value set in `paths.artifacts` (which is used by core Hardhat and has a default value of `artifacts`).
    starknetArtifacts: "also-my-own-starknet-path",

   // Same purpose as the `--cairo-path` argument of the `starknet-compile` command
   // Allows specifying the locations of imported files, if necessary.
    cairoPaths: ["my/own/cairo-path1", "also/my/own/cairo-path2"]
  }
  ...
};
```

### Runtime network

To set the network used in your Hardhat scripts/tests, use `starknet["network"]` or the `--starknet-network` CLI option. Not specifying one will default to using alpha-goerli. Do not confuse this network with Hardhat's default `--network` option which refers to the L1 network.

A faster approach is to use [starknet-devnet](https://github.com/Shard-Labs/starknet-devnet), a Ganache-like local testnet.

```javascript
module.exports = {
  starknet: {
    network: "myNetwork"
  },
  networks: {
    devnet: { // this way you can also specify it with `--starknet-network devnet`
      url: "http://127.0.0.1:5050"
    }
  }
  ...
};
```

Predefined networks include `alpha-goerli`, `alpha-goerli2`, `alpha-mainnet` and `integrated-devnet`.

### Runtime network - Integrated Devnet

[starknet-devnet](https://github.com/Shard-Labs/starknet-devnet) is available out of the box as a starknet network called `integrated-devnet`. By default, it will spawn Devnet using its Docker image and listening on `http://127.0.0.1:5050`. Target it via the hardhat config file or `--starknet-network integrated-devnet`.

By defining/modifying `networks["integratedDevnet"]` in your hardhat config file, you can specify:

-   the version of Devnet to use (effectivelly specifying the version of the underlying Docker image)
-   a Python environment with installed starknet-devnet (can be active environment); this will avoid using the dockerized version
-   CLI arguments to be used on Devnet startup: [options](https://shard-labs.github.io/starknet-devnet/docs/guide/run)
-   where output should be flushed _(either to the terminal or to a file)_.

```javascript
module.exports = {
  starknet: {
    network: "integrated-devnet"
  },
  networks: {
    integratedDevnet: {
      url: "http://127.0.0.1:5050",

      // venv: "active" <- for the active virtual environment with installed starknet-devnet
      // venv: "path/to/venv" <- for env with installed starknet-devnet (created with e.g. `python -m venv path/to/venv`)
      venv: "<VENV_PATH>",

      // or specify Docker image tag
      dockerizedVersion: "<DEVNET_VERSION>",

      // optional devnet CLI arguments, read more here: https://shard-labs.github.io/starknet-devnet/docs/guide/run
      args: ["--gas-price", "2000000000", "--fork-network", "alpha-goerli"],

      // stdout: "logs/stdout.log" <- dumps stdout to the file
      stdout: "STDOUT", // <- logs stdout to the terminal
      // stderr: "logs/stderr.log" <- dumps stderr to the file
      stderr: "STDERR"  // <- logs stderr to the terminal
    }
  }
  ...
};
```

### Installing third-party libraries

If you want to install a third-party Cairo library and be able to import it in your Cairo files, use the following pattern:

#### With npm packages:

1. Install (example package: `influenceth__cairo_math_64x61@npm:@influenceth/cairo-math-64x61`)

```
npm install --save-dev influenceth__cairo_math_64x61@npm:@influenceth/cairo-math-64x61
```

2. Edit the `paths.cairoPaths` section of your `hardhat.config` file ([docs](#paths)):

```typescript
paths: {
    cairoPaths: ["./node_modules"];
}
```

3. Import

```
from influenceth__cairo_math_64x61.contracts.Math64x61 import Math64x61_ONE, Math64x61_mul
```

#### With pip packages:

1. Install (example package: `openzeppelin-cairo-contracts`)

```
pip install openzeppelin-cairo-contracts
```

2. If you are installing in a virtual environment, edit the `paths.cairoPaths` section of your `hardhat.config` file ([docs](#paths)) as:

```typescript
paths: {
    // this directory contains the openzeppelin directory
    cairoPaths: ["path/to/cairo_venv/lib/python3.8/site-packages"];
}
```

3. Import

```
from openzeppelin.token.erc20.library import ERC20
```

#### With non-npm git repositories:

If you want to install directly from a git repo that doesn't contain `package.json`, you cannot use `npm i`. However, `yarn` supports this.

1. Install (example package: `https://github.com/OpenZeppelin/cairo-contracts`)

```
yarn add openzeppelin__cairo_contracts@git+https://git@github.com/OpenZeppelin/cairo-contracts.git
```

### Using `starknet.getContractFactory` with third-party libraries

This paragraph assumes you've read and run [3rd party library installation](#Installing-third-party-libraries).
The example package used is `https://github.com/OpenZeppelin/cairo-contracts` so you may want to check [non-npm git repos](#With-non-npm-git-repositories).

1. Compile

```
$ npx hardhat starknet-compile node_modules/openzeppelin__cairo_contracts/src/openzeppelin/token/erc20/presets/ERC20.cairo
```

2. Get contract factory

```typescript
const contractFactory = await starknet.getContractFactory(
    "node_modules/openzeppelin__cairo_contracts/src/openzeppelin/token/erc20/presets/ERC20"
);
```

### Wallet - Starknet CLI

**ATTENTION!** Use this only if you want to achieve compatibility with the wallet used in Starknet CLI. For all other uses, [these accounts](#account) should suffice.

To configure a wallet for your project, specify it by adding an entry to `wallets` in your hardhat config file.
You can specify multiple wallets/accounts.

The parameters for the wallet are:

-   `accountName`: The name to give the account. If omitted, the default value `__default__` will be used;
-   `modulePath`: The python module and wallet class of your chosen wallet provider;
-   `accountPath`: The path where your wallet information will be saved.

```javascript
module.exports = {
  starknet: {
    wallets: {
      MyWallet: {
        accountName: "OpenZeppelin",
        modulePath: "starkware.starknet.wallets.open_zeppelin.OpenZeppelinAccount",
        accountPath: "~/.starknet_accounts"
      },
      AnotherWallet: {
        accountName: "AnotherOpenZeppelin",
        modulePath: "starkware.starknet.wallets.open_zeppelin.OpenZeppelinAccount",
        accountPath: "~/.starknet_accounts"
      }
    }
  }
  ...
};
```

Accounts are deployed in the same network as the one passed as an argument to the `npx hardhat starknet-deploy-account` CLI command.

To use the wallet in your scripts, use the `getWallet` utility function (using `Account.getAccountFromAddress(...)` will probably not work):

```typescript
import { starknet } from "hardhat";
...
const wallet = starknet.getWallet("MyWallet");
const contract = ...;
await contract.invoke("increase_balance", { amount: 1 }, { wallet });
```

## Recompilation

Recompilation is performed when contracts are updated or when artifacts are missing. A file will be created with the name `cairo-files-cache.json` to handle caching. Recompilation is handled before the following [CLI commands](#cli-commands) are executed.

-   `npx hardhat run`
-   `npx hardhat test`

This feature is turned off by default and is specified in the `hardhat.config.ts` file.

```typescript
module.exports = {
    starknet: {
        recompile: true // <- to switch recompilation on
    }
};
```

## Account

In Starknet, an account is a contract through which you interact with other contracts.
Its usage is exemplified [earlier in the docs](#accounts) and [in the example repo](https://github.com/Shard-Labs/starknet-hardhat-example/blob/plugin/test/oz-account-test.ts).

There are several Starknet account implementations; this plugin supports the following as properties of `hre.starknet`:

-   `OpenZeppelinAccount` - [v0.5.1](https://github.com/OpenZeppelin/cairo-contracts/releases/tag/v0.5.1)
-   `ArgentAccount` - Commit [780760e](https://github.com/argentlabs/argent-contracts-starknet/tree/780760e4156afe592bb1feff7e769cf279ae9831) of branch develop.

### Create account

```typescript
import { starknet } from "hardhat";
const account = await starknet.OpenZeppelinAccount.createAccount();
const accountFromOptions = await starknet.OpenZeppelinAccount.createAccount({
    salt: "0x123", // salt to always deploy to an expected address
    privateKey: process.env.MY_KEY // the key only known to you, the public key will be inferred
});
console.log(account.address);
```

### Fund account

After creating the account, you need to fund it (give it some ETH):

-   On alpha-goerli use [this faucet](https://faucet.goerli.starknet.io/).
-   On alpha-goerli2 use [this](https://www.newton.so/view/636d020159c30b8efc8d1d86)
-   On starknet-devnet use [this faucet](https://shard-labs.github.io/starknet-devnet/docs/guide/mint-token/).
-   Alternatively transfer some amount from an already funded account to the newly deployed account.

If you're facing issues loading the account you've just funded, check out [this issue](https://github.com/Shard-Labs/starknet-hardhat-plugin/issues/281#issuecomment-1354588817).

### Deploy account

After funding the account, you need to deploy it (in case of `ArgentAccount`, this will also take care of initialization):

```typescript
await account.deployAccount({ maxFee: ... });
```

To successfully deploy `ArgentAccount`, the chain you are interacting with is expected to have `ArgentAccount` contracts declared. Alpha Goerli and Alpha Mainnet satisfy this criterion, but if you're working with Devnet, this is most easily achievable by running Devnet [forked](https://shard-labs.github.io/starknet-devnet/docs/guide/fork) from e.g. Alpha Goerli.

### Reuse account

To retrieve an already deployed Account, use the `getAccountFromAddress` method. What may be especially useful are [predeployed+predefined accounts](https://shard-labs.github.io/starknet-devnet/docs/guide/Predeployed-accounts) that come with Devnet (retrieve them with `starknet.devnet.getPredeployedAccounts()`).

```typescript
const account = await starknet.OpenZeppelinAccount.getAccountFromAddress(
    accountAddress,
    process.env.PRIVATE_KEY
);
```

### Interact through account

Use the `invoke` method of `Account` to invoke (change the state), but `call` method of `StarknetContract` to call (read the state).

```typescript
await account.invoke(contract, "increase_balance", { amount });
const { res: amount } = await contract.call("get_balance");
```

Once your account is funded and deployed, you can specify a max fee greater than zero:

```typescript
await account.invoke(contract, "foo", { arg1: ... }, { maxFee: BigInt(...) });
```

If you don't specify a `maxFee`, one will be calculated for you by applying an overhead of 50% to the result of fee estimation. You can also customize the overhead by providing a value for `overhead`:

```typescript
// maxFee will be 40% of estimated fee; if overhead not provided, the default value is used.
await account.invoke(contract, "foo", { arg1: ... }, { overhead: 0.4 });
```

### Multicalls

You can also use the Account object to perform multi{invokes, fee estimations}.

```typescript
const interactionArray = [
    {
        toContract: contract1,
        functionName: "increase_balance",
        calldata: { amount: 10n }
    },
    {
        toContract: contract2,
        functionName: "increase_balance",
        calldata: { amount: 20n }
    }
];
const fee = await account.multiEstimateFee(interactionArray);
const txHash = await account.multiInvoke(interactionArray);
```

### Guardian

Unlike OpenZeppelin account, Argent account offers [guardian functionality](https://support.argent.xyz/hc/en-us/articles/360022631992-About-guardians). The guardian is by default not set (the guardian key is undefined), but if you want to change it, cast the `account` to `ArgentAccount` and execute `setGuardian`.

```typescript
await argentAccount.setGuardian(process.env.GUARDIAN_PRIVATE_KEY, { maxFee: 1e18 });
// to unset it, use an undefined key
await argentAccount.setGuardian(undefined, { maxFee: 1e18 });
```

## More examples

An example Hardhat project using this plugin can be found [here](https://github.com/Shard-Labs/starknet-hardhat-example).
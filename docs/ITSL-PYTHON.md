# Interchained Token Subsystem Layer (ITSL) Python SDK

The Interchained Token Subsystem Layer (ITSL) is a lightweight Python SDK and CLI wrapper that interfaces directly with the `interchainedd` RPC endpoint to manage tokens. 

This SDK simplifies interacting securely and programmatically with the Interchained token ledger without writing raw JSON-RPC requests.

## Setup Requirements

Ensure you have the requests library installed in your python environment:

```bash
pip install requests base58 ecdsa ripemd-hash
```

You must have `interchainedd` running locally (or remotely) with the RPC server enabled.

## Configuration & Global Flags

Whether running via CLI or using the Python Client, you must configure the RPC connection. 

When invoking `itsl.py` from the command line, use the following global flags before adding any commands:

* `--rpcuser`: RPC username (required)
* `--rpcpass`: RPC password (required)
* `--rpchost`: RPC host IP (default: 127.0.0.1)
* `--rpcport`: RPC port (default: 17100)
* `--wallet`: Wallet name (required if `interchainedd` has multiple wallets loaded)

## Using the CLI

Make the script executable and call it directly with the appropriate flags:

```bash
chmod +x itsl.py
./itsl.py --rpcuser="user" --rpcpass="pass" <command> [args...]
```

### Common Commands

#### Create a Token
Creates a token with the specified supply and attributes. If `--wif-key` is omitted, the node will sign with the wallet's default address. 
```bash
./itsl.py --rpcuser="user" --rpcpass="pass" createtoken "1000" "MyToken" "MTK" 8 --wif-key "cVX... your WIF key here ... "
```

#### Transfer Tokens
Send tokens to another address.
```bash
./itsl.py --rpcuser="user" --rpcpass="pass" tokentransfer "destination_address" "token_id" "50" --memo "Thanks for the services"
```

#### Check Token Balances
List all tokens held by the active wallet.
```bash
./itsl.py --rpcuser="user" --rpcpass="pass" my_tokens
```

#### Check a Specific Token Balance
Get the balance of a specific token for your wallet (or an arbitrary address).
```bash
# Your wallet:
./itsl.py --rpcuser="user" --rpcpass="pass" gettokenbalance "token_id"

# Someone else's address:
./itsl.py --rpcuser="user" --rpcpass="pass" gettokenbalanceof "token_id" "address"
```

#### View Token Operation History
View the entire transaction history for a given token.
```bash
./itsl.py --rpcuser="user" --rpcpass="pass" token_history "token_id"
```

## Supported Commands Overview

The SDK wraps all token namespace RPC interactions:

**Information & State Retrieval:**
* `getsigneraddress`: Print the default signer address for the wallet.
* `gettokenbalance`: Get token balance for the current wallet.
* `gettokenbalanceof`: Get token balance for a specific address.
* `tokenallowance`: Check the current allowance granted to a spender.
* `tokentotalsupply`: Get the total circulating supply of a token.
* `getgovernancebalance`: Get accumulated network governance fees.
* `my_tokens`: List all tokens owned by the wallet.
* `all_tokens`: List all recognized tokens in the ledger.
* `token_history`: List operation history for a token.
* `token_meta`: Get static token metadata (Creator, Decimals, etc.).
* `token_tx_memo`: Get the memo string associated with a specific token transaction hash.

**State Modifications (Require WIF Key or Wallet Signer):**
* `createtoken`: Issue a new token.
* `tokentransfer`: Send tokens to an address.
* `tokenapprove`: Approve an address to spend on your behalf.
* `tokentransferfrom`: Transfer tokens using a previously granted allowance.
* `tokenincreaseallowance`: Increase a spender's allowance.
* `tokendecreaseallowance`: Decrease a spender's allowance.
* `tokenburn`: Permanently destroy tokens from the total supply.
* `tokenmint`: Create more tokens (requires token operator rights).
* `tokentransferownership`: Handoff token operator rights to a new address.

## Programmatic Usage (Python API)

You can import `ITSLClient` into your own Python applications to interact with the Interchained network seamlessly. 

```python
from itsl import ITSLClient

# Instantiate the client
client = ITSLClient(
    rpc_user="user", 
    rpc_password="password", 
    rpc_host="127.0.0.1", 
    rpc_port=17100, 
    wallet_name="my_trading_wallet" # Only needed if running a multi-wallet node
)

# Fetch data
my_tokens = client.my_tokens()
print("Owned Tokens:", my_tokens)

# Execute an operation using a private WIF key (Overrides node wallet signing)
private_wif_key = "cVX... your WIF key here ... "
result = client.token_transfer(
    to="recipient_address_here",
    token="target_token_id_here",
    amount="1.50",
    memo="Programmatic Transfer",
    witness=True, # Ensure WIF key generates a SegWit signature 
    wif_key=private_wif_key
)

print("Transfer Result:", result)
```

#!/usr/bin/env python3
import argparse
import requests
import json
import base64
import hashlib
import base58
import ecdsa

class ITSLClient:
    def __init__(self, rpc_user, rpc_password, rpc_host="127.0.0.1", rpc_port=17100, wallet_name=""):
        if wallet_name:
            self.url = f"http://{rpc_host}:{rpc_port}/wallet/{wallet_name}"
        else:
            self.url = f"http://{rpc_host}:{rpc_port}/"
        auth_str = f"{rpc_user}:{rpc_password}"
        b64_auth = base64.b64encode(auth_str.encode("utf-8")).decode("utf-8")
        self.headers = {"Authorization": f"Basic {b64_auth}", "content-type": "application/json"}
        self.request_id = 0

    def _call_rpc(self, method, params=None):
        if params is None:
            params = []
        
        self.request_id += 1
        payload = {
            "method": method,
            "params": params,
            "jsonrpc": "1.0",
            "id": f"itsl_{self.request_id}",
        }
        
        try:
            response = requests.post(self.url, headers=self.headers, data=json.dumps(payload))
            response.raise_for_status()
            data = response.json()
            if data.get("error"):
                raise Exception(f"RPC Error: {data['error']}")
            return data.get("result")
        except requests.exceptions.HTTPError as e:
            try:
                err_data = response.json()
                if "error" in err_data and err_data["error"]:
                    raise Exception(f"RPC HTTP Error: {err_data['error']['message']}")
            except json.JSONDecodeError:
                pass
            raise Exception(f"HTTP Error: {e}\nResponse: {response.text}")
        except Exception as e:
            raise Exception(f"Failed to connect or parsed failed: {e}")

    # --- Token Commands ---
    
    def get_signer_address(self):
        return self._call_rpc("getsigneraddress")

    def create_token(self, amount, name, symbol, decimals, witness=False, wif_key=None):
        params = [str(amount), name, symbol, str(decimals), "true" if witness else "false"]
        if wif_key: params.append(wif_key)
        return self._call_rpc("createtoken", params)

    def get_token_balance(self, token, witness=False, address=None):
        params = [token, "true" if witness else "false"]
        if address: params.append(address)
        return self._call_rpc("gettokenbalance", params)

    def get_token_balance_of(self, token, address):
        return self._call_rpc("gettokenbalanceof", [token, address])

    def token_approve(self, spender, token, amount, witness=False, wif_key=None):
        params = [spender, token, str(amount), "true" if witness else "false"]
        if wif_key: params.append(wif_key)
        return self._call_rpc("tokenapprove", params)

    def token_allowance(self, owner, spender, token):
        return self._call_rpc("tokenallowance", [owner, spender, token])

    def token_transfer(self, to, token, amount, memo="", witness=False, wif_key=None):
        params = [to, token, str(amount), memo, "true" if witness else "false"]
        if wif_key: params.append(wif_key)
        return self._call_rpc("tokentransfer", params)

    def token_transfer_from(self, from_addr, to, token, amount, memo="", witness=False, wif_key=None):
        params = [from_addr, to, token, str(amount), memo, "true" if witness else "false"]
        if wif_key: params.append(wif_key)
        return self._call_rpc("tokentransferfrom", params)

    def token_increase_allowance(self, spender, token, amount, witness=False, wif_key=None):
        params = [spender, token, str(amount), "true" if witness else "false"]
        if wif_key: params.append(wif_key)
        return self._call_rpc("tokenincreaseallowance", params)

    def token_decrease_allowance(self, spender, token, amount, witness=False, wif_key=None):
        params = [spender, token, str(amount), "true" if witness else "false"]
        if wif_key: params.append(wif_key)
        return self._call_rpc("tokendecreaseallowance", params)

    def token_burn(self, token, amount, witness=False, wif_key=None):
        params = [token, str(amount), "true" if witness else "false"]
        if wif_key: params.append(wif_key)
        return self._call_rpc("tokenburn", params)

    def token_mint(self, token, amount, witness=False, wif_key=None):
        params = [token, str(amount), "true" if witness else "false"]
        if wif_key: params.append(wif_key)
        return self._call_rpc("tokenmint", params)

    def token_transfer_ownership(self, token, new_owner, witness=False, wif_key=None):
        params = [token, new_owner, "true" if witness else "false"]
        if wif_key: params.append(wif_key)
        return self._call_rpc("tokentransferownership", params)

    def token_total_supply(self, token):
        return self._call_rpc("tokentotalsupply", [token])

    def get_governance_balance(self):
        return self._call_rpc("getgovernancebalance", [])

    def my_tokens(self, witness=False):
        return self._call_rpc("my_tokens", ["true" if witness else "false"])

    def all_tokens(self):
        return self._call_rpc("all_tokens", [])

    def token_history(self, token, filter_addr=None):
        params = [token]
        if filter_addr: params.append(filter_addr)
        return self._call_rpc("token_history", params)

    def token_meta(self, token):
        return self._call_rpc("token_meta", [token])

    def token_tx_memo(self, token, txid):
        return self._call_rpc("token_tx_memo", [token, txid])

    def rescan_tokentx(self, from_height=None):
        params = []
        if from_height is not None: params.append(from_height)
        return self._call_rpc("rescan_tokentx", params)

def ripemd160(data_in: bytes) -> bytes:
    # RIPEMD-160 implementation in pure python
    # Source: https://github.com/jb55/python-ripemd160
    
    def F(x: int, y: int, z: int) -> int: return (x ^ y ^ z)
    def G(x: int, y: int, z: int) -> int: return (x & y) | (~x & z)
    def H(x: int, y: int, z: int) -> int: return (x | ~y) ^ z
    def I(x: int, y: int, z: int) -> int: return (x & z) | (y & ~z)
    def J(x: int, y: int, z: int) -> int: return x ^ (y | ~z)
    
    def rol(x: int, n: int) -> int: return ((x << n) & 0xffffffff) | (x >> (32 - n))
    
    h0: int = 0x67452301
    h1: int = 0xefcdab89
    h2: int = 0x98badcfe
    h3: int = 0x10325476
    h4: int = 0xc3d2e1f0
    
    # Pad message
    data = bytearray(data_in)
    ml = len(data) * 8
    data += b'\x80'
    while (len(data) % 64) != 56:
        data += b'\x00'
    data += ml.to_bytes(8, 'little')
    
    r1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
          1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    r2 = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    
    s1 = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
          7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
          11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    s2 = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    
    for i in range(0, len(data), 64):
        chunk = data[i:i+64]
        words = [int.from_bytes(chunk[j:j+4], 'little') for j in range(0, 64, 4)]
        
        A, B, C, D, E = h0, h1, h2, h3, h4
        A_, B_, C_, D_, E_ = h0, h1, h2, h3, h4
        
        for j in range(80):
            if j < 16:
                t = (A + F(B, C, D) + words[r1[j]] + 0x00000000) & 0xffffffff
                t_ = (A_ + J(B_, C_, D_) + words[r2[j]] + 0x50a28be6) & 0xffffffff
            elif j < 32:
                t = (A + G(B, C, D) + words[r1[j]] + 0x5a827999) & 0xffffffff
                t_ = (A_ + I(B_, C_, D_) + words[r2[j]] + 0x5c4dd124) & 0xffffffff
            elif j < 48:
                t = (A + H(B, C, D) + words[r1[j]] + 0x6ed9eba1) & 0xffffffff
                t_ = (A_ + H(B_, C_, D_) + words[r2[j]] + 0x6d703ef3) & 0xffffffff
            elif j < 64:
                t = (A + I(B, C, D) + words[r1[j]] + 0x8f1bbcdc) & 0xffffffff
                t_ = (A_ + G(B_, C_, D_) + words[r2[j]] + 0x7a6d76e9) & 0xffffffff
            else:
                t = (A + J(B, C, D) + words[r1[j]] + 0xa953fd4e) & 0xffffffff
                t_ = (A_ + F(B_, C_, D_) + words[r2[j]] + 0x00000000) & 0xffffffff
                
            A = E
            E = D
            D = rol(C, 10)
            C = B
            B = (t + rol(t, s1[j])) & 0xffffffff
            
            A_ = E_
            E_ = D_
            D_ = rol(C_, 10)
            C_ = B_
            B_ = (t_ + rol(t_, s2[j])) & 0xffffffff
            
        t = (h1 + C + D_) & 0xffffffff
        h1 = (h2 + D + E_) & 0xffffffff
        h2 = (h3 + E + A_) & 0xffffffff
        h3 = (h4 + A + B_) & 0xffffffff
        h4 = (h0 + B + C_) & 0xffffffff
        h0 = t
        
    return b''.join(x.to_bytes(4, 'little') for x in (h0, h1, h2, h3, h4))

def _bech32_polymod(values):
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk

def _bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def _bech32_create_checksum(hrp, data):
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def _bech32_encode(hrp, data):
    combined = data + _bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join("qpzry9x8gf2tvdw0s3jn54khce6mua7l"[d] for d in combined)

def _convertbits(data, frombits, tobits, pad=True):
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits: ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def get_segwit_address_from_wif(wif: str) -> str:
    # 1. Decode Base58Check
    decoded = base58.b58decode_check(wif)
    # the first byte is version, next 32 bytes are private key, 
    # last byte (0x01) indicates compressed pubkey
    privkey_bytes = decoded[1:33]
    is_compressed = len(decoded) == 34 and decoded[33] == 1
    
    # 2. Get public key (secp256k1)
    sk = ecdsa.SigningKey.from_string(privkey_bytes, curve=ecdsa.SECP256k1)
    vk = sk.get_verifying_key()
    pubkey_uncompressed = vk.to_string()
    
    # Compress it based on WIF flag
    if is_compressed:
        prefix = b'\x02' if pubkey_uncompressed[-1] % 2 == 0 else b'\x03'
        pubkey_final = prefix + pubkey_uncompressed[:32]
    else:
        pubkey_final = b'\x04' + pubkey_uncompressed
    
    # 3. Hash160 (RIPEMD160(SHA256(pubkey)))
    sha256_hash = hashlib.sha256(pubkey_final).digest()
    try:
        h160 = hashlib.new('ripemd160')
        h160.update(sha256_hash)
        pubkey_hash = h160.digest()
    except ValueError:
        try:
            h160 = hashlib.new('rmd160')
            h160.update(sha256_hash)
            pubkey_hash = h160.digest()
        except ValueError:
            pubkey_hash = ripemd160(sha256_hash)
    
    # 4. Bech32 Encode (WitnessV0KeyHash)
    # Version 0 (0x00) + pubkey_hash converted to 5-bit groups
    hrp = "itc" 
    witprog = _convertbits(pubkey_hash, 8, 5)
    if witprog is None:
        raise ValueError("Invalid witness program")
    return _bech32_encode(hrp, [0] + witprog)

def _prompt_confirmation(action_desc):
    print("\n" + "="*60)
    print("⚠️  TRANSACTION REVIEW ⚠️")
    print("="*60)
    print(action_desc)
    print("-" * 60)
    
    while True:
        resp = input("Are you absolutely sure you want to broadcast this? (y/N): ").strip().lower()
        if resp in ['y', 'yes']:
            return True
        elif resp in ['n', 'no', '']:
            return False
        print("Please answer y or n.")

def _execute_command(client, args):
    if hasattr(args, 'wif_key') and args.wif_key:
        args.witness = True

    if args.command == "getsigneraddress":
        return client.get_signer_address()
    elif args.command == "createtoken":
        if not args.yes:
            desc = f"Action:        CREATE TOKEN\nToken:         {args.name} ({args.symbol})\nAmount:        {args.amount} (Decimals: {args.decimals})\nWitness Sig:   {args.witness}\nWIF Key:       {'Provided' if args.wif_key else 'None (Using Node Wallet)'}"
            if not _prompt_confirmation(desc):
                print("Operation cancelled.")
                import sys; sys.exit(0)
        return client.create_token(args.amount, args.name, args.symbol, args.decimals, args.witness, args.wif_key)
    elif args.command == "gettokenbalance":
        if hasattr(args, 'wif_key') and args.wif_key and not args.address:
            args.address = get_segwit_address_from_wif(args.wif_key)
        return client.get_token_balance(args.token, args.witness, args.address)
    elif args.command == "gettokenbalanceof":
        return client.get_token_balance_of(args.token, args.address)
    elif args.command == "tokenapprove":
        if not args.yes:
            desc = f"Action:        APPROVE SPENDER\nSpender:       {args.spender}\nToken:         {args.token}\nAmount:        {args.amount}\nWitness Sig:   {args.witness}\nWIF Key:       {'Provided' if args.wif_key else 'None'}"
            if not _prompt_confirmation(desc): return {"status": "cancelled"}
        return client.token_approve(args.spender, args.token, args.amount, args.witness, args.wif_key)
    elif args.command == "tokenallowance":
        return client.token_allowance(args.owner, args.spender, args.token)
    elif args.command == "tokentransfer":
        if not args.yes:
            desc = f"Action:        TRANSFER TOKENS\nDestination:   {args.to}\nToken ID:      {args.token}\nAmount:        {args.amount}\nMemo:          {args.memo}\nWitness Sig:   {args.witness}\nWIF Key:       {'Provided' if args.wif_key else 'None'}"
            if not _prompt_confirmation(desc): return {"status": "cancelled"}
        return client.token_transfer(args.to, args.token, args.amount, args.memo, args.witness, args.wif_key)
    elif args.command == "tokentransferfrom":
        if not args.yes:
            desc = f"Action:        TRANSFER FROM (ALLOWANCE)\nFrom:          {args.from_addr}\nTo:            {args.to}\nToken ID:      {args.token}\nAmount:        {args.amount}\nMemo:          {args.memo}\nWitness Sig:   {args.witness}\nWIF Key:       {'Provided' if args.wif_key else 'None'}"
            if not _prompt_confirmation(desc): return {"status": "cancelled"}
        return client.token_transfer_from(args.from_addr, args.to, args.token, args.amount, args.memo, args.witness, args.wif_key)
    elif args.command == "tokenincreaseallowance":
        if not args.yes:
            if not _prompt_confirmation(f"Action: INCREASE ALLOWANCE\nSpender: {args.spender}\nToken: {args.token}\nAmount: +{args.amount}"): return {"status": "cancelled"}
        return client.token_increase_allowance(args.spender, args.token, args.amount, args.witness, args.wif_key)
    elif args.command == "tokendecreaseallowance":
        if not args.yes:
            if not _prompt_confirmation(f"Action: DECREASE ALLOWANCE\nSpender: {args.spender}\nToken: {args.token}\nAmount: -{args.amount}"): return {"status": "cancelled"}
        return client.token_decrease_allowance(args.spender, args.token, args.amount, args.witness, args.wif_key)
    elif args.command == "tokenburn":
        if not args.yes:
            if not _prompt_confirmation(f"Action: BURN TOKENS (DESTROY FOREVER)\nToken: {args.token}\nAmount: {args.amount}"): return {"status": "cancelled"}
        return client.token_burn(args.token, args.amount, args.witness, args.wif_key)
    elif args.command == "tokenmint":
        if not args.yes:
            if not _prompt_confirmation(f"Action: MINT TOKENS\nToken: {args.token}\nAmount: {args.amount}"): return {"status": "cancelled"}
        return client.token_mint(args.token, args.amount, args.witness, args.wif_key)
    elif args.command == "tokentransferownership":
        if not args.yes:
            if not _prompt_confirmation(f"Action: TRANSFER OPERATOR OWNERSHIP\nToken: {args.token}\nNew Owner: {args.new_owner}\nWARNING: You will lose operator rights!"): return {"status": "cancelled"}
        return client.token_transfer_ownership(args.token, args.new_owner, args.witness, args.wif_key)
    elif args.command == "tokentotalsupply":
        return client.token_total_supply(args.token)
    elif args.command == "getgovernancebalance":
        return client.get_governance_balance()
    elif args.command == "my_tokens":
        if hasattr(args, 'wif_key') and args.wif_key:
            address = get_segwit_address_from_wif(args.wif_key)
            print(f"[*] Derived Segwit Address from WIF: {address}")
            
            all_known_tokens = client.all_tokens()
            if isinstance(all_known_tokens, dict) and "error" in all_known_tokens:
                return all_known_tokens # return rpc error

            held_tokens = []
            for token_info in all_known_tokens:
                try:
                    bal_str = client.get_token_balance_of(token_info["address"], address)
                    print(f"DEBUG: Token {token_info['address']} Balance: '{bal_str}' Type: {type(bal_str)}")
                    if isinstance(bal_str, dict) and "error" in bal_str:
                        continue
                    if float(bal_str) > 0:
                        token_info["balance"] = bal_str
                        held_tokens.append(token_info)
                except Exception as e:
                    print(f"DEBUG: Exception on Token {token_info['address']}: {e}")
                    # Ignore tokens that fail to fetch balance (e.g. invalid token ID error from node)
                    continue
            return held_tokens
        return client.my_tokens(args.witness)
    elif args.command == "all_tokens":
        return client.all_tokens()
    elif args.command == "token_history":
        return client.token_history(args.token, args.filter)
    elif args.command == "token_meta":
        return client.token_meta(args.token)
    elif args.command == "token_tx_memo":
        return client.token_tx_memo(args.token, args.txid)
    elif args.command == "rescan_tokentx":
        return client.rescan_tokentx(args.from_height)
    else:
        raise ValueError("Unknown command")


def main():
    parser = argparse.ArgumentParser(description="Interchained Token Subsystem Layer (ITSL) SDK / CLI")
    
    # Global RPC config arguments
    parser.add_argument("--rpcuser", type=str, required=True, help="RPC username")
    parser.add_argument("--rpcpass", type=str, required=True, help="RPC password")
    parser.add_argument("--rpchost", type=str, default="127.0.0.1", help="RPC host (default: 127.0.0.1)")
    parser.add_argument("--rpcport", type=int, default=17100, help="RPC port (default: 17100)")
    parser.add_argument("--wallet", type=str, default="", help="Wallet name (required if multiple wallets are loaded)")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip interactive confirmation prompts for state-modifying commands")
    
    subparsers = parser.add_subparsers(dest="command", required=True, help="ITSL Commands")

    # Command: getsigneraddress
    subparsers.add_parser("getsigneraddress", help="Get the default signer address for the wallet")

    # Command: createtoken
    parser_create = subparsers.add_parser("createtoken", help="Create a new token")
    parser_create.add_argument("amount", type=str, help="Initial supply amount")
    parser_create.add_argument("name", type=str, help="Token name")
    parser_create.add_argument("symbol", type=str, help="Token symbol")
    parser_create.add_argument("decimals", type=int, help="Token decimals")
    parser_create.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_create.add_argument("--wif-key", type=str, help="Optional WIF key for signing")

    # Command: gettokenbalance
    parser_getbal = subparsers.add_parser("gettokenbalance", help="Get token balance for this wallet (or WIF key)")
    parser_getbal.add_argument("token", type=str, help="Token ID")
    parser_getbal.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_getbal.add_argument("--address", type=str, help="Optional address (if omitted, uses wallet default)")
    parser_getbal.add_argument("--wif-key", type=str, help="Derive address from WIF key")

    # Command: gettokenbalanceof
    parser_getbalof = subparsers.add_parser("gettokenbalanceof", help="Get token balance of a specific address")
    parser_getbalof.add_argument("token", type=str, help="Token ID")
    parser_getbalof.add_argument("address", type=str, help="Address to check")

    # Command: tokenapprove
    parser_approve = subparsers.add_parser("tokenapprove", help="Approve a spender")
    parser_approve.add_argument("spender", type=str, help="Spender address")
    parser_approve.add_argument("token", type=str, help="Token ID")
    parser_approve.add_argument("amount", type=str, help="Amount to approve")
    parser_approve.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_approve.add_argument("--wif-key", type=str, help="Optional WIF key for signing")

    # Command: tokenallowance
    parser_allowance = subparsers.add_parser("tokenallowance", help="Check allowance")
    parser_allowance.add_argument("owner", type=str, help="Owner address")
    parser_allowance.add_argument("spender", type=str, help="Spender address")
    parser_allowance.add_argument("token", type=str, help="Token ID")

    # Command: tokentransfer
    parser_transfer = subparsers.add_parser("tokentransfer", help="Transfer tokens")
    parser_transfer.add_argument("to", type=str, help="Destination address")
    parser_transfer.add_argument("token", type=str, help="Token ID")
    parser_transfer.add_argument("amount", type=str, help="Amount to transfer")
    parser_transfer.add_argument("--memo", type=str, default="", help="Optional memo")
    parser_transfer.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_transfer.add_argument("--wif-key", type=str, help="Optional WIF key for signing")

    # Command: tokentransferfrom
    parser_transfer_from = subparsers.add_parser("tokentransferfrom", help="Transfer tokens using allowance")
    parser_transfer_from.add_argument("from_addr", type=str, help="Source address (owner)")
    parser_transfer_from.add_argument("to", type=str, help="Destination address")
    parser_transfer_from.add_argument("token", type=str, help="Token ID")
    parser_transfer_from.add_argument("amount", type=str, help="Amount to transfer")
    parser_transfer_from.add_argument("--memo", type=str, default="", help="Optional memo")
    parser_transfer_from.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_transfer_from.add_argument("--wif-key", type=str, help="Optional WIF key for signing")

    # Command: tokenincreaseallowance
    parser_inc_allowance = subparsers.add_parser("tokenincreaseallowance", help="Increase allowance")
    parser_inc_allowance.add_argument("spender", type=str, help="Spender address")
    parser_inc_allowance.add_argument("token", type=str, help="Token ID")
    parser_inc_allowance.add_argument("amount", type=str, help="Amount to increase")
    parser_inc_allowance.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_inc_allowance.add_argument("--wif-key", type=str, help="Optional WIF key for signing")

    # Command: tokendecreaseallowance
    parser_dec_allowance = subparsers.add_parser("tokendecreaseallowance", help="Decrease allowance")
    parser_dec_allowance.add_argument("spender", type=str, help="Spender address")
    parser_dec_allowance.add_argument("token", type=str, help="Token ID")
    parser_dec_allowance.add_argument("amount", type=str, help="Amount to decrease")
    parser_dec_allowance.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_dec_allowance.add_argument("--wif-key", type=str, help="Optional WIF key for signing")

    # Command: tokenburn
    parser_burn = subparsers.add_parser("tokenburn", help="Burn tokens")
    parser_burn.add_argument("token", type=str, help="Token ID")
    parser_burn.add_argument("amount", type=str, help="Amount to burn")
    parser_burn.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_burn.add_argument("--wif-key", type=str, help="Optional WIF key for signing")

    # Command: tokenmint
    parser_mint = subparsers.add_parser("tokenmint", help="Mint tokens (operator only)")
    parser_mint.add_argument("token", type=str, help="Token ID")
    parser_mint.add_argument("amount", type=str, help="Amount to mint")
    parser_mint.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_mint.add_argument("--wif-key", type=str, help="Optional WIF key for signing")

    # Command: tokentransferownership
    parser_ownership = subparsers.add_parser("tokentransferownership", help="Transfer token ownership to new operator")
    parser_ownership.add_argument("token", type=str, help="Token ID")
    parser_ownership.add_argument("new_owner", type=str, help="New operator address")
    parser_ownership.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_ownership.add_argument("--wif-key", type=str, help="Optional WIF key for signing")

    # Command: tokentotalsupply
    parser_supply = subparsers.add_parser("tokentotalsupply", help="Get total token supply")
    parser_supply.add_argument("token", type=str, help="Token ID")

    # Command: getgovernancebalance
    subparsers.add_parser("getgovernancebalance", help="Get accumulated network token fees")

    # Command: my_tokens
    parser_my = subparsers.add_parser("my_tokens", help="List all tokens owned by this wallet (or WIF key)")
    parser_my.add_argument("--witness", action="store_true", help="Use witness signer")
    parser_my.add_argument("--wif-key", type=str, help="List tokens owned by this WIF key")

    # Command: all_tokens
    subparsers.add_parser("all_tokens", help="List all known tokens in the ledger")

    # Command: token_history
    parser_hist = subparsers.add_parser("token_history", help="List token operation history")
    parser_hist.add_argument("token", type=str, help="Token ID")
    parser_hist.add_argument("--filter", type=str, help="Optional address filter")

    # Command: token_meta
    parser_meta = subparsers.add_parser("token_meta", help="Get token metadata")
    parser_meta.add_argument("token", type=str, help="Token ID")

    # Command: token_tx_memo
    parser_memo = subparsers.add_parser("token_tx_memo", help="Get memo string for a specific token txid")
    parser_memo.add_argument("token", type=str, help="Token ID")
    parser_memo.add_argument("txid", type=str, help="Transaction hash")

    # Command: rescan_tokentx
    parser_rescan = subparsers.add_parser("rescan_tokentx", help="Rescan blockchain for token operations")
    parser_rescan.add_argument("--from-height", type=int, help="Height to rescan from")

    args = parser.parse_args()
    
    client = ITSLClient(args.rpcuser, args.rpcpass, args.rpchost, args.rpcport, args.wallet)

    try:
        result = _execute_command(client, args)
        print(json.dumps(result, indent=2))
    except Exception as e:
        print(f"Error ({args.command}): {e}")
        import sys
        sys.exit(1)

if __name__ == "__main__":
    main()

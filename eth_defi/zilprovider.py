import hashlib

from pyzil.zilliqa.chain import BlockChain, set_active_chain, active_chain
from pyzil.account import Account
from pyzil.crypto.zilkey import to_checksum_address

from web3.providers.base import JSONBaseProvider
from web3 import Web3

def getSenderFromPubKey(pubkey):
    m = hashlib.sha256()
    m.update(Web3.toBytes(hexstr=pubkey))
    return to_checksum_address("0x" + m.digest()[-20:].hex())


class ZilProvider(JSONBaseProvider):

    endpoint = "http://localhost:5555"
    private_key = "d96e9eb5b782a80ea153c937fa83e5948485fbfc8b7e7c069d7b914dbc350aba"

    def __init__(self):
        self.blockchain = BlockChain(api_url=self.endpoint,
                                     version=65537,
                                     network_id=1)
        set_active_chain(self.blockchain)
        self.account = Account(private_key=self.private_key)

    def make_request(self, method: RPCEndpoint, params: Any) -> RPCResponse:
        return self.__call__(method, *params)

    def web3_clientVersion(self):
        return "Zilliqa/v0.8.2/linux/cpp"

    def web3_sha(self, data):
        return keccack256(data)

    def net_version(self):
        return "33001"

    def net_listening(self):
        return True   # In fact might not be listening.

    def net_peerCount(self):
        return "0x1"

    def eth_protocolVersion(self):
        return "54"   # See the default example in the spec.

    def eth_syncing(self):
        return False  # Always fully synced.

    def eth_coinbase(self):
        return "0x0000000000000000000000000000000000000000"

    def eth_mining(self):
        return False

    def eth_hashrate(self):
        return "0x0"

    def eth_gasPrice(self):
        return "0x77359400"  # 2000000000

    def eth_accounts(self):
        return []  # maybe ["0x381f4008505e940ad7681ec3468a719060caf796"]

    def eth_blockNumber(self):
        return active_chain.api.GetBlockchainInfo().get("NumTxBlocks", "0x0")

    def eth_getBalance(self, address, _tag):
        return active_chain.api.GetBalance(to_checksum_address(address)).get("balance", "0x0")

    def eth_getStorageAt(self, address, position, _tag):
        substate = active_chain.api.GetSmartContractSubState(
            address, "_evm_storage",
            ["\"{:040x}\"".format(position)])
        return substate

    def eth_getTransactionCount(self, address, _tag):
        return active_chain.api.GetBalance(to_checksum_address(address)).get("nonce", "0x0")


    def eth_getBlockTransactionCountByNumber(self, block_number):
        try:
            bn = int(block_number)
            result = active_chain.api.GetTxBlock(bn)
        except ValueError:
            result = active_chain.api.GetLatestTxBlock()
        return (result.get("nonce", "0x0")
                .get("header", {})
                .get("NumTxns", 0))

    def eth_getBlockTransactionCountByHash(self, block_hash):
        # In Zilliqa, we can only get a block by number, so we pretend block_hash is a number.
        return self.eth_getBlockTransactionCountByNumber(block_hash)

    def eth_getUncleCountByBlockNumber(self, _block_number):
        return "0x0"

    def eth_getUncleCountByBlockHash(self, _block_number):
        return "0x0"

    def get_getCode(self, address, _tag):
        return active_chain.api.GetSmartContractCode(to_checksum_address(address)).get("code", "")

    def eth_sign(self, address, data):
        raise NotImplementedError

    def eth_signTransaction(self, *params):
        raise NotImplementedError  # No way to separately sign/send transaction in Zilliqa

    def eth_signRawTransaction(self, *params):
        raise NotImplementedError  # No way to separately sign/send transaction in Zilliqa

    def eth_sendTransaction(self, txn):
        txn_param = {}
        if not "value" in txn:
            txn["value"] = 0
        if not "to" in txn:
            txn_param = zil.contract_deploy(txn["data"])
            txn_details = self.account.transfer(to_addr="0x0000000000000000000000000000000000000000",
                                                zils=0,
                                                code=txn["data"].replace("0x", "EVM"),
                                                gas_limit=100_000_000, #default for now
                                                priority=True,
                                                data="",  # TODO: Change for constructor params.
                                                confirm=True)
        elif "data" in txn:
            txn_details = self.account.transfer(to_addr=to_checksum_address(txn["to"]),
                                                zils=value,
                                                gas_limit=100_000, #default for now
                                                data=txn["data"].replace("0x",""),
                                                confirm=True)
        return "0x" + txn_details["ID"]

    def eth_call(self, txn):
        return active_chain.api.GetEthCall({"toAddr": to_checksum_address(txn["to"]),
                                            "data": txn["data"].replace("0x","")})

    def eth_estimateGas(self, _txn):
        return "0x186a0"

    def eth_feeHistory(self, _obj):
        # Some constants. TODO: Read EIP 1559, and implement something reasonable.
        return {
            "oldestBlock": self.eth_blockNumber(),
            "reward": [
                [
                    "0x4a817c7ee",
                    "0x4a817c7ee",
                ]
            ],
            "baseFeePerGas": [
                "0x12",
            ],
            "gasUsedRatio": [
                0.026,
            ]
        }

    def eth_getTransactionByBlockHashAndIndex(self, *params):
        raise NotImplementeError

    def eth_getTransactionByBlockNumberAndIndex(self, *params):
        raise NotImplementeError

    def eth_getTransactionByHash(self, txn_hash):
        txn = active_chain.api.GetTransaction(txn_hash)
        return {
            "blockHash": result.get("body", {}).get("BlockHash", "0x0"),
            "blockNumber": result.get("header", {}).get("BlockNum", "0x0"),
            "from": getSenderFromPubKey(result.get("senderPubKey", "")),
            "gas": None,  # maybe result.get("receipt", {}).get("cumulative_gas"),
            "gasPrice": result.get("gasPrice", "0x0"),
            "hash": result.get("ID"),
            "input": result.get("data"),
            "nonce": result.get("nonce"),
            "to": result.get("to", None),
            "transactionIndex": "0x0",  # Dummy.
            "value": result.get("amount", "0x0"),
            # TODO: get v, r, s from the transaction.
            "v": None, 
            "r": None,
            "s": None,
        }

    def eth_getTransactionReceipt(self, txn_hash):
        txn = active_chain.api.GetTransaction(txn_hash)
        return {
            "transactionHash": result.get("ID"),
            "transactionIndex": "0x0",  # Dummy.
            "blockHash":  result.get("body", {}).get("BlockHash", "0x0"),
            "blockNumber": result.get("header", {}).get("BlockNum", "0x0"),
            "from": getSenderFromPubKey(result.get("senderPubKey", "")),
            "to": result.get("to", None),
            "cumulativeGasUsed": result.get("receipt", {}).get("cumulative_gas"),
            "gasUsed": None,
            "contractAddress": "0x0",
            "logs": [],   # TODO: retreive real logs
            "status": "0x1",
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        }

    def eth_getLogs(self, _req_obj):
        return []

    def get_getFilterChanges(self, _filter_id):
        return []

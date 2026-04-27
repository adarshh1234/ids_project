"""
blockchain/ganache_chain.py
===========================
Ganache/Ethereum blockchain integration — compatible with web3 v7
"""

import json
import time
from pathlib import Path

try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    WEB3_AVAILABLE = False
    print("⚠️  web3 not installed. Run: pip install web3")

try:
    from solcx import compile_source, install_solc
    SOLCX_AVAILABLE = True
except ImportError:
    SOLCX_AVAILABLE = False

BASE_DIR      = Path(__file__).parent
CONTRACT_FILE = BASE_DIR / 'IDSAuditLog.sol'
DEPLOY_FILE   = BASE_DIR / 'deployment.json'
GANACHE_URL   = 'http://127.0.0.1:7545'


class GanacheBlockchain:

    def __init__(self, ganache_url: str = GANACHE_URL):
        self.ganache_url = ganache_url
        self.w3          = None
        self.contract    = None
        self.account     = None
        self._connected  = False
        self._connect()

    def _connect(self):
        if not WEB3_AVAILABLE:
            print("❌ web3 not available")
            return
        try:
            self.w3 = Web3(Web3.HTTPProvider(self.ganache_url))
            if self.w3.is_connected():
                self.account    = self.w3.eth.accounts[0]
                self._connected = True
                print(f"✅ Connected to Ganache at {self.ganache_url}")
                print(f"   Using account: {self.account}")
                self._load_or_deploy()
            else:
                print(f"❌ Cannot connect to Ganache at {self.ganache_url}")
                print("   Make sure Ganache is running!")
        except Exception as e:
            print(f"❌ Ganache connection error: {e}")

    def _compile_contract(self) -> dict:
        if not SOLCX_AVAILABLE:
            raise RuntimeError("solcx not installed. Run: pip install py-solc-x")
        print("🔨 Compiling IDSAuditLog.sol...")
        install_solc('0.8.0')
        with open(CONTRACT_FILE, 'r') as f:
            source = f.read()
        compiled = compile_source(
            source,
            output_values=['abi', 'bin'],
            solc_version='0.8.0'
        )
        contract_interface = compiled['<stdin>:IDSAuditLog']
        print("✅ Contract compiled successfully")
        return contract_interface

    def _deploy_contract(self) -> dict:
        contract_interface = self._compile_contract()
        abi      = contract_interface['abi']
        bytecode = contract_interface['bin']
        print("🚀 Deploying contract to Ganache...")
        Contract   = self.w3.eth.contract(abi=abi, bytecode=bytecode)
        tx_hash    = Contract.constructor().transact({'from': self.account, 'gas': 3000000})
        tx_receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
        contract_address = tx_receipt.contractAddress
        print(f"✅ Contract deployed at: {contract_address}")
        deployment = {
            'contract_address': contract_address,
            'abi':              abi,
            'tx_hash':          tx_hash.hex(),
            'deployed_at':      time.time(),
            'network':          'Ganache (localhost:7545)',
            'deployer':         self.account,
        }
        with open(DEPLOY_FILE, 'w') as f:
            json.dump(deployment, f, indent=2)
        return deployment

    def _load_or_deploy(self):
        if DEPLOY_FILE.exists():
            try:
                with open(DEPLOY_FILE, 'r') as f:
                    deployment = json.load(f)
                address = deployment['contract_address']
                abi     = deployment['abi']
                code    = self.w3.eth.get_code(address)
                if code and code != b'' and code.hex() != '0x':
                    self.contract = self.w3.eth.contract(address=address, abi=abi)
                    print(f"✅ Loaded existing contract at {address}")
                    return
                else:
                    print("⚠️  Contract not found on chain. Redeploying...")
            except Exception as e:
                print(f"⚠️  Could not load deployment: {e}. Deploying fresh...")
        deployment    = self._deploy_contract()
        self.contract = self.w3.eth.contract(
            address=deployment['contract_address'],
            abi=deployment['abi']
        )

    @property
    def is_connected(self) -> bool:
        return self._connected and self.contract is not None

    def add_alert(self, alert_data: dict) -> dict:
        if not self.is_connected:
            return {'error': 'Not connected to Ganache'}
        try:
            top_feats     = alert_data.get('top_features', [])[:3]
            top_feats_str = json.dumps([
                {'feature': f['feature'], 'value': round(f['shap_value'], 4)}
                for f in top_feats
            ])
            alert_id   = int(alert_data.get('alert_id', 0))
            attack_cat = str(alert_data.get('attack_category', 'Unknown'))
            severity   = str(alert_data.get('severity', 'info'))
            source_ip  = str(alert_data.get('source_ip', '0.0.0.0'))
            dest_ip    = str(alert_data.get('destination_ip', '0.0.0.0'))
            confidence = int(float(alert_data.get('confidence', 0)) * 100)

            tx_hash = self.contract.functions.logAlert(
                alert_id, attack_cat, severity,
                source_ip, dest_ip, confidence, top_feats_str,
            ).transact({'from': self.account, 'gas': 500000})

            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash)
            block   = self.w3.eth.get_block(receipt.blockNumber)

            return {
                'tx_hash':      tx_hash.hex(),
                'block_number': receipt.blockNumber,
                'block_hash':   block['hash'].hex(),
                'gas_used':     receipt.gasUsed,
                'contract':     self.contract.address,
                'network':      'Ganache Ethereum (localhost:7545)',
                'from_account': self.account,
                'status':       'success' if receipt.status == 1 else 'failed',
            }
        except Exception as e:
            return {'error': str(e)}

    def get_all_alerts(self) -> list:
        if not self.is_connected:
            return []
        try:
            ids    = self.contract.functions.getAllAlertIds().call()
            result = []
            for aid in ids:
                try:
                    a = self.contract.functions.getAlert(aid).call()
                    result.append({
                        'alert_id':        a[0],
                        'attack_category': a[1],
                        'severity':        a[2],
                        'source_ip':       a[3],
                        'destination_ip':  a[4],
                        'confidence':      a[5] / 100.0,
                        'top_features':    a[6],
                        'timestamp':       a[7],
                    })
                except Exception:
                    continue
            return result
        except Exception as e:
            print(f"Error fetching alerts: {e}")
            return []

    def get_chain_info(self) -> dict:
        if not self.is_connected:
            return {'connected': False}
        try:
            return {
                'connected':        True,
                'network':          'Ganache Ethereum',
                'chain_id':         self.w3.eth.chain_id,
                'block_number':     self.w3.eth.block_number,
                'contract_address': self.contract.address,
                'account':          self.account,
                'balance_eth':      float(self.w3.from_wei(
                    self.w3.eth.get_balance(self.account), 'ether'
                )),
                'alert_count': self.contract.functions.getAlertCount().call(),
            }
        except Exception as e:
            return {'connected': False, 'error': str(e)}

    def verify_alert(self, alert_id: int) -> dict:
        if not self.is_connected:
            return {'verified': False, 'error': 'Not connected'}
        try:
            exists = self.contract.functions.verifyAlert(alert_id).call()
            return {
                'verified': exists,
                'alert_id': alert_id,
                'network':  'Ganache Ethereum',
                'contract': self.contract.address,
            }
        except Exception as e:
            return {'verified': False, 'error': str(e)}

    def get_recent_transactions(self, count: int = 10) -> list:
        if not self.is_connected:
            return []
        try:
            latest = self.w3.eth.block_number
            txs    = []
            for bn in range(max(0, latest - count), latest + 1):
                block = self.w3.eth.get_block(bn, full_transactions=True)
                for tx in block.transactions:
                    receipt = self.w3.eth.get_transaction_receipt(tx['hash'])
                    txs.append({
                        'tx_hash':      tx['hash'].hex(),
                        'block_number': bn,
                        'block_hash':   block['hash'].hex(),
                        'from':         tx['from'],
                        'to':           tx.get('to') or 'Contract Creation',
                        'gas':          tx['gas'],
                        'gas_used':     receipt.gasUsed,
                        'status':       receipt.status,
                        'timestamp':    block['timestamp'],
                    })
            return txs[-count:]
        except Exception as e:
            return []


# ── Singleton ──────────────────────────────────────────────────────────────────
_ganache_instance = None

def get_ganache() -> GanacheBlockchain:
    global _ganache_instance
    if _ganache_instance is None:
        _ganache_instance = GanacheBlockchain()
    return _ganache_instance
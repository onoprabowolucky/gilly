import os
import time
import logging
import json
from typing import Dict, Any, List, Optional, Set

import requests
from web3 import Web3
from web3.middleware import geth_poa_middleware
from web3.exceptions import TransactionNotFound, BlockNotFound
from dotenv import load_dotenv

# --- Basic Configuration ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

# Load environment variables from a .env file
load_dotenv()

# --- Constants and Mock Data ---
# In a real-world scenario, ABIs would be loaded from JSON files.
# Mock ABI for the source chain bridge contract with a 'TokensDeposited' event.
SOURCE_CHAIN_BRIDGE_ABI = json.dumps([
    {
        "anonymous": False,
        "inputs": [
            {"indexed": True, "internalType": "address", "name": "sender", "type": "address"},
            {"indexed": True, "internalType": "address", "name": "recipient", "type": "address"},
            {"indexed": False, "internalType": "uint256", "name": "amount", "type": "uint256"},
            {"indexed": False, "internalType": "uint256", "name": "destinationChainId", "type": "uint256"}
        ],
        "name": "TokensDeposited",
        "type": "event"
    }
])

# Mock ABI for the destination chain bridge contract with a 'releaseTokens' function.
DESTINATION_CHAIN_BRIDGE_ABI = json.dumps([
    {
        "inputs": [
            {"internalType": "address", "name": "recipient", "type": "address"},
            {"internalType": "uint256", "name": "amount", "type": "uint256"},
            {"internalType": "bytes32", "name": "sourceTxHash", "type": "bytes32"}
        ],
        "name": "releaseTokens",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
])

# --- Component Classes ---

class BlockchainConnector:
    """Handles the connection to a specific blockchain via a Web3 provider."""

    def __init__(self, rpc_url: str):
        """
        Initializes the Web3 provider and tests the connection.

        Args:
            rpc_url (str): The HTTP RPC endpoint URL for the blockchain node.
        """
        self.rpc_url = rpc_url
        self.web3 = Web3(Web3.HTTPProvider(self.rpc_url))

        # Inject middleware for PoA chains like Goerli or Polygon Mumbai
        self.web3.middleware_onion.inject(geth_poa_middleware, layer=0)

        if not self.web3.is_connected():
            logging.error(f"Failed to connect to blockchain node at {self.rpc_url}")
            raise ConnectionError(f"Unable to connect to {self.rpc_url}")
        
        logging.info(f"Successfully connected to blockchain node. Chain ID: {self.web3.eth.chain_id}")

    def get_web3_instance(self) -> Web3:
        """Returns the configured Web3 instance."""
        return self.web3

    def get_latest_block_number(self) -> int:
        """Fetches the latest block number from the connected node."""
        try:
            return self.web3.eth.block_number
        except Exception as e:
            logging.error(f"Could not fetch latest block number: {e}")
            # In a production system, this might trigger a reconnect or alert.
            return 0

class EventScanner:
    """Scans a range of blocks for specific smart contract events."""

    def __init__(self, connector: BlockchainConnector, contract_address: str, contract_abi: str, event_name: str):
        """
        Initializes the scanner with contract details.

        Args:
            connector (BlockchainConnector): The connector for the blockchain to scan.
            contract_address (str): The address of the smart contract to monitor.
            contract_abi (str): The ABI of the smart contract.
            event_name (str): The name of the event to listen for.
        """
        self.web3 = connector.get_web3_instance()
        self.contract_address = self.web3.to_checksum_address(contract_address)
        self.contract = self.web3.eth.contract(address=self.contract_address, abi=contract_abi)
        self.event_name = event_name
        self.event = getattr(self.contract.events, self.event_name, None)

        if not self.event:
            raise ValueError(f"Event '{self.event_name}' not found in the provided ABI.")

    def scan_blocks(self, from_block: int, to_block: int) -> List[Dict[str, Any]]:
        """
        Scans a given range of blocks for the configured event.

        Args:
            from_block (int): The starting block number (inclusive).
            to_block (int): The ending block number (inclusive).

        Returns:
            List[Dict[str, Any]]: A list of decoded event logs.
        """
        if from_block > to_block:
            return []

        logging.info(f"Scanning blocks from {from_block} to {to_block} for '{self.event_name}' events.")
        try:
            event_filter = self.event.create_filter(fromBlock=from_block, toBlock=to_block)
            events = event_filter.get_all_entries()
            if events:
                logging.info(f"Found {len(events)} '{self.event_name}' event(s) in block range.")
            return events
        except (BlockNotFound, ValueError) as e:
            # ValueError can be raised for block range too large, etc.
            logging.warning(f"Could not scan block range {from_block}-{to_block}: {e}")
            return []
        except Exception as e:
            logging.error(f"An unexpected error occurred during event scanning: {e}")
            return []

class OracleValidator:
    """Simulates an off-chain oracle service to validate bridge events."""

    def __init__(self, oracle_api_url: str):
        """
        Args:
            oracle_api_url (str): The API endpoint of the oracle service.
        """
        self.api_url = oracle_api_url

    def validate_event(self, event_data: Dict[str, Any]) -> bool:
        """
        Sends event data to an oracle for external validation.
        In this simulation, it's a mock API call that always returns true on success.

        Args:
            event_data (Dict[str, Any]): The event log data.

        Returns:
            bool: True if the event is valid, False otherwise.
        """
        tx_hash = event_data.get('transactionHash').hex()
        logging.info(f"Requesting validation for transaction {tx_hash} from oracle at {self.api_url}")

        payload = {
            'transactionHash': tx_hash,
            'blockNumber': event_data.get('blockNumber'),
            'eventDetails': {
                'sender': event_data.get('args', {}).get('sender'),
                'recipient': event_data.get('args', {}).get('recipient'),
                'amount': event_data.get('args', {}).get('amount'),
            }
        }

        try:
            # In a real system, you'd use a real endpoint. We use a mock service for simulation.
            response = requests.post(self.api_url, json=payload, timeout=10)
            response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)
            
            validation_result = response.json()
            if validation_result.get('isValid'):
                logging.info(f"Oracle validation successful for {tx_hash}.")
                return True
            else:
                logging.warning(f"Oracle validation failed for {tx_hash}: {validation_result.get('reason')}")
                return False
        except requests.exceptions.RequestException as e:
            logging.error(f"Could not connect to oracle service for {tx_hash}: {e}")
            return False

class TransactionRelayer:
    """Constructs, signs, and sends transactions to a destination chain."""

    def __init__(self, connector: BlockchainConnector, private_key: str, contract_address: str, contract_abi: str):
        """
        Initializes the relayer with destination chain details.

        Args:
            connector (BlockchainConnector): The connector for the destination blockchain.
            private_key (str): The private key of the relayer account.
            contract_address (str): The bridge contract address on the destination chain.
            contract_abi (str): The ABI of the destination bridge contract.
        """
        self.web3 = connector.get_web3_instance()
        self.chain_id = self.web3.eth.chain_id
        self.account = self.web3.eth.account.from_key(private_key)
        self.address = self.account.address
        self.contract_address = self.web3.to_checksum_address(contract_address)
        self.contract = self.web3.eth.contract(address=self.contract_address, abi=contract_abi)
        logging.info(f"TransactionRelayer initialized for address {self.address} on chain {self.chain_id}.")

    def relay_transaction(self, recipient: str, amount: int, source_tx_hash: bytes) -> Optional[str]:
        """
        Builds and sends the 'releaseTokens' transaction.

        Args:
            recipient (str): The final recipient of the tokens.
            amount (int): The amount of tokens to release.
            source_tx_hash (bytes): The hash of the original deposit transaction.

        Returns:
            Optional[str]: The transaction hash if successful, otherwise None.
        """
        try:
            logging.info(f"Relaying transaction for recipient {recipient}, amount {amount}.")
            
            # 1. Get the current nonce for the relayer account
            nonce = self.web3.eth.get_transaction_count(self.address)

            # 2. Build the transaction
            tx_data = self.contract.functions.releaseTokens(
                self.web3.to_checksum_address(recipient),
                amount,
                source_tx_hash
            ).build_transaction({
                'chainId': self.chain_id,
                'from': self.address,
                'nonce': nonce,
                'gas': 200000, # This should ideally be estimated using `estimate_gas`
                'gasPrice': self.web3.eth.gas_price
            })

            # 3. Sign the transaction
            signed_tx = self.web3.eth.account.sign_transaction(tx_data, self.account.key)

            # 4. Send the transaction
            tx_hash = self.web3.eth.send_raw_transaction(signed_tx.rawTransaction)
            logging.info(f"Sent release transaction to destination chain. Tx Hash: {tx_hash.hex()}")

            # 5. Wait for the transaction receipt (optional, but good practice)
            receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash, timeout=120)
            if receipt.status == 1:
                logging.info(f"Transaction {tx_hash.hex()} confirmed successfully.")
                return tx_hash.hex()
            else:
                logging.error(f"Transaction {tx_hash.hex()} failed (reverted).")
                return None

        except Exception as e:
            logging.error(f"Failed to relay transaction: {e}")
            return None


class BridgeListener:
    """Main orchestrator for the cross-chain bridge event listener."""

    def __init__(self, config: Dict[str, Any]):
        """
        Initializes all components of the listener based on the provided configuration.
        """
        self.config = config
        self.poll_interval_seconds = config.get('POLL_INTERVAL_SECONDS', 15)
        self.block_processing_limit = config.get('BLOCK_PROCESSING_LIMIT', 100)

        # --- Component Initialization ---
        logging.info("Initializing BridgeListener components...")
        self.source_connector = BlockchainConnector(config['SOURCE_CHAIN_RPC_URL'])
        self.dest_connector = BlockchainConnector(config['DESTINATION_CHAIN_RPC_URL'])

        self.event_scanner = EventScanner(
            connector=self.source_connector,
            contract_address=config['SOURCE_BRIDGE_CONTRACT'],
            contract_abi=SOURCE_CHAIN_BRIDGE_ABI,
            event_name='TokensDeposited'
        )

        self.oracle_validator = OracleValidator(config['ORACLE_API_URL'])
        
        self.transaction_relayer = TransactionRelayer(
            connector=self.dest_connector,
            private_key=config['RELAYER_PRIVATE_KEY'],
            contract_address=config['DESTINATION_BRIDGE_CONTRACT'],
            contract_abi=DESTINATION_CHAIN_BRIDGE_ABI
        )

        # --- State Management ---
        # In a production system, this state should be persisted (e.g., in a file or DB).
        self.last_processed_block = config.get('START_BLOCK') or self.source_connector.get_latest_block_number() - 1
        self.processed_tx_hashes: Set[str] = set()
        logging.info(f"BridgeListener initialized. Starting scan from block {self.last_processed_block + 1}.")


    def _process_event(self, event: Dict[str, Any]):
        """Handles the validation and relaying of a single detected event."""
        tx_hash_hex = event['transactionHash'].hex()
        if tx_hash_hex in self.processed_tx_hashes:
            logging.warning(f"Skipping already processed transaction: {tx_hash_hex}")
            return

        logging.info(f"Processing new event from transaction: {tx_hash_hex}")

        # 1. Validate the event with the oracle
        is_valid = self.oracle_validator.validate_event(event)
        if not is_valid:
            logging.warning(f"Event validation failed for {tx_hash_hex}. Skipping.")
            return
        
        # 2. If valid, relay the transaction to the destination chain
        event_args = event['args']
        relay_tx_hash = self.transaction_relayer.relay_transaction(
            recipient=event_args['recipient'],
            amount=event_args['amount'],
            source_tx_hash=event['transactionHash']
        )

        if relay_tx_hash:
            logging.info(f"Successfully relayed event from {tx_hash_hex} via destination tx {relay_tx_hash}")
            self.processed_tx_hashes.add(tx_hash_hex)
        else:
            logging.error(f"Failed to relay event from {tx_hash_hex}. Will retry on next cycle.")


    def run(self):
        """The main execution loop for the bridge listener."""
        logging.info("Starting bridge listener main loop. Press Ctrl+C to exit.")
        try:
            while True:
                # Determine the range of blocks to scan
                latest_block = self.source_connector.get_latest_block_number()
                if self.last_processed_block >= latest_block:
                    logging.info(f"No new blocks to process. Current block: {latest_block}. Sleeping...")
                    time.sleep(self.poll_interval_seconds)
                    continue
                
                # To avoid overwhelming the RPC node, process blocks in chunks
                to_block = min(latest_block, self.last_processed_block + self.block_processing_limit)
                from_block = self.last_processed_block + 1

                # Scan for events
                events = self.event_scanner.scan_blocks(from_block, to_block)

                for event in events:
                    self._process_event(event)
                
                # Update the state to the last block we've successfully scanned
                self.last_processed_block = to_block
                
                time.sleep(self.poll_interval_seconds)

        except KeyboardInterrupt:
            logging.info("Shutdown signal received. Exiting gracefully.")
        except Exception as e:
            logging.critical(f"A critical error occurred in the main loop: {e}", exc_info=True)

def main():
    """Entry point for the script."""
    # --- Configuration Loading ---
    # This configuration would come from a secure source in a real application
    required_vars = [
        'SOURCE_CHAIN_RPC_URL',
        'DESTINATION_CHAIN_RPC_URL',
        'SOURCE_BRIDGE_CONTRACT',
        'DESTINATION_BRIDGE_CONTRACT',
        'RELAYER_PRIVATE_KEY',
        'ORACLE_API_URL' # e.g., 'https://api.mock-oracle.com/validate'
    ]
    config = {var: os.getenv(var) for var in required_vars}
    
    # Validate that all required environment variables are set
    if not all(config.values()):
        missing_vars = [key for key, value in config.items() if not value]
        logging.error(f"Missing required environment variables: {', '.join(missing_vars)}")
        return

    # Optional config with defaults
    config['POLL_INTERVAL_SECONDS'] = int(os.getenv('POLL_INTERVAL_SECONDS', '15'))
    config['BLOCK_PROCESSING_LIMIT'] = int(os.getenv('BLOCK_PROCESSING_LIMIT', '100'))
    start_block_str = os.getenv('START_BLOCK')
    config['START_BLOCK'] = int(start_block_str) if start_block_str else None

    try:
        listener = BridgeListener(config)
        listener.run()
    except (ConnectionError, ValueError) as e:
        logging.critical(f"Failed to initialize BridgeListener: {e}")
    except Exception as e:
        logging.critical(f"An unexpected error occurred during setup: {e}", exc_info=True)


if __name__ == '__main__':
    main()

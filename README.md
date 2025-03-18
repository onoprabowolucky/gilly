# Gilly - Cross-Chain Bridge Event Listener Simulation

This repository contains `gilly`, a sophisticated Python script that simulates the operation of a relayer node for a cross-chain bridge. It is designed to listen for specific events on a source blockchain, validate them through a mock oracle, and then trigger a corresponding transaction on a destination blockchain.

This project serves as an architectural blueprint for building robust, modular, and resilient off-chain components for decentralized systems.

## Concept

A cross-chain bridge allows users to transfer assets or data from one blockchain (the 'source chain') to another (the 'destination chain'). The process typically works as follows:

1.  A user deposits assets into a smart contract on the source chain. This action emits an event (e.g., `TokensDeposited`).
2.  Off-chain services, known as 'listeners' or 'relayers', monitor the source chain for these deposit events.
3.  Upon detecting an event, the relayer validates its authenticity and details. This may involve waiting for a certain number of block confirmations or consulting an external oracle service.
4.  Once validated, the relayer submits a transaction to a smart contract on the destination chain. This transaction instructs the contract to release or mint a corresponding amount of assets to the user's address on that chain.

`gilly` simulates the core logic of this relayer component (steps 2, 3, and 4).

## Code Architecture

The script is built with a modular, class-based architecture to separate concerns and enhance testability and maintainability. Each class has a distinct responsibility:

-   `BlockchainConnector`: A wrapper around the `web3.py` library that manages the connection to a specific blockchain's RPC node. It handles connection testing and basic data fetching, such as the latest block number.

-   `EventScanner`: Responsible for scanning a given range of blocks on the source chain for a specific smart contract event (e.g., `TokensDeposited`). It uses the `BlockchainConnector` to communicate with the node and decodes the event logs.

-   `OracleValidator`: Simulates an external validation service. It takes event data, formats it into a request, and sends it to a mock API endpoint using the `requests` library. This class represents the off-chain verification step crucial for bridge security.

-   `TransactionRelayer`: Manages the creation, signing, and broadcasting of transactions on the destination chain. It holds the relayer's private key, handles nonce management, and submits the transaction to release assets to the user.

-   `BridgeListener`: The main orchestrator class. It initializes and coordinates all the other components. Its `run()` method contains the main execution loop that periodically polls the source chain for new blocks, processes events, and manages the listener's state (like the last block it scanned).

## How it Works

The operational flow of the `gilly` script is as follows:

1.  **Initialization**: The `main` function loads configuration from environment variables (e.g., RPC URLs, contract addresses, private keys) using `python-dotenv`.

2.  **Setup**: The `BridgeListener` is instantiated. It creates instances of `BlockchainConnector` for both the source and destination chains, along with the `EventScanner`, `OracleValidator`, and `TransactionRelayer`.

3.  **Polling Loop**: The `BridgeListener.run()` method starts an infinite loop:
    a. It fetches the latest block number from the source chain.
    b. It determines the range of blocks to scan since the last run, ensuring not to query too many blocks at once to avoid overwhelming the RPC node.
    c. It calls `EventScanner.scan_blocks()` to find all instances of the target event within that range.

4.  **Event Processing**: For each event found:
    a. The event's transaction hash is checked against an in-memory set to prevent processing the same event twice.
    b. The `OracleValidator.validate_event()` method is called to simulate off-chain verification.
    c. If the oracle confirms the event's validity, the `TransactionRelayer.relay_transaction()` method is invoked.

5.  **Transaction Relaying**: The relayer constructs a new transaction to call the `releaseTokens` function on the destination bridge contract, signs it with the relayer's private key, and broadcasts it to the network.

6.  **State Update**: After scanning a block range, the listener updates its internal state (`last_processed_block`) to ensure it picks up where it left off in the next iteration.

7.  **Delay**: The loop pauses for a configurable interval (`POLL_INTERVAL_SECONDS`) before starting the next cycle.

## Usage Example

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/your-username/gilly.git
    cd gilly
    ```

2.  **Create a virtual environment and install dependencies:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
    pip install -r requirements.txt
    ```

3.  **Create a `.env` file** in the root of the project and populate it with your configuration details. Use placeholder URLs and keys for simulation.

    ```ini
    # .env file

    # RPC URL for the source chain (e.g., Ethereum Goerli)
    SOURCE_CHAIN_RPC_URL="https://goerli.infura.io/v3/YOUR_INFURA_PROJECT_ID"

    # RPC URL for the destination chain (e.g., Polygon Mumbai)
    DESTINATION_CHAIN_RPC_URL="https://polygon-mumbai.infura.io/v3/YOUR_INFURA_PROJECT_ID"

    # Address of the bridge contract on the source chain
    SOURCE_BRIDGE_CONTRACT="0x..."

    # Address of the bridge contract on the destination chain
    DESTINATION_BRIDGE_CONTRACT="0x..."

    # Private key for the relayer wallet (DO NOT USE A REAL KEY WITH VALUE IN A PUBLIC REPO)
    RELAYER_PRIVATE_KEY="0x..."

    # Mock oracle API endpoint for validation
    ORACLE_API_URL="https://httpbin.org/post" # httpbin.org is great for testing POST requests

    # Optional: Starting block to scan from (if not set, starts from the latest block)
    # START_BLOCK=8000000

    # Optional: How often to poll for new blocks, in seconds
    # POLL_INTERVAL_SECONDS=30
    ```

4.  **Run the script:**
    ```bash
    python script.py
    ```

5.  **Observe the output:** The console will display logs showing the listener's activity, such as connecting to nodes, scanning block ranges, and processing any found events.

    ```
    2023-10-27 15:30:00 - INFO - [blockchain_connector] - Successfully connected to blockchain node. Chain ID: 5
    2023-10-27 15:30:01 - INFO - [blockchain_connector] - Successfully connected to blockchain node. Chain ID: 80001
    2023-10-27 15:30:01 - INFO - [bridge_listener] - BridgeListener initialized. Starting scan from block 9500001.
    2023-10-27 15:30:01 - INFO - [bridge_listener] - Starting bridge listener main loop. Press Ctrl+C to exit.
    2023-10-27 15:30:05 - INFO - [event_scanner] - Scanning blocks from 9500001 to 9500100 for 'TokensDeposited' events.
    ...
    ```

# Platireum Network
![PLT-Logo](https://github.com/user-attachments/assets/2b3df40d-c052-4561-b0fd-a822b36b96c2)


<div align="center">



[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build Status](https://img.shields.io/github/workflow/status/platireumTech/Platireum-Network/CI)](https://github.com/platireumTech/Platireum-Network/actions)
[![GitHub Issues](https://img.shields.io/github/issues/platireumTech/Platireum-Network)](https://github.com/platireumTech/Platireum-Network/issues)
[![GitHub Stars](https://img.shields.io/github/stars/platireumTech/Platireum-Network)](https://github.com/platireumTech/Platireum-Network/stargazers)

🔗 Secure • ⚡ Fast • 💪 Scalable

</div>

Platireum Network is a cutting-edge hybrid blockchain-DAG system that integrates a novel **Proof of Computing (PoC)** consensus mechanism. This mechanism combines the security of a blockchain with the scalability of a Directed Acyclic Graph (DAG), enabling parallel transaction processing and efficient finality. It leverages **AI computation** for verifiable useful work and employs **value-based selection** for validators, ensuring a robust and fair network. The system utilizes a UTXO model and supports smart contracts through cryptographic validation.

## Overview

Platireum Network is a blockchain platform that provides a robust infrastructure for decentralized applications and digital asset management. The project implements core blockchain functionality, networking protocols, smart contracts, and efficient storage solutions.

## ✨ Features

- **Proof of Computing (PoC) Consensus**: A hybrid consensus mechanism integrating AI computation, value-based validator selection, and a dual TransactionDAG/FinalityChain architecture for enhanced security and scalability.
- **AI Computation Integration**: Verifiable AI computation as a core component of the consensus, rewarding useful work.
- **Value-Based Validator Selection**: A dynamic selection process for validators based on their staked capital and proven useful AI computation scores.
- **Smart Contracts**: Support for executing and managing smart contracts
- **API Integration**: RESTful API for easy integration with external services
- **Advanced Networking**: P2P networking capabilities for node communication
- **Efficient Storage**: Optimized storage solutions for blockchain data

## 🏗️ Project Structure

```
platireum-network/
├── src/
│   ├── ai_engine/     # AI computation engine and proof generation
│   ├── api/           # API implementation
│   ├── core/          # Core blockchain functionality
│   ├── networking/    # P2P networking components
│   ├── smart_contracts/ # Smart contract implementation
│   ├── storage/       # Storage management
│   ├── node.cpp      # Node implementation
│   ├── node.h        # Node header file
│   └── main.cpp      # Application entry point
└── CMakeLists.txt    # CMake build configuration
```

## 🚀 Building the Project

### Prerequisites

- C++ compiler with C++17 support
- CMake (version 3.10 or higher)
- OpenSSL library
- Boost library

### Build Instructions

1. Clone the repository:

```bash
git clone https://github.com/platireumTech/Platireum-Network.git
cd Platireum-Network
```

2. Create a build directory and run CMake:

```bash
mkdir build && cd build
cmake ..
make
```

## 👥 Contributing

Contributions are welcome! Please feel free to submit pull requests.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 📬 Contact

- Project Website: [https://platireum.com](https://platireum.com)
- GitHub: [https://github.com/platireumTech/Platireum-Network](https://github.com/platireumTech/Platireum-Network)

## 🙏 Acknowledgments

- Thanks to all contributors who have helped shape this project
- Special thanks to the blockchain community for their continuous support

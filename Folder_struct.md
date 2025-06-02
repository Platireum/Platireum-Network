blockchain_project/
├── src/
│   ├── main.cpp
│   ├── node.h
│   ├── node.cpp
│   ├── core/
│   │   ├── block.h
│   │   ├── block.cpp
│   │   ├── finality_chain.h
│   │   ├── finality_chain.cpp
│   │   ├── crypto_helper.h
│   │   ├── crypto_helper.cpp
│   │   ├── transaction.h
│   │   ├── transaction.cpp
│   │   ├── transaction_dag.h
│   │   ├── transaction_dag.cpp
│   │   ├── validator_manager.h
│   │   └── validator_manager.cpp
│   ├── storage/
│   │   ├── serializer.h
│   │   ├── storage_manager.h
│   │   └── storage_manager.cpp
│   ├── smart_contracts/
│   │   ├── contract.h
│   │   ├── contract.cpp
│   │   ├── vm_engine.h
│   │   └── vm_engine.cpp
│   └── api/
│       ├── api_server.h
│       ├── api_server.cpp
│       ├── cli_client.h
│       └── cli_client.cpp
├── CMakeLists.txt  (جديد - لتبسيط عملية البناء)
└── build/          (سيتم إنشاؤه بواسطة CMake)
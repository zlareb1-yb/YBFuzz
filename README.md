# YBFuzz: A Professional-Grade Fuzzing Framework for YugabyteDB

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-Apache%202.0-blue)
![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)

`YBFuzz` is a **Hybrid Generative-Mutational Fuzzing Framework** designed to be a highly autonomous, scalable, and intelligent system for finding deep logical, performance, and correctness bugs in YugabyteDB.

It combines a grammar-driven engine that generates novel queries from scratch with an intelligent mutational engine that learns from a corpus of real-world examples. This hybrid approach allows `YBFuzz` to achieve deep test coverage with minimal manual intervention.

---
## Key Features

* **Hybrid Fuzzing Engine:** Intelligently switches between a **Generative Engine** (for exploring fundamental SQL structures) and a **Mutational Engine** (for testing complex, real-world syntax learned from a corpus).

* **Pluggable Bug-Finding Oracles:** A suite of advanced, configurable oracles to detect a wide range of bugs:
    * **TLP (Ternary Logic Partitioning):** Finds correctness bugs in `WHERE` clause logic.
    * **NoREC (Non-optimizing Reference Engine):** Finds logic bugs by disabling optimizer features and comparing results.
    * **DQP (Differential Query Plans):** Finds optimizer bugs by comparing query plans before and after schema changes (e.g., adding an index).
    * **CERT (Cardinality Estimation Testing):** Finds planner bugs by validating row count estimates against actual results.

* **Autonomous & Scalable:** Designed to learn new SQL syntax and functions with minimal manual upkeep, making it easy to scale testing as YugabyteDB evolves.

* **Reproducible & Configurable:** Every bug report includes the random seed for perfect reproducibility. A powerful CLI and YAML configuration provide full control over every aspect of a fuzzing run.

---
## Architecture Overview

The framework is built on a modular, object-oriented design to ensure maximum scalability and maintainability.

```
ybfuzz_framework/
├── main.py                   # Single, powerful entry point for the framework
├── config.yaml               # Central configuration for all settings
├── README.md                 # This file
│
├── corpus/
│   └── seed_queries.txt      # Seed queries for the Mutational Engine
│
├── core/                     # The heart of the fuzzer
│   ├── engine.py             # The main FuzzerEngine orchestrator
│   ├── grammar.py            # Loads the core SQL grammar for the Generator
│   ├── generator.py          # The Generative Engine
│   └── mutator.py            # The Mutational Engine
│
├── oracles/                  # Pluggable bug-finding modules
│   ├── base_oracle.py        # Abstract Base Class for all oracles
│   ├── tlp_oracle.py         # Implements TLP and NoREC
│   └── qpg_oracle.py         # Implements DQP and CERT
│
└── utils/                    # Helper modules
    ├── db_executor.py        # Handles all database connections and schema discovery
    └── bug_reporter.py       # Manages structured, deduplicated bug reporting
```

---
## Getting Started

### 1. Prerequisites

* Python 3.10+
* Access to a running YugabyteDB instance

### 2. Installation

```bash
# Clone the repository
git clone <repository_url>
cd ybfuzz_framework

# Install dependencies
pip install psycopg2-binary pyyaml
```

### 3. Configuration

There are two key files to configure:

**a) `config.yaml`**

This is the main configuration file. Copy the example provided in the repository and edit it to match your environment. At a minimum, you must set your database connection details.

**b) `corpus/seed_queries.txt`**

This file feeds the mutational engine. Add a variety of valid, complex SQL queries that are relevant to your use case. The more diverse this corpus, the more powerful the fuzzer will be. Use `$$schema$$` as a placeholder for the schema name defined in your `config.yaml`.

---
## Usage

The fuzzer is controlled entirely from the command line.

### Basic Run

To start a fuzzing session, you must provide a path to your configuration file.

```bash
python main.py --config config.yaml
```

### Command-Line Arguments

For full control, you can override any setting from the `config.yaml` file using command-line arguments. Use `python main.py --help` for a complete list.

| Argument         | Shorthand | Description                                                              |
| ---------------- | --------- | ------------------------------------------------------------------------ |
| `--config`       | `-c`      | **(Required)** Path to the YAML configuration file.                      |
| `--duration`     | `-d`      | Fuzzing duration in seconds.                                             |
| `--max-queries`  | `-q`      | Maximum number of queries to generate.                                   |
| `--seed`         | `-s`      | Integer seed for a reproducible run.                                     |
| `--log-level`    | `-l`      | Set the logging level (`DEBUG`, `INFO`, `WARNING`, `ERROR`).             |
| `--db-host`      |           | Override the database host.                                              |
| `--enable-oracle`|           | Enable a specific oracle (e.g., `TLOracle`). Can be used multiple times. |
| `--disable-oracle`|           | Disable a specific oracle (e.g., `QPGOracle`). Can be used multiple times.|
| `--dry-run`      |           | Generate and print queries without executing them.                       |

### Example Runs

**Run a quick 5-minute smoke test:**

```bash
python main.py --config config.yaml --duration 300
```

**Reproduce a bug found in a previous run:**

```bash
python main.py --config config.yaml --seed 1660047891 --max-queries 1
```

**Run a long session focused only on finding logic bugs (disabling the optimizer oracle):**

```bash
python main.py --config config.yaml --duration 3600 --disable-oracle QPGOracle
```

---
## Contributing

Contributions are welcome! The framework is designed to be easily extended. The best place to start is by:

1.  **Adding more queries** to the `corpus/seed_queries.txt` file.
2.  **Developing a new oracle** in the `oracles/` directory by creating a new class that inherits from `BaseOracle`.

Please follow standard fork, branch, and pull request workflows.

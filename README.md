# YBFuzz: A Professional-Grade Fuzzing Framework for YugabyteDB

![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)

`YBFuzz` is a **Hybrid Generative-Mutational Fuzzing Framework** designed to be a highly autonomous, scalable, and intelligent system for finding deep logical, performance, and correctness bugs in YugabyteDB.

It combines a grammar-driven engine that generates novel queries from scratch with an intelligent mutational engine that learns from a corpus of real-world examples. This hybrid approach allows `YBFuzz` to achieve deep test coverage with minimal manual intervention.

---
## Key Features

* **Hybrid Fuzzing Engine:** Intelligently switches between a **Generative Engine** (for exploring fundamental SQL structures) and a **Mutational Engine** (for testing complex, real-world syntax learned from a corpus).

* **Pluggable Bug-Finding Oracles:** A suite of advanced, configurable oracles to detect a wide range of bugs:
    * **TLP (Ternary Logic Partitioning):** Finds correctness bugs in `WHERE` clause logic.
    * **NoREC (Non-optimizing Reference Engine):** Finds logic bugs by disabling optimizer features and comparing results.
    * **DQP (Differential Query Plans):** Finds optimizer bugs and performance regressions by comparing query plans before and after schema changes (e.g., adding an index).
    * **CERT (Cardinality Estimation Testing):** Finds planner bugs by validating row count estimates against actual results, which is a primary cause of poor query performance.
    * **CODDTest (Constant Optimization Driven Testing):** Finds optimizer stability bugs by comparing query plans after minor changes to literal values.

* **Performance Bug Detection:** The framework is explicitly designed to find performance issues by analyzing query plans, validating optimizer choices, and checking for cardinality misestimations.

* **Autonomous & Scalable:** Designed to learn new SQL functions and types automatically from `pg_catalog` and new syntax from a simple corpus file, making it easy to scale testing as YugabyteDB evolves.

* **Reproducible & Configurable:** Every bug report is a structured JSON object that includes the random seed for perfect reproducibility. A powerful CLI and YAML configuration provide full control over every aspect of a fuzzing run.

---
## Architecture Overview

The framework is built on a modular, object-oriented design to ensure maximum scalability and maintainability. Its core philosophy is the **separation of concerns**: the fuzzing *engine* is kept separate from the *knowledge* of SQL and the *strategies* for finding bugs.

```
ybfuzz_framework/
├── main.py                   # Single, powerful entry point for the framework
├── config.py                 # Loads and validates configuration from YAML
├── config.yaml               # Central configuration for all settings
├── README.md                 # This file
│
├── corpus/
│   └── seed_queries.txt      # Seed queries for the Mutational Engine
│
├── core/                     # The heart of the fuzzer
│   ├── engine.py             # The main FuzzerEngine orchestrator
│   ├── grammar.py            # Loads and validates the grammar from YAML
│   ├── grammar.yaml          # Grammar "textbook" for the Generator
│   ├── generator.py          # The Generative Engine
│   └── mutator.py            # The Mutational Engine
│
├── oracles/                  # Pluggable bug-finding modules
│   ├── base_oracle.py        # Abstract Base Class for all oracles
│   ├── tlp_oracle.py         # Implements TLP and NoREC
│   └── qpg_oracle.py         # Implements DQP, CERT, and CODDTest
│
└── utils/                    # Helper modules
    ├── db_executor.py        # Handles all database connections and schema discovery
    └── bug_reporter.py       # Manages structured, deduplicated bug reporting
```

### Detailed File Explanations

#### Root Directory
* `main.py`: The single entry point for the entire framework. It handles command-line argument parsing, providing a clean and standard user interface. This centralizes control and makes the framework easy to integrate into automated CI/CD pipelines.
* `config.py`: A robust configuration loader. Its job is to read the `config.yaml` file, validate the settings, and intelligently merge them with any command-line arguments.
* `config.yaml`: The "control panel" for the fuzzer. This file allows any user to change the fuzzer's entire behavior—from database credentials to the probabilities of generating certain SQL clauses—by editing a simple, human-readable file.

#### `corpus/` Directory
* `seed_queries.txt`: The heart of the **mutational engine** and a key to the framework's autonomy. This file allows us to teach the fuzzer new and complex SQL syntax simply by adding an example. The fuzzer then learns from this corpus, generating thousands of variations. This is how we scale to new YugabyteDB features with minimal effort.

#### `core/` Package
* `engine.py`: The central orchestrator. Its job is to make high-level decisions, such as choosing between the generative and mutational engines, and passing the results to the oracles. It remains small and stable, delegating the complex work to other components.
* `grammar.yaml`: The "grammar textbook" for the generative engine. It defines the structure of the SQL language in a human-readable format, completely decoupled from the fuzzer's code.
* `grammar.py`: The loader and validator for `grammar.yaml`. It ensures the grammar is well-formed before the fuzzer starts.
* `generator.py`: The **generative engine**. It uses the grammar to build novel, semantically correct queries from scratch, ensuring we can explore fundamental SQL structures that might not be present in our corpus. It builds a rich Abstract Syntax Tree (AST) for deep analysis.
* `mutator.py`: The **mutational engine**. It intelligently modifies queries from the corpus, allowing the fuzzer to test complex syntax it has learned by observation.

#### `oracles/` Package
* `base_oracle.py`: Defines the `BaseOracle` abstract class. This is a critical use of the **Strategy design pattern**. It allows the engine to treat all bug-finding techniques uniformly, making the system highly extensible.
* `tlp_oracle.py`: A concrete implementation of the oracle strategy. This module contains the logic for advanced correctness testing like **Ternary Logic Partitioning (TLP)** and **Non-optimizing Reference Engine Construction (NoREC)**.
* `qpg_oracle.py`: Another oracle implementation, this one focused on the optimizer. It contains the logic for **Differential Query Plans (DQP)**, **Cardinality Estimation Restriction Testing (CERT)**, and **Constant Optimization Driven Testing (CODDTest)**.

#### `utils/` Package
* `db_executor.py`: Encapsulates all database interaction. This is crucial for maintainability. It also contains the `Catalog` class, which performs **automatic vocabulary discovery** by querying `pg_catalog`, making the entire framework state-aware.
* `bug_reporter.py`: Centralizes all bug reporting. It performs **automatic bug deduplication** and formats reports as structured JSON for easy analysis. This decouples the format of a bug report from the logic that finds it.

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

**Reproduce a bug found in a previous run using its seed:**

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

# YBFuzz: A Professional-Grade Fuzzing Framework for YugabyteDB

![Python Version](https://img.shields.io/badge/python-3.10+-blue.svg)

`YBFuzz` is a **Hybrid Generative-Mutational Fuzzing Framework** designed to be a highly autonomous, scalable, and intelligent system for finding deep logical, performance, and correctness bugs in YugabyteDB.

It combines a grammar-driven engine that generates novel queries from scratch with an intelligent mutational engine that learns from a corpus of real-world examples. This hybrid approach allows `YBFuzz` to achieve deep test coverage with minimal manual intervention.

---
## Key Features

### Fuzzing Engine & Strategy
* **Hybrid Engine:** Intelligently switches between a **Generative Engine** (for exploring fundamental SQL structures) and a **Mutational Engine** (for testing complex, real-world syntax learned from a corpus).
* **Stateful Fuzzing Sessions:** Moves beyond single queries to test complex interactions, generating sequences of DDL and DML to create a rich database state before running a final validation query.
* **Autonomous Vocabulary Discovery:** Automatically learns the full set of functions and data types from the target database's `pg_catalog`, ensuring it always tests the latest features.
* **Corpus Evolution:** Learns over time by automatically saving interesting queries (those that trigger bugs or new query plans) to a dynamic corpus, making future fuzzing runs smarter.

### Advanced Bug-Finding Oracles
* **TLP (Ternary Logic Partitioning):** Finds correctness bugs in `WHERE` clause logic by validating `TRUE`, `FALSE`, and `NULL` partitions.
* **NoREC (Non-optimizing Reference Engine):** Finds logic bugs by disabling optimizer features (e.g., hash joins) and comparing results against the optimized query.
* **DQP (Differential Query Plans):** Finds optimizer bugs and performance regressions by comparing query plans before and after schema changes (e.g., adding an index).
* **CERT (Cardinality Estimation Testing):** Finds planner bugs by validating row count estimates against actual results, a primary cause of poor query performance.
* **CODDTest (Constant Optimization Driven Testing):** Finds optimizer stability bugs by comparing query plans after minor changes to literal values.

### Developer Workflow & Reproducibility
* **Automatic Test Case Reduction:** When a bug is found, a **delta debugging** algorithm automatically shrinks the failing query to the smallest possible version that still reproduces the bug, saving hours of developer time.
* **SQLLogicTest Formatter:** For every unique bug found, the framework automatically generates a ready-to-commit regression test in the standard `SQLLogicTest` format.
* **Sanitizer Integration:** Designed to run against sanitizer-enabled builds (ASan, TSan) to find the most critical memory corruption and data race bugs.
* **Structured, Reproducible Bug Reports:** Every bug report is a machine-readable JSON object that includes the random seed, query history, and minimized test case for perfect reproducibility.

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
│   ├── grammar.yaml          # Grammar "textbook" for the Generator
│   ├── grammar.py            # Loads and validates the grammar from YAML
│   ├── generator.py          # The Generative Engine
│   └── mutator.py            # The Mutational Engine
│
├── oracles/                  # Pluggable bug-finding modules
│   ├── base_oracle.py        # Abstract Base Class for all oracles
│   ├── tlp_oracle.py         # Implements TLP and NoREC
│   └── qpg_oracle.py         # Implements DQP, CERT, and CODDTest
│
├── reducer/
│   └── delta_reducer.py      # Implements the test case reduction logic
│
└── utils/                    # Helper modules
    ├── db_executor.py        # Handles all database connections and schema discovery
    ├── bug_reporter.py       # Manages structured, deduplicated bug reporting
    └── sqllogictest_formatter.py # Creates regression tests
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
| `--max-sessions` | `-q`      | Maximum number of sessions to generate.                                  |
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
python main.py --config config.yaml --seed 1660047891 --max-sessions 1
```

**Run a long session focused only on finding logic bugs (disabling the optimizer oracle):**

```bash
python main.py --config config.yaml --duration 3600 --disable-oracle QPGOracle
```

---
## Advanced Usage: Sanitizer Integration

To find the most critical memory corruption and data race bugs, it is highly recommended to run `YBFuzz` against a version of YugabyteDB that has been compiled with a sanitizer like AddressSanitizer (ASan).

### Workflow

1.  **Compile YugabyteDB with a Sanitizer:**
    Follow the official YugabyteDB documentation to build the database from source with the desired sanitizer enabled (e.g., using the `--asan` flag in `yb_build.sh`).

2.  **Start the Sanitized YugabyteDB Cluster:**
    Run your custom-built, sanitized version of YugabyteDB.

3.  **Configure `config.yaml` for Sanitizer Testing:**
    Update your `config.yaml` to tell the fuzzer it's running in sanitizer mode. This is critical for generating high-quality bug reports.

    ```yaml
    # In config.yaml
    sanitizer:
      type: "ASan"
      log_file_path: "/path/to/your/yugabyte_data/node-1/disk-1/yb-data/tserver/logs/yugabytedb-tserver.INFO"
    ```
    * **`type`**: The name of the sanitizer you used (e.g., "ASan", "TSan").
    * **`log_file_path`**: The **absolute path** to the YugabyteDB `tserver` log file. The bug reporter will scan this file for sanitizer output when a crash occurs.

4.  **Run the Fuzzer:**
    Execute `YBFuzz` as you normally would. When a query causes a crash, the `BugReporter` will automatically check the database log. If it finds sanitizer output, it will create a high-priority bug report with a specific type like `ASan - Heap-Use-After-Free`, providing invaluable information for developers.

---
## Contributing

Contributions are welcome! The framework is designed to be easily extended. The best place to start is by:

1.  **Adding more queries** to the `corpus/seed_queries.txt` file.
2.  **Developing a new oracle** in the `oracles/` directory by creating a new class that inherits from `BaseOracle`.

Please follow standard fork, branch, and pull request workflows.

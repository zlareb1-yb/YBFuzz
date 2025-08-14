# YBFuzz - Advanced Database Fuzzer for YugabyteDB

## Overview

YBFuzz is a comprehensive database fuzzing framework designed to detect logical bugs, consistency issues, and query optimizer performance problems in YugabyteDB through intelligent query generation, multi-oracle testing, and advanced bug detection. The framework provides production-grade testing capabilities for distributed database systems with a focus on catching real-world issues.

## Key Features

- **Grammar-Based Query Generation**: BNF grammar-driven SQL generation with AST construction and semantic validation
- **Multi-Oracle Testing**: 12 specialized oracle implementations for comprehensive bug detection
- **YugabyteDB-Specific Testing**: Optimized for distributed database features, consistency levels, and distributed execution
- **Concurrent Testing**: Built-in ACID violation detection, race condition testing, and Jepsen-like consistency checks
- **High-Performance Mode**: Optimized for high-throughput testing with batch processing capabilities
- **Professional Bug Reporting**: Comprehensive bug reproduction scripts, test files, and metadata

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    YBFuzz Framework                            │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   Main      │  │   Config    │  │   Logging   │           │
│  │  Entry      │  │ Management  │  │   System    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│                        Core Engine                             │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Session    │  │   Query     │  │   Oracle    │           │
│  │ Management  │  │ Generation  │  │ Orchestrator│           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│                     Oracle Layer                               │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   TLP       │  │    QPG      │  │    PQS      │           │
│  │  Oracle     │  │   Oracle    │  │   Oracle    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   NoREC     │  │    CERT     │  │    DQP      │           │
│  │  Oracle     │  │   Oracle    │  │   Oracle    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  CODDTest   │  │ YugabyteDB  │  │   Complex   │           │
│  │   Oracle    │  │  Features   │  │     SQL     │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │Distributed  │  │   Edge      │  │   Mutator   │           │
│  │Consistency  │  │   Case      │  │             │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│                    Infrastructure Layer                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │  Database   │  │    Bug      │  │   Corpus    │           │
│  │ Executor    │  │  Reporter   │  │  Manager    │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
├─────────────────────────────────────────────────────────────────┤
│                     YugabyteDB                                 │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐           │
│  │   Tables    │  │   Indexes   │  │   Views     │           │
│  │             │  │             │  │             │           │
│  └─────────────┘  └─────────────┘  └─────────────┘           │
└─────────────────────────────────────────────────────────────────┘
```

## Core Components

### 1. **Core Engine** (`core/engine.py`)
- **Session Management**: Multi-session orchestration with automatic recovery
- **Performance Optimization**: High-throughput query execution with batch processing
- **Concurrent Testing**: Jepsen-like consistency testing with ACID violation detection
- **Resource Monitoring**: Memory, CPU, and database connection tracking
- **Metrics Collection**: Comprehensive performance and bug detection metrics

### 2. **Query Generator** (`core/generator.py`)
- **Grammar-Driven**: BNF grammar-based SQL generation with semantic validation
- **Complex Query Patterns**: Multi-level CTEs, advanced aggregations, complex JOINs
- **YugabyteDB Features**: Distributed execution, consistency levels, partitioning
- **Performance Optimization**: Batch generation for high-throughput testing
- **Query Templates**: Pre-built complex query patterns for consistent testing

### 3. **Oracle System** (`oracles/`)
- **TLP Oracle**: Testing Logical Properties with non-deterministic query detection
- **QPG Oracle**: Query Plan Generation testing with performance analysis
- **PQS Oracle**: Pivot Query System testing for complex transformations
- **NoREC Oracle**: Non-optimizing Reference Engine Comparison
- **CERT Oracle**: Consistent Result Testing across different execution paths
- **DQP Oracle**: Different Query Plan detection and analysis
- **CODDTest Oracle**: Codd's Relational Model compliance testing
- **Distributed Consistency Oracle**: ACID compliance and distributed consistency
- **YugabyteDB Features Oracle**: YugabyteDB-specific feature testing
- **Edge Case Oracle**: Boundary condition and edge case detection
- **Complex SQL Oracle**: Advanced SQL pattern testing

### 4. **Database Executor** (`utils/db_executor.py`)
- **Connection Management**: Connection pooling and automatic recovery
- **Query Execution**: Optimized query execution with timeout handling
- **Error Handling**: Comprehensive error classification and reporting
- **Performance Monitoring**: Query timing and resource usage tracking
- **Schema Discovery**: Automatic table, column, and function discovery

### 5. **Bug Reporter** (`utils/bug_reporter.py`)
- **Comprehensive Reports**: SQL reproduction scripts, test files, and metadata
- **Structured Output**: JSON metadata with detailed bug context
- **Reproduction Scripts**: Executable SQL scripts for bug verification
- **Test Files**: Automated test cases for regression testing
- **Severity Classification**: Bug severity and impact assessment

## Supported YugabyteDB Features

### **Consistency Levels**
- `SNAPSHOT` (default)

### **Distributed Features**
- Cross-node query distribution
- Partition-aware query execution
- Tablet splitting and merging operations

### **Advanced SQL Patterns**
- Multi-level recursive CTEs (10+ levels)
- Complex window functions with advanced frames
- Advanced aggregations (GROUPING SETS, CUBE, ROLLUP)
- Complex JOINs (10+ table JOINs)
- Partitioning (HASH, RANGE, LIST)
- Subpartitioning strategies

### **Data Types**
- `UUID`, `JSONB`, `ARRAY`
- `INTERVAL`, `TIMESTAMP WITH TIME ZONE`
- `NUMERIC(38,0)`
- Geometric types: `point`, `line`, `circle`
- Text search: `tsvector`, `tsquery`

## Performance Characteristics

### **Current Performance**
- **Queries per Minute**: 176+ QPM (target: 1000+ QPM)
- **Queries per Second**: 2.9+ QPS
- **Syntax Error Rate**: 2%
- **CPU Efficiency**: Multi-threaded execution

### **Optimization Features**
- Batch query generation and execution
- Selective oracle execution
- Connection pooling and reuse
- Memory-efficient result processing
- Parallel session execution

## Installation and Setup

### **Prerequisites**
- Python 3.8+
- YugabyteDB 2025.1
- Network access to YugabyteDB cluster

### **Installation**
```bash
# Clone the repository
git clone https://github.com/your-org/ybfuzz.git
cd ybfuzz

# Install dependencies
pip install -r requirements.txt

# Create configuration
cp config.yaml config.yaml.local
# Edit config.yaml.local with your database settings
```

### **Configuration**
```yaml
database:
  host: "10.9.86.186,10.9.139.177,10.9.205.248"
  port: 5433
  dbname: "yugabyte"
  user: "yugabyte"
  password: "your_password"
  schema_name: "ybfuzz_schema"

oracles:
  enabled_oracles:
    - "TLPOracle"
    - "QPGOracle"
    - "PQSOracle"
    - "NoRECOracle"
    - "CERTOracle"
    - "DQPOracle"
    - "CODDTestOracle"
    - "DistributedConsistencyOracle"
    - "YugabyteDBFeaturesOracle"
    - "EdgeCaseOracle"
    - "ComplexSQLOracle"

performance:
  target_qpm: 1000
  session_duration: 30
  max_concurrent_sessions: 5
```

## Usage Examples

### **Basic Usage**
```bash
# Run fuzzer for 1 hour
python3 main.py -c config.yaml --duration 3600

# Run with debug logging
python3 main.py -c config.yaml --duration 1800 --debug

# Run with specific oracles
python3 main.py -c config.yaml --duration 3600 --oracles TLP,QPG
```

## Bug Detection Capabilities

### **Logical Bugs**
- Query result inconsistencies
- Data corruption scenarios
- Constraint violations
- Referential integrity issues

### **Performance Issues**
- Query plan regressions
- Query Optimizer efficiency

### **Distributed Issues**
- ACID violation detection
- Race condition identification
- Cross-node consistency problems

### **SQL Compatibility**
- Syntax error detection
- Feature support validation
- Type compatibility issues
- Function behavior differences

## Output and Reporting

### **Bug Reports**
- **SQL Reproduction Scripts**: Executable SQL for bug verification
- **Test Files**: Automated test cases for regression testing
- **Metadata**: JSON files with detailed bug context
- **Severity Classification**: Bug impact assessment

### **Performance Metrics**
- Real-time QPM/QPS tracking
- Oracle execution statistics

### **Logs and Debugging**
- Comprehensive logging system
- Debug information for troubleshooting

### **Architecture Principles**
- Modular design with clear interfaces
- Separation of concerns
- Extensible oracle system
- Configuration-driven behavior

## Troubleshooting

### **Common Issues**
- **Connection Failures**: Check network connectivity and credentials
- **Performance Issues**: Monitor resource usage and adjust configuration
- **False Positives**: Review oracle logic and query filtering
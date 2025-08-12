# YBFuzz - YugabyteDB Testing Framework

A comprehensive fuzzing framework designed to detect bugs in YugabyteDB through advanced testing techniques.

## Architecture

### Core Components
- **Query Generator**: Grammar-based SQL generation with schema awareness
- **Oracle System**: Multiple bug detection oracles using different testing methodologies
- **Bug Reporter**: Structured bug reporting with reproduction scripts
- **Database Executor**: Connection management and query execution

### Oracle Ecosystem

#### TLP (Ternary Logic Partitioning)
- **Purpose**: Detects logic bugs by partitioning queries into three logical states
- **Method**: Compares results of WHERE TRUE, WHERE FALSE, and WHERE NULL clauses
- **Use Case**: Logic consistency validation

#### QPG (Query Plan Guidance)
- **Purpose**: Identifies optimization bugs through query plan analysis
- **Method**: Monitors query plan changes and detects inconsistencies
- **Use Case**: Query optimizer testing

#### PQS (Pivoted Query Synthesis)
- **Purpose**: Generates queries guaranteed to fetch specific pivot rows
- **Method**: Creates targeted queries based on existing data
- **Use Case**: Data consistency validation

#### NoREC (Non-optimizing Reference Engine Construction)
- **Purpose**: Finds optimization bugs by comparing optimized vs. non-optimized queries
- **Method**: Generates query variations with different optimization levels
- **Use Case**: Query optimization testing

#### CERT (Cardinality Estimation Restriction Testing)
- **Purpose**: Detects performance issues through cardinality analysis
- **Method**: Compares estimated vs. actual row counts
- **Use Case**: Performance optimization testing

#### DQP (Differential Query Plans)
- **Purpose**: Identifies logic bugs through plan variation analysis
- **Method**: Compares results from different execution plans
- **Use Case**: Execution plan consistency testing

#### CODDTest (Constant Optimization Driven Testing)
- **Purpose**: Finds logic bugs through constant optimization techniques
- **Method**: Applies constant folding and propagation to queries
- **Use Case**: Advanced logic testing

## Features

### Query Generation
- Grammar-based SQL generation
- Schema-aware query construction
- Type-safe column selection
- Context-aware clause generation

### Bug Detection
- Multiple oracle implementations
- False positive filtering
- Comprehensive bug reporting
- Reproduction script generation

### Performance
- Efficient query execution
- Connection pooling
- Resource monitoring
- Scalable architecture

### Security
- SQL injection protection
- Query sanitization
- Access control validation
- Schema isolation

## Configuration

### Basic Setup
```yaml
database:
  host: "localhost"
  port: 5433
  user: "username"
  password: "password"
  database: "testdb"
  schema_name: "test_schema"

fuzzing:
  duration: 300
  max_sessions: 100
  queries_per_session: 10
```

### Oracle Configuration
```yaml
oracles:
  tlp:
    enabled: true
    max_partitions: 3
  
  qpg:
    enabled: true
    plan_observation_threshold: 10
```

## Usage

### Command Line
```bash
# Basic run
python3 main.py -c config.yaml

# Duration-limited run
python3 main.py -c config.yaml -d 60

# Verbose logging
python3 main.py -c config.yaml -v
```

### Programmatic Usage
```python
from core.engine import FuzzerEngine
from config import Config

config = Config('config.yaml')
engine = FuzzerEngine(config)
engine.run(duration=300)
```

## Bug Reporting

### Report Structure
- **Bug Type**: Classification by oracle and category
- **Description**: Detailed bug explanation
- **Reproduction**: Executable SQL scripts
- **Context**: Query plans, error details, metadata

### Output Formats
- JSON: Structured data for programmatic processing
- SQL: Executable reproduction scripts
- Markdown: Human-readable documentation
- HTML: Web-based viewing

## Testing Methodology

### Session Structure
1. **DDL Phase**: Schema modifications and table creation
2. **DML Phase**: Data manipulation operations
3. **Validation Phase**: Query execution and oracle testing

### Oracle Testing
1. **Query Analysis**: Determine if oracle can process query
2. **Bug Detection**: Apply oracle-specific testing logic
3. **Result Validation**: Compare expected vs. actual results
4. **Bug Reporting**: Generate comprehensive bug reports

## Performance Considerations

### Query Execution
- Connection pooling for efficient database access
- Timeout management to prevent hanging queries
- Memory usage monitoring and control

### Scalability
- Configurable session limits
- Adaptive query generation
- Resource-aware execution

## Security Features

### Input Validation
- SQL injection prevention
- Query parameter sanitization
- Schema access control

### Database Security
- Privilege validation
- Schema isolation
- Query restriction enforcement

## Monitoring and Logging

### Log Levels
- **INFO**: General operational information
- **DEBUG**: Detailed debugging information
- **WARNING**: Bug detection and warnings
- **ERROR**: Error conditions and failures

### Metrics
- Query execution statistics
- Bug detection rates
- Performance measurements
- Resource utilization

## Extensibility

### Custom Oracles
- Implement BaseOracle interface
- Register in ORACLE_REGISTRY
- Configure in config.yaml

### Custom Generators
- Extend SQLNode classes
- Implement generation strategies
- Add new query types

## Best Practices

### Configuration
- Use appropriate timeouts for your database
- Configure oracle parameters based on testing needs
- Monitor resource usage during execution

### Testing
- Start with short durations to validate setup
- Use appropriate oracle combinations for your use case
- Review bug reports for false positives

### Maintenance
- Regular configuration updates
- Oracle parameter tuning
- Performance monitoring and optimization

## Troubleshooting

### Common Issues
- **Connection Failures**: Check database credentials and network connectivity
- **Permission Errors**: Verify database user privileges
- **Timeout Issues**: Adjust execution timeouts in configuration

### Debug Mode
Enable debug logging for detailed troubleshooting:
```yaml
logging:
  level: "DEBUG"
```

## Contributing

### Development Setup
1. Clone the repository
2. Install dependencies: `pip install -r requirements.txt`
3. Configure database connection
4. Run tests: `python3 main.py -c config.yaml -d 10`

### Code Standards
- Follow PEP 8 style guidelines
- Include comprehensive docstrings
- Add unit tests for new features
- Update documentation for changes

## License
This project is licensed under the MIT License - see the LICENSE file for details.

## Support
For questions and support, please refer to the project documentation or create an issue in the repository.

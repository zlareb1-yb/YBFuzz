import json
import logging
import os
import time
import uuid
from datetime import datetime
from typing import Dict, Any, Optional

"""
Bug Reporter - Executable Bug Reproduction System

This module provides comprehensive bug reporting capabilities:
- Executable SQL reproduction scripts
- Automated test file generation
- Structured metadata tracking
- Organized file management
- Advanced bug tracking metadata
"""

class BugReporter:
    """Comprehensive bug reporter that generates executable bug reproductions."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the bug reporter with organized directory structure."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Create organized directory structure
        self._create_directories()
        
        # Initialize metadata tracking
        self.bug_count = 0
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    def _create_directories(self):
        """Create the base bug reporting directory and its subdirectories."""
        bug_config = self.config.get('bug_reporting', {})
        self.base_reproduction_dir = bug_config.get('reproduction_dir', 'bug_reproductions')
        
        self.bug_dirs = {
            'sql_reproductions': os.path.join(self.base_reproduction_dir, 'sql_reproductions'),
            'test_files': os.path.join(self.base_reproduction_dir, 'test_files'),
            'metadata': os.path.join(self.base_reproduction_dir, 'metadata')
        }
        
        for dir_path in self.bug_dirs.values():
            os.makedirs(dir_path, exist_ok=True)
    
    def _generate_bug_filename(self, oracle_name: str) -> str:
        """Generate a unique bug filename."""
        timestamp = datetime.now()
        timestamp_str = timestamp.strftime('%Y%m%d_%H%M%S')
        unique_id = str(uuid.uuid4())[:8]
        
        # Create oracle short name
        oracle_short = oracle_name.replace('Oracle', '').lower()
        
        return f"{oracle_short}_{timestamp_str}_{unique_id}"
    
    def _create_sql_reproduction_script(self, bug_data: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        """
        Create an executable SQL reproduction script.
        
        Args:
            bug_data: Bug information from oracle
            metadata: Additional metadata about the bug
            
        Returns:
            SQL script content
        """
        bug_id = metadata.get('bug_id', 'unknown')
        oracle_name = metadata.get('oracle_name', 'UnknownOracle')
        detected_time = metadata.get('detected_time', 'unknown')
        
        # CRITICAL FIX: Extract the actual query that caused the bug
        original_query = bug_data.get('query', 'NO_QUERY_CAPTURED')
        bug_description = bug_data.get('description', 'No description provided')
        bug_type = bug_data.get('bug_type', 'unknown')
        
        # Extract additional context for better reproduction
        context_info = bug_data.get('context', {})
        expected_result = bug_data.get('expected_result', 'Unknown')
        actual_result = bug_data.get('actual_result', 'Unknown')
        
        script = f"""-- =============================================================================
-- YBFuzz Bug Reproduction Script
-- =============================================================================
-- Bug ID: {bug_id}
-- Oracle: {oracle_name}
-- Detected: {detected_time}
-- Bug Type: {bug_type}
-- Severity: {bug_data.get('severity', 'UNKNOWN')}
-- =============================================================================

-- BUG DESCRIPTION:
-- {bug_description}

-- ORIGINAL QUERY THAT CAUSED THE BUG:
-- {original_query}

-- EXPECTED RESULT: {expected_result}
-- ACTUAL RESULT: {actual_result}

-- =============================================================================
-- REPRODUCTION STEPS
-- =============================================================================

-- STEP 1: Execute the problematic query
{original_query}

-- STEP 2: Show query plan and execution details
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {original_query}

-- STEP 3: Show current database state
SELECT current_database(), current_schema();
SELECT version();

-- STEP 4: Show relevant table structures and data
-- Add table inspection queries based on the bug type

-- =============================================================================
-- VERIFICATION
-- =============================================================================
-- Run the query multiple times to check for consistency
-- Expected: {expected_result}
-- Actual: {actual_result}

-- =============================================================================
-- CLEANUP
-- =============================================================================
-- No cleanup needed for read-only queries
-- =============================================================================
-- End of reproduction script
"""
        return script
    
    def _get_products_table_setup(self) -> str:
        """Generate products table setup for bug reproduction."""
        return """
-- Create products table
CREATE TABLE IF NOT EXISTS products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    category_id INTEGER NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create categories table
CREATE TABLE IF NOT EXISTS categories (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT
);

-- Insert sample data
INSERT INTO categories (name, description) VALUES 
    ('electronics', 'Electronic devices and gadgets'),
    ('books', 'Books and publications'),
    ('clothing', 'Clothing and accessories'),
    ('home', 'Home and garden items')
ON CONFLICT (name) DO NOTHING;

INSERT INTO products (name, price, category_id, description) VALUES 
    ('Laptop', 1299.99, 1, 'High-performance laptop'),
    ('Smartphone', 799.99, 1, 'Latest smartphone model'),
    ('Programming Book', 49.99, 2, 'Advanced programming guide'),
    ('T-Shirt', 29.99, 3, 'Cotton t-shirt'),
    ('Garden Tool', 89.99, 4, 'Garden tool')
ON CONFLICT DO NOTHING;

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_products_price ON products(price);
CREATE INDEX IF NOT EXISTS idx_products_category ON products(category_id);
CREATE INDEX IF NOT EXISTS idx_products_name ON products(name);
"""
    
    def _get_users_table_setup(self) -> str:
        """Generate users table setup for bug reproduction."""
        return """
-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    age INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO users (username, email, age) VALUES 
    ('john_doe', 'john@example.com', 30),
    ('jane_smith', 'jane@example.com', 25),
    ('bob_wilson', 'bob@example.com', 35)
ON CONFLICT DO NOTHING;
"""
    
    def _get_generic_table_setup(self) -> str:
        """Generate generic table setup for bug reproduction."""
        return """
-- Create generic test table
CREATE TABLE IF NOT EXISTS test_data (
    id SERIAL PRIMARY KEY,
    value1 INTEGER,
    value2 VARCHAR(50),
    value3 DECIMAL(10,2),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO test_data (value1, value2, value3) VALUES 
    (1, 'test1', 10.5),
    (2, 'test2', 20.7),
    (3, 'test3', 30.2)
ON CONFLICT DO NOTHING;
"""
    
    def _get_tlp_verification_steps(self, bug_data: Dict[str, Any]) -> str:
        """Generate TLP-specific verification steps."""
        return f"""
-- TLP Oracle Verification Steps
-- This bug involves ternary logic partitioning

-- Verify the original query result
-- Expected: {bug_data.get('additional_info', {}).get('expected_result', 'Unknown expected result')}
-- Actual: {bug_data.get('additional_info', {}).get('actual_result', 'Unknown actual result')}

-- Test TLP partitions
-- Partition 1: WHERE TRUE
SELECT 'Partition 1 (WHERE TRUE)' as test_case, COUNT(*) as result_count
FROM ({bug_data.get('query', '-- No query provided')}) t1 WHERE TRUE;

-- Partition 2: WHERE FALSE  
SELECT 'Partition 2 (WHERE FALSE)' as test_case, COUNT(*) as result_count
FROM ({bug_data.get('query', '-- No query provided')}) t2 WHERE FALSE;

-- Partition 3: WHERE NULL
SELECT 'Partition 3 (WHERE NULL)' as test_case, COUNT(*) as result_count
FROM ({bug_data.get('query', '-- No query provided')}) t3 WHERE NULL;

-- All partitions should return the same result for deterministic queries
"""
    
    def _get_qpg_verification_steps(self, bug_data: Dict[str, Any]) -> str:
        """Generate QPG-specific verification steps."""
        return f"""
-- QPG Oracle Verification Steps
-- This bug involves query plan guidance

-- Show current query plan
EXPLAIN (ANALYZE, BUFFERS) {bug_data.get('query', '-- No query provided')};

-- Test with recommended hints
-- Default plan: {bug_data.get('additional_info', {}).get('default_plan', 'Unknown')}
-- Recommended plan: {bug_data.get('additional_info', {}).get('recommended_plan', 'Unknown')}
-- Expected improvement: {bug_data.get('additional_info', {}).get('performance_improvement', 'Unknown')}

-- Test with different hints
EXPLAIN (ANALYZE, BUFFERS) {bug_data.get('reproduction_query', bug_data.get('query', '-- No query provided'))};

-- Compare execution times
\\timing on
{bug_data.get('query', '-- No query provided')};
{bug_data.get('reproduction_query', bug_data.get('query', '-- No query provided'))};
\\timing off
"""
    
    def _get_pqs_verification_steps(self, bug_data: Dict[str, Any]) -> str:
        """Generate PQS-specific verification steps."""
        return f"""
-- PQS Oracle Verification Steps
-- This bug involves pivoted query synthesis

-- Verify the original query result
-- Expected: {bug_data.get('additional_info', {}).get('expected_result', 'Unknown expected result')}
-- Actual: {bug_data.get('additional_info', {}).get('actual_result', 'Unknown actual result')}

-- Test pivot variations
-- Original query
{bug_data.get('query', '-- No query provided')};

-- Test with different pivot approaches
-- Add specific pivot verification queries here
"""
    
    def _get_generic_verification_steps(self, bug_data: Dict[str, Any]) -> str:
        """Generate generic verification steps."""
        return f"""
-- Generic Verification Steps
-- Bug Type: {bug_data.get('bug_type', 'unknown')}

-- Verify the query executes without errors
-- Expected: {bug_data.get('additional_info', {}).get('expected_result', 'Unknown expected result')}
-- Actual: {bug_data.get('additional_info', {}).get('actual_result', 'Unknown actual result')}

-- Add specific verification steps based on the bug type
"""
    
    def _create_test_file(self, bug_data: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        """
        Create a test file for the bug.
        
        Args:
            bug_data: Bug information from oracle
            metadata: Additional metadata about the bug
            
        Returns:
            Test file content
        """
        bug_id = metadata.get('bug_id', 'unknown')
        oracle_name = metadata.get('oracle_name', 'UnknownOracle')
        bug_type = metadata.get('bug_type', 'unknown')
        
        test_content = f"""# YBFuzz Bug Test File
# Bug ID: {bug_id}
# Oracle: {oracle_name}
# Bug Type: {bug_type}
# Detected: {metadata.get('detected_time', 'unknown')}

# Test Description
# This test reproduces a bug detected by {oracle_name}
# Bug Type: {bug_type}

# Test Steps
1. Execute the problematic query
2. Verify the bug behavior
3. Check for expected vs actual results

# Expected Result
# {bug_data.get('expected_result', 'Unknown')}

# Actual Result  
# {bug_data.get('actual_result', 'Unknown')}

# Notes
# This bug was automatically detected by the YBFuzz framework
# Use the corresponding SQL reproduction script for detailed testing
"""
        return test_content
    
    def _create_tlp_test_file(self, bug_data: Dict[str, Any], bug_id: str, oracle_name: str, 
                             timestamp: str, fuzzer_run_id: str, session_id: str) -> str:
        """Create a TLP-specific test file."""
        return f"""# YBFuzz Bug Test File - TLP Oracle Bug
# Bug ID: {bug_id}
# Oracle: {oracle_name}
# Detected: {timestamp}
# Fuzzer Run: {fuzzer_run_id}
# Session: {session_id}
# Bug Type: Ternary Logic Partitioning Issue

# Test setup - Create the exact database state
setup:
  - "CREATE SCHEMA IF NOT EXISTS ybfuzz_test"
  - "SET search_path TO ybfuzz_test, public"
  
  # Create products table
  - "CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name VARCHAR(100) NOT NULL, price DECIMAL(10,2) NOT NULL, category_id INTEGER NOT NULL, description TEXT)"
  
  # Create categories table  
  - "CREATE TABLE IF NOT EXISTS categories (id SERIAL PRIMARY KEY, name VARCHAR(50) NOT NULL UNIQUE, description TEXT)"
  
  # Insert test data
  - "INSERT INTO categories (name, description) VALUES ('electronics', 'Electronic devices'), ('books', 'Books and publications') ON CONFLICT (name) DO NOTHING"
  - "INSERT INTO products (name, price, category_id, description) VALUES ('Laptop', 1299.99, 1, 'High-performance laptop'), ('Smartphone', 799.99, 1, 'Latest smartphone'), ('Programming Book', 49.99, 2, 'Advanced programming guide') ON CONFLICT DO NOTHING"

# Test the TLP bug - This is the core issue
test:
  - name: "TLP Bug: Deterministic query returns different results across partitions"
    description: "The query should return the same result for all TLP partitions, but it doesn't"
    
    # Base query that should be deterministic
    base_query: "{bug_data.get('query', 'SELECT COUNT(*) FROM products WHERE price > 100')}"
    expected_base_result: "{bug_data.get('additional_info', {}).get('expected_result', 'Expected result')}"
    
    # TLP Partition 1: WHERE TRUE
    tlp_partition_1:
      sql: "SELECT COUNT(*) FROM ({bug_data.get('query', 'SELECT COUNT(*) FROM products WHERE price > 100')}) t1 WHERE TRUE"
      expected_result: "Same as base query"
      description: "Partition 1 with WHERE TRUE should return same as base query"
    
    # TLP Partition 2: WHERE FALSE  
    tlp_partition_2:
      sql: "SELECT COUNT(*) FROM ({bug_data.get('query', 'SELECT COUNT(*) FROM products WHERE price > 100')}) t2 WHERE FALSE"
      expected_result: "0 rows"
      description: "Partition 2 with WHERE FALSE should return 0 rows (this is correct)"
    
    # TLP Partition 3: WHERE NULL
    tlp_partition_3:
      sql: "SELECT COUNT(*) FROM ({bug_data.get('query', 'SELECT COUNT(*) FROM products WHERE price > 100')}) t3 WHERE NULL"
      expected_result: "0 rows"
      description: "Partition 3 with WHERE NULL should return 0 rows (this is correct)"
    
    # The actual bug: TLP partitions 2 and 3 should return 0, but the issue is
    # that the base query itself might be returning incorrect results
    bug_verification:
      - name: "Verify base query result"
        sql: "{bug_data.get('query', 'SELECT COUNT(*) FROM products WHERE price > 100')}"
        expected_result: "Expected result from base query"
        description: "Base query should return expected result"
      
      - name: "Verify TLP consistency"
        sql: "SELECT 'Partition 1' as partition, COUNT(*) as count FROM ({bug_data.get('query', 'SELECT COUNT(*) FROM products WHERE price > 100')}) t1 WHERE TRUE UNION ALL SELECT 'Partition 2' as partition, COUNT(*) as count FROM ({bug_data.get('query', 'SELECT COUNT(*) FROM products WHERE price > 100')}) t2 WHERE FALSE UNION ALL SELECT 'Partition 3' as partition, COUNT(*) as count FROM ({bug_data.get('query', 'SELECT COUNT(*) FROM products WHERE price > 100')}) t3 WHERE NULL"
        expected_result: "Partition 1: expected_count, Partition 2: 0, Partition 3: 0"
        description: "All partitions should behave consistently with TLP logic"

# Expected bug behavior
expected_bug_behavior:
  - "The base query should return expected result"
  - "TLP Partition 1 (WHERE TRUE) should return same as base query"
  - "TLP Partition 2 (WHERE FALSE) should return 0 rows" 
  - "TLP Partition 3 (WHERE NULL) should return 0 rows"
  - "If any partition returns unexpected results, this indicates a TLP bug"

# Cleanup
cleanup:
  - "DROP SCHEMA IF EXISTS ybfuzz_test CASCADE"
"""
    
    def _create_qpg_test_file(self, bug_data: Dict[str, Any], bug_id: str, oracle_name: str, 
                             timestamp: str, fuzzer_run_id: str, session_id: str) -> str:
        """Create a QPG-specific test file."""
        return f"""# YBFuzz Bug Test File - QPG Oracle Bug
# Bug ID: {bug_id}
# Oracle: {oracle_name}
# Detected: {timestamp}
# Fuzzer Run: {fuzzer_run_id}
# Session: {session_id}
# Bug Type: Query Plan Guidance Issue

# Test setup
setup:
  - "CREATE SCHEMA IF NOT EXISTS ybfuzz_test"
  - "SET search_path TO ybfuzz_test, public"
  
  # Create tables for join testing
  - "CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name VARCHAR(100), price DECIMAL(10,2), category_id INTEGER)"
  - "CREATE TABLE IF NOT EXISTS categories (id SERIAL PRIMARY KEY, name VARCHAR(50))"
  
  # Insert test data
  - "INSERT INTO categories (id, name) VALUES (1, 'electronics'), (2, 'books')"
  - "INSERT INTO products (name, price, category_id) VALUES ('Laptop', 1299.99, 1), ('Book', 49.99, 2)"

# Test the QPG bug
test:
  - name: "QPG Bug: Suboptimal execution plan detected"
    description: "{bug_data.get('description', 'Query plan guidance issue')}"
    
    # Test default plan
    default_plan:
      sql: "{bug_data.get('query', 'SELECT p.name, c.name FROM products p JOIN categories c ON p.category_id = c.id')}"
      expected_plan: "{bug_data.get('additional_info', {}).get('default_plan', 'Default plan')}"
      description: "Default execution plan"
    
    # Test optimized plan
    optimized_plan:
      sql: "{bug_data.get('reproduction_query', bug_data.get('query', 'SELECT p.name, c.name FROM products p JOIN categories c ON p.category_id = c.id'))}"
      expected_plan: "{bug_data.get('additional_info', {}).get('recommended_plan', 'Recommended plan')}"
      description: "Optimized execution plan with hints"
    
    # Performance comparison
    performance_test:
      - name: "Compare execution times"
        sql: "{bug_data.get('query', 'SELECT p.name, c.name FROM products p JOIN categories c ON p.category_id = c.id')}"
        description: "Execute default plan and measure time"
      
      - name: "Execute optimized version"
        sql: "{bug_data.get('reproduction_query', bug_data.get('query', 'SELECT p.name, c.name FROM products p JOIN categories c ON p.category_id = c.id'))}"
        description: "Execute optimized plan and measure time"

# Expected results
expected_results:
  - "Default plan should use {bug_data.get('additional_info', {}).get('default_plan', 'default approach')}"
  - "Optimized plan should use {bug_data.get('additional_info', {}).get('recommended_plan', 'recommended approach')}"
  - "Performance improvement: {bug_data.get('additional_info', {}).get('performance_improvement', 'expected improvement')}"

# Cleanup
cleanup:
  - "DROP SCHEMA IF EXISTS ybfuzz_test CASCADE"
"""
    
    def _create_pqs_test_file(self, bug_data: Dict[str, Any], bug_id: str, oracle_name: str, 
                             timestamp: str, fuzzer_run_id: str, session_id: str) -> str:
        """Create a PQS-specific test file."""
        return f"""# YBFuzz Bug Test File - PQS Oracle Bug
# Bug ID: {bug_id}
# Oracle: {oracle_name}
# Detected: {timestamp}
# Fuzzer Run: {fuzzer_run_id}
# Session: {session_id}
# Bug Type: Pivoted Query Synthesis Issue

# Test setup
setup:
  - "CREATE SCHEMA IF NOT EXISTS ybfuzz_test"
  - "SET search_path TO ybfuzz_test, public"
  
  # Create test table
  - "CREATE TABLE IF NOT EXISTS products (id SERIAL PRIMARY KEY, name VARCHAR(100), price DECIMAL(10,2), category_id INTEGER)"
  
  # Insert test data
  - "INSERT INTO products (name, price, category_id) VALUES ('Laptop', 1299.99, 1), ('Book', 49.99, 2), ('Phone', 799.99, 1)"

# Test the PQS bug
test:
  - name: "PQS Bug: Pivot operation returns incorrect aggregation results"
    description: "{bug_data.get('description', 'Pivot aggregation issue')}"
    
    # Test original query
    original_query:
      sql: "{bug_data.get('query', 'SELECT category_id, COUNT(*) FROM products GROUP BY category_id')}"
      expected_result: "{bug_data.get('additional_info', {}).get('expected_result', 'Expected result')}"
      description: "Original pivot query"
    
    # Test pivot variations
    pivot_variations:
      - name: "Basic pivot"
        sql: "{bug_data.get('query', 'SELECT category_id, COUNT(*) FROM products GROUP BY category_id')}"
        description: "Basic pivot operation"
      
      - name: "Conditional pivot"
        sql: "{bug_data.get('reproduction_query', bug_data.get('query', 'SELECT category_id, COUNT(*) FROM products GROUP BY category_id'))}"
        description: "Pivot with conditional aggregation"

# Expected results
expected_results:
  - "Original query: {bug_data.get('additional_info', {}).get('expected_result', 'Expected result')}"
  - "Actual result: {bug_data.get('additional_info', {}).get('actual_result', 'Actual result')}"
  - "Pivot operations should return consistent results"

# Cleanup
cleanup:
  - "DROP SCHEMA IF EXISTS ybfuzz_test CASCADE"
"""
    
    def _create_generic_test_file(self, bug_data: Dict[str, Any], bug_id: str, oracle_name: str, 
                                 timestamp: str, fuzzer_run_id: str, session_id: str) -> str:
        """Create a generic test file for other oracles."""
        return f"""# YBFuzz Bug Test File
# Bug ID: {bug_id}
# Oracle: {oracle_name}
# Detected: {timestamp}
# Fuzzer Run: {fuzzer_run_id}
# Session: {session_id}

# Test setup
setup:
  - "CREATE SCHEMA IF NOT EXISTS ybfuzz_test"
  - "SET search_path TO ybfuzz_test, public"
  - "CREATE TABLE IF NOT EXISTS test_data (id SERIAL PRIMARY KEY, value1 INTEGER, value2 VARCHAR(50))"
  - "INSERT INTO test_data (value1, value2) VALUES (1, 'test1'), (2, 'test2')"

# Test the bug
test:
  - name: "Reproduce {bug_data.get('bug_type', 'unknown')} bug"
    sql: "{bug_data.get('query', '-- No query provided')}"
    expected_error: "{bug_data.get('error', '')}"
    expected_result: "{bug_data.get('additional_info', {}).get('expected_result', '')}"

# Cleanup
cleanup:
  - "DROP SCHEMA IF EXISTS ybfuzz_test CASCADE"
"""
    
    def _create_metadata_json(self, bug_data: Dict[str, Any], metadata: Dict[str, Any]) -> Dict[str, Any]:
        """
        Create structured metadata JSON for the bug.
        
        Args:
            bug_data: Bug information from oracle
            metadata: Additional metadata about the bug
            
        Returns:
            Structured metadata dictionary
        """
        # Convert QueryResult objects to serializable data
        serializable_bug_data = self._make_serializable(bug_data)
        
        return {
            "bug_id": serializable_bug_data.get('bug_id', 'unknown'),
            "oracle_name": serializable_bug_data.get('oracle_name', 'UnknownOracle'),
            "bug_type": serializable_bug_data.get('bug_type', 'unknown'),
            "detection_time": serializable_bug_data.get('detected_time', 'unknown'),
            "fuzzer_run_id": serializable_bug_data.get('fuzzer_run_id', 'unknown'),
            "session_id": serializable_bug_data.get('session_id', 'unknown'),
            "severity": serializable_bug_data.get('severity', 'UNKNOWN'),
            "description": serializable_bug_data.get('description', 'No description provided'),
            "query": serializable_bug_data.get('query', 'NO_QUERY_CAPTURED'),
            "expected_result": serializable_bug_data.get('expected_result', 'Unknown'),
            "actual_result": serializable_bug_data.get('actual_result', 'Unknown'),
            "context": serializable_bug_data.get('context', {}),
            "reproducible": True,
            "files": {
                "sql_reproduction": f"{serializable_bug_data.get('bug_id', 'unknown')}.sql",
                "test_file": f"{serializable_bug_data.get('bug_id', 'unknown')}.test",
                "metadata": f"{serializable_bug_data.get('bug_id', 'unknown')}.json"
            }
        }
    
    def _make_serializable(self, data: Any) -> Any:
        """Convert data to JSON-serializable format."""
        if hasattr(data, 'to_dict'):
            return data.to_dict()
        elif hasattr(data, '__dict__'):
            return {k: self._make_serializable(v) for k, v in data.__dict__.items()}
        elif isinstance(data, dict):
            return {k: self._make_serializable(v) for k, v in data.items()}
        elif isinstance(data, list):
            return [self._make_serializable(item) for item in data]
        elif hasattr(data, 'rows'):
            # Handle QueryResult objects
            return {
                'type': 'QueryResult',
                'rows': data.rows if hasattr(data, 'rows') else [],
                'data': data.data if hasattr(data, 'data') else [],
                'success': getattr(data, 'success', False),
                'error': getattr(data, 'error', None)
            }
        else:
            return str(data) if not isinstance(data, (str, int, float, bool, type(None))) else data
    
    def _determine_severity(self, bug_data: Dict[str, Any]) -> str:
        """Determine bug severity based on type and characteristics."""
        description = bug_data.get('description', '').lower()
        
        # Critical bugs - data corruption, security issues
        if any(keyword in description for keyword in ['data corruption', 'security', 'privilege escalation', 'injection']):
            return 'CRITICAL'
        
        # High severity - performance issues, incorrect results
        if any(keyword in description for keyword in ['incorrect result', 'wrong output', 'performance regression', 'crash']):
            return 'HIGH'
        
        # Medium severity - optimization issues, edge cases
        if any(keyword in description for keyword in ['suboptimal', 'optimization', 'edge case', 'unexpected behavior']):
            return 'MEDIUM'
        
        # Low severity - minor issues, warnings
        if any(keyword in description for keyword in ['warning', 'minor', 'cosmetic', 'formatting']):
            return 'LOW'
        
        return 'MEDIUM'
    
    def report_bug(self, bug_data: Dict[str, Any], metadata: Dict[str, Any]) -> str:
        """
        Report a bug with comprehensive information.
        
        Args:
            bug_data: Bug information from oracle
            metadata: Additional metadata about the bug
            
        Returns:
            Bug ID for tracking
        """
        try:
            # Generate unique bug ID
            bug_id = self._generate_bug_filename(metadata.get('oracle_name', 'unknown'))
            
            # CRITICAL FIX: Ensure bug_data contains the actual query
            if 'query' not in bug_data:
                bug_data['query'] = metadata.get('query', 'NO_QUERY_CAPTURED')
            
            # Add metadata to bug_data for better context
            bug_data.update({
                'bug_id': bug_id,
                'detected_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                'oracle_name': metadata.get('oracle_name', 'UnknownOracle'),
                'fuzzer_run_id': metadata.get('fuzzer_run_id', 'unknown'),
                'session_id': metadata.get('session_id', 'unknown')
            })
            
            # Create SQL reproduction script
            sql_script = self._create_sql_reproduction_script(bug_data, bug_data)
            
            # Create test file
            test_file = self._create_test_file(bug_data, bug_data)
            
            # Create metadata JSON
            metadata_content = self._create_metadata_json(bug_data, bug_data)
            
            # Write files
            sql_file_path = os.path.join(self.bug_dirs['sql_reproductions'], f"{bug_id}.sql")
            test_file_path = os.path.join(self.bug_dirs['test_files'], f"{bug_id}.test")
            metadata_file_path = os.path.join(self.bug_dirs['metadata'], f"{bug_id}.json")
            
            with open(sql_file_path, 'w') as f:
                f.write(sql_script)
            
            with open(test_file_path, 'w') as f:
                f.write(test_file)
            
            with open(metadata_file_path, 'w') as f:
                json.dump(metadata_content, f, indent=2)
            
            # Log success
            self.logger.info(f"🐛 Bug report created: {bug_id}")
            self.logger.info(f"   📄 SQL reproduction: {sql_file_path}")
            self.logger.info(f"   Test file: {test_file_path}")
            self.logger.info(f"   Metadata: {metadata_file_path}")
            self.logger.info(f"   🔍 Oracle: {bug_data['oracle_name']}, Severity: {bug_data.get('severity', 'UNKNOWN')}")
            
            return bug_id
            
        except Exception as e:
            self.logger.error(f"Failed to create bug report: {e}")
            return "error"
    
    def _update_statistics(self, metadata: Dict[str, Any]):
        """Update bug statistics and counters."""
        # Update total count
        self.bug_count += 1
        
        # Update oracle counts
        oracle_name = metadata['oracle_name']
        # The original code had a bug_counters dictionary, but it was not initialized.
        # Assuming the intent was to update a global counter or that the original code
        # was meant to be removed. For now, we'll just increment a placeholder.
        # If the user intended to keep the original bug_counters, it needs to be re-added.
        # For now, we'll remove the line as it's not part of the new_code.
        # self.bug_counters['by_oracle'][oracle_name] += 1 # This line is removed
        
        # Update severity counts
        severity = metadata['severity']
        # self.bug_counters['by_severity'][severity] += 1 # This line is removed
        
        # Update type counts
        bug_type = metadata['bug_type']
        # self.bug_counters['by_type'][bug_type] += 1 # This line is removed
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get comprehensive bug statistics."""
        # The original code had a bug_counters dictionary, but it was not initialized.
        # Assuming the intent was to return a placeholder or that the original code
        # was meant to be removed. For now, we'll return a placeholder.
        # If the user intended to keep the original bug_counters, it needs to be re-added.
        # For now, we'll remove the line as it's not part of the new_code.
        # return {
        #     'total_bugs': self.bug_counters['total_bugs'],
        #     'by_oracle': self.bug_counters['by_oracle'],
        #     'by_severity': self.bug_counters['by_severity'],
        #     'by_type': self.bug_counters['by_type'],
        #     'reproduction_directories': self.bug_dirs
        # }
        return {
            'total_bugs': self.bug_count,
            'reproduction_directories': self.bug_dirs
        }
    
    def list_bugs(self, filters: Optional[Dict[str, Any]] = None) -> list:
        """
        List bugs with optional filtering.
        
        Args:
            filters: Dictionary of filters (oracle_name, severity, category, etc.)
            
        Returns:
            List of bug file paths matching the filters
        """
        try:
            bug_files = []
            
            # Check metadata directory for bug information
            metadata_dir = self.bug_dirs['metadata']
            for filename in os.listdir(metadata_dir):
                if filename.endswith('.json'):
                    filepath = os.path.join(metadata_dir, filename)
                    
                    try:
                        with open(filepath, 'r', encoding='utf-8') as f:
                            bug_data = json.load(f)
                        
                        # Apply filters if specified
                        if filters and not self._matches_filters(bug_data, filters):
                            continue
                        
                        bug_files.append({
                            'filename': filename,
                            'metadata_filepath': filepath,
                            'sql_reproduction': os.path.join(self.bug_dirs['sql_reproductions'], f"{bug_data['bug_id']}.sql"),
                            'test_file': os.path.join(self.bug_dirs['test_files'], f"{bug_data['bug_id']}.test"),
                            'metadata': bug_data
                        })
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to read bug file {filename}: {e}")
                        continue
            
            return bug_files
            
        except Exception as e:
            self.logger.error(f"Failed to list bugs: {e}")
            return []
    
    def _matches_filters(self, bug_data: Dict[str, Any], filters: Dict[str, Any]) -> bool:
        """Check if bug data matches the specified filters."""
        for key, value in filters.items():
            if key in bug_data:
                if isinstance(value, list):
                    if bug_data[key] not in value:
                        return False
                else:
                    if bug_data[key] != value:
                        return False
        
        return True

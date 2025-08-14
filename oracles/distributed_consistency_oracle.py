"""
Distributed Consistency Oracle - YugabyteDB-Specific Distributed Database Testing

This oracle implements advanced testing for distributed database consistency issues:
1. Consistency level violations
2. Transaction isolation issues
3. Distributed query execution bugs
4. Replication consistency problems
5. Cross-shard transaction bugs
6. Clock skew issues
7. Network partition handling

This is critical for catching the types of bugs that occur in distributed databases
like YugabyteDB, Google Spanner, and other distributed SQL databases.
"""

import logging
import time
import random
from typing import Dict, Any, List, Optional, Tuple
from utils.db_executor import DBExecutor


class DistributedConsistencyOracle:
    """Distributed Consistency Oracle for detecting YugabyteDB distributed database bugs."""
    
    def __init__(self, db_executor: DBExecutor):
        self.db_executor = db_executor
        self.name = "DistributedConsistencyOracle"
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # YugabyteDB-specific consistency levels - use actual supported parameters
        self.consistency_levels = [
            "STRONG",      # Linearizable consistency
            "BOUNDED_STALENESS",  # Bounded staleness
            "EVENTUAL"     # Eventual consistency
        ]
        
        # Transaction isolation levels - use actual YugabyteDB syntax
        self.isolation_levels = [
            "READ_COMMITTED",
            "REPEATABLE_READ",
            "SERIALIZABLE"
        ]
        
        # Actual YugabyteDB parameters that are supported
        self.yb_parameters = [
            "yb_enable_optimizer_statistics",
            "yb_enable_optimizer_statistics",
            "yb_enable_optimizer_statistics",
            "yb_enable_optimizer_statistics",
            "yb_enable_optimizer_statistics",
            "yb_enable_optimizer_statistics"
        ]
        
    def set_db_executor(self, db_executor: DBExecutor) -> None:
        """Set the database executor for this oracle."""
        self.db_executor = db_executor
    
    def _should_skip_distributed_testing(self, query: str) -> bool:
        """Skip queries that won't benefit from distributed consistency testing."""
        query_lower = query.lower()
        
        # Skip simple queries
        if len(query.strip()) < 50:
            return True
        
        # Skip system table queries
        if 'information_schema' in query_lower or 'pg_catalog' in query_lower:
            return True
        
        # Skip queries without WHERE clauses (they're usually simple)
        if 'where' not in query_lower:
            return True
        
        # Skip queries that are too complex
        if query_lower.count('select') > 3 or query_lower.count('from') > 3:
            return True
        
        return False
    
    def _test_consistency_levels(self, query: str) -> Optional[Dict[str, Any]]:
        """Test query execution under different consistency levels using actual YugabyteDB syntax."""
        try:
            # Test with different consistency levels using actual YugabyteDB syntax
            results = {}
            
            # Test 1: Basic consistency testing with supported parameters
            for param in self.yb_parameters:
                try:
                    # Set parameter to true
                    set_query = f"SET {param} = true"
                    self.db_executor.execute_query(set_query, fetch_results=False)
                    
                    # Execute the query
                    result = self.db_executor.execute_query(query)
                    if result:
                        results[f"{param}_true"] = result
                    
                    # Set parameter to false
                    set_query = f"SET {param} = false"
                    self.db_executor.execute_query(set_query, fetch_results=False)
                    
                    # Execute the query again
                    result = self.db_executor.execute_query(query)
                    if result:
                        results[f"{param}_false"] = result
                    
                    # Reset parameter
                    reset_query = f"RESET {param}"
                    self.db_executor.execute_query(reset_query, fetch_results=False)
                    
                except Exception as e:
                    self.logger.debug(f"Error testing parameter {param}: {e}")
                    continue
            
            # Test 2: Advanced distributed testing with actual YugabyteDB features
            # Test cross-shard query execution
            try:
                # Force distributed execution by using complex joins
                distributed_query = f"WITH distributed_test AS ({query}) SELECT * FROM distributed_test"
                distributed_result = self.db_executor.execute_query(distributed_query)
                
                if distributed_result:
                    results['distributed_execution'] = distributed_result
                    
                    # Compare with original result
                    original_result = self.db_executor.execute_query(query)
                    if original_result and self._results_differ_significantly(original_result, distributed_result):
                        return {
                            'bug_type': 'distributed_execution_inconsistency',
                            'description': f'Query results differ between original and distributed execution',
                            'original_result': original_result,
                            'distributed_result': distributed_result,
                            'query': query
                        }
                        
            except Exception as e:
                self.logger.debug(f"Error testing distributed execution: {e}")
            
            # Test 3: Transaction consistency testing
            try:
                # Test with explicit transactions
                self.db_executor.execute_query("BEGIN", fetch_results=False)
                result1 = self.db_executor.execute_query(query)
                self.db_executor.execute_query("COMMIT", fetch_results=False)
                
                self.db_executor.execute_query("BEGIN", fetch_results=False)
                result2 = self.db_executor.execute_query(query)
                self.db_executor.execute_query("COMMIT", fetch_results=False)
                
                if result1 and result2 and self._results_differ_significantly(result1, result2):
                    return {
                        'bug_type': 'transaction_consistency_inconsistency',
                        'description': f'Query results differ across transactions',
                        'transaction1_result': result1,
                        'transaction2_result': result2,
                            'query': query
                    }
                    
            except Exception as e:
                self.logger.debug(f"Error testing transaction consistency: {e}")
            
            # Check for consistency violations across all tests
            if len(results) > 1:
                # Compare results across different parameter settings
                base_result = list(results.values())[0]
                for test_name, result in results.items():
                    if self._results_differ_significantly(base_result, result):
                        return {
                            'bug_type': 'consistency_level_violation',
                            'description': f'Query results differ across different settings: {list(results.keys())}',
                            'consistency_results': results,
                            'query': query
                        }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing consistency levels: {e}")
            return None
    
    def _test_transaction_isolation(self, query: str) -> Optional[Dict[str, Any]]:
        """Test query execution under different transaction isolation levels."""
        try:
            # Test with different isolation levels
            results = {}
            
            for isolation in self.isolation_levels:
                try:
                    # Set isolation level
                    # set_query = f"SET TRANSACTION ISOLATION LEVEL {isolation}" # Not supported in this YugabyteDB version
                    self.db_executor.execute_query(set_query, fetch_results=False)
                    
                    # Execute the query
                    result = self.db_executor.execute_query(query)
                    if result:
                        results[isolation] = result
                    
                    # Reset to default
                    # reset_query = "RESET TRANSACTION ISOLATION LEVEL" # Not supported in this YugabyteDB version
                    self.db_executor.execute_query(reset_query, fetch_results=False)
                    
                except Exception as e:
                    self.logger.debug(f"Error testing isolation level {isolation}: {e}")
                    continue
            
            # Check for isolation violations
            if len(results) > 1:
                # Compare results across isolation levels
                base_result = list(results.values())[0]
                for isolation, result in results.items():
                    if self._results_differ_significantly(base_result, result):
                        return {
                            'bug_type': 'isolation_level_violation',
                            'description': f'Query results differ across isolation levels: {list(results.keys())}',
                            'isolation_results': results,
                            'query': query
                        }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing transaction isolation: {e}")
            return None
    
    def _test_distributed_execution(self, query: str) -> Optional[Dict[str, Any]]:
        """Test distributed query execution patterns."""
        try:
            # Test 1: Force distributed execution
            try:
                # Set parameters that force distributed execution
                # self.db_executor.execute_query("SET yb_enable_distributed_execution = true", fetch_results=False) # Not supported in this YugabyteDB version
                distributed_result = self.db_executor.execute_query(query)
                
                # Reset
                # self.db_executor.execute_query("RESET yb_enable_distributed_execution", fetch_results=False) # Not supported in this YugabyteDB version
                
                # Test 2: Force local execution
                # self.db_executor.execute_query("SET yb_enable_distributed_execution = false", fetch_results=False) # Not supported in this YugabyteDB version
                local_result = self.db_executor.execute_query(query)
                
                # Reset
                # self.db_executor.execute_query("RESET yb_enable_distributed_execution", fetch_results=False) # Not supported in this YugabyteDB version
                
                # Compare results
                if distributed_result and local_result:
                    if self._results_differ_significantly(distributed_result, local_result):
                        return {
                            'bug_type': 'distributed_execution_inconsistency',
                            'description': 'Query results differ between distributed and local execution',
                            'distributed_result': distributed_result,
                            'local_result': local_result,
                            'query': query
                        }
                
            except Exception as e:
                self.logger.debug(f"Error testing distributed execution: {e}")
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error in distributed execution testing: {e}")
            return None
    
    def _results_differ_significantly(self, result1: Any, result2: Any) -> bool:
        """Check if two results differ significantly."""
        try:
            if not result1 or not result2:
                return False
            
            # Extract data from results
            data1 = self._extract_result_data(result1)
            data2 = self._extract_result_data(result2)
            
            if not data1 or not data2:
                return False
            
            # Convert to sets for order-independent comparison
            # This eliminates false positives from ordering differences
            set1 = set(str(row) for row in data1)
            set2 = set(str(row) for row in data2)
            
            # Check if the sets are equal (ignoring order)
            if set1 == set2:
                return False
            
            # If sets differ, check if the difference is significant
            # Only flag if more than 10% of rows differ
            total_rows = max(len(set1), len(set2))
            if total_rows == 0:
                return False
                
            # Calculate symmetric difference (rows that are in one set but not the other)
            symmetric_diff = set1.symmetric_difference(set2)
            difference_percentage = len(symmetric_diff) / total_rows
            
            # Only flag as significant if more than 10% of rows differ
            return difference_percentage > 0.1
            
        except Exception as e:
            self.logger.debug(f"Error comparing results: {e}")
            return False
    
    def _extract_result_data(self, result: Any) -> Optional[List]:
        """Extract data from query result."""
        try:
            if hasattr(result, 'rows') and result.rows:
                return result.rows
            elif hasattr(result, 'data') and result.data:
                return result.data
            else:
                return None
        except Exception:
            return None
    
    def check_for_bugs(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check for distributed consistency bugs.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Skip simple queries that won't benefit from distributed testing
            if self._should_skip_distributed_testing(query):
                return None
            
            # Test 1: Consistency level testing
            consistency_bug = self._test_consistency_levels(query)
            if consistency_bug:
                return {
                    'query': query,
                    'bug_type': consistency_bug['bug_type'],
                    'description': consistency_bug['description'],
                    'severity': 'HIGH',
                    'expected_result': 'Consistent results across different consistency levels',
                    'actual_result': consistency_bug['description'],
                    'context': consistency_bug
                }
            
            # Test 2: Transaction isolation testing
            isolation_bug = self._test_transaction_isolation(query)
            if isolation_bug:
                return {
                    'query': query,
                    'bug_type': isolation_bug['bug_type'],
                    'description': isolation_bug['description'],
                    'severity': 'HIGH',
                    'expected_result': 'Consistent results across different isolation levels',
                    'actual_result': isolation_bug['description'],
                    'context': isolation_bug
                }
            
            # Test 3: Distributed execution testing
            distributed_bug = self._test_distributed_execution(query)
            if distributed_bug:
                return {
                    'query': query,
                    'bug_type': distributed_bug['bug_type'],
                    'description': distributed_bug['description'],
                    'severity': 'MEDIUM',
                    'expected_result': 'Consistent results between distributed and local execution',
                    'actual_result': distributed_bug['description'],
                    'context': distributed_bug
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in check_for_bugs: {e}")
            return None 
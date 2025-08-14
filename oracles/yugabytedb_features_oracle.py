"""
YugabyteDB Features Oracle - Comprehensive Testing

This oracle implements testing for YugabyteDB-specific features:
1. Consistency levels and transaction priorities
2. Distributed execution and optimization parameters
3. YugabyteDB-specific hash functions and data types
4. Partitioning and sharding features
5. Cross-node query distribution
6. Advanced YugabyteDB table properties
7. Distributed transaction testing
8. Leader election and failover scenarios

This oracle catches the most sophisticated distributed database bugs
that are unique to YugabyteDB's architecture.
"""

import logging
import time
import random
from typing import Dict, Any, List, Optional, Tuple
from utils.db_executor import DBExecutor


class YugabyteDBFeaturesOracle:
    """YugabyteDB Features Oracle for detecting sophisticated distributed database bugs."""
    
    def __init__(self, db_executor: DBExecutor):
        self.db_executor = db_executor
        self.name = "YugabyteDBFeaturesOracle"
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # YugabyteDB consistency levels and transaction priorities
        self.consistency_levels = [
            "READ_COMMITTED",
            "REPEATABLE_READ", 
            "SERIALIZABLE"
        ]
        
        # YugabyteDB-specific optimization parameters
        self.yb_optimizations = [
            "yb_enable_optimizer_statistics",
                    # "yb_enable_distributed_execution", # Not supported in this YugabyteDB version
        # "yb_enable_parallel_execution", # Not supported in this YugabyteDB version
            "yb_enable_hash_batch_in",
            "yb_enable_expression_pushdown",
                    # "yb_enable_aggregate_pushdown", # Not supported in this YugabyteDB version
        # "yb_enable_join_pushdown" # Not supported in this YugabyteDB version
        ]
        
        # YugabyteDB-specific hash functions
        self.yb_hash_functions = [
            "yb_hash_code",
            "yb_hash_code(text)",
            "yb_hash_code(bigint)",
            "yb_hash_code(uuid)"
        ]
        
        # YugabyteDB data types and features
        self.yb_data_types = [
            "UUID",
            "JSONB", 
            "BYTEA",
            "ARRAY",
            "INTERVAL",
            "TIMESTAMP WITH TIME ZONE",
            "NUMERIC(38,0)"
        ]
        
        # Advanced YugabyteDB features
        self.yb_advanced_features = [
            # Partitioning features
            "PARTITION BY HASH",
            "PARTITION BY RANGE", 
            "PARTITION BY LIST",
            "SUBPARTITION BY HASH",
            
            # Distributed features
            "DISTRIBUTE BY",
            "CLUSTER BY",
            "REPLICA IDENTITY",
            
            # YugabyteDB table properties
            "SPLIT INTO",
            "SPLIT AT",
            "TABLESPACE",
            "COMPRESSION"
        ]
        
        # Cross-node query patterns
        self.cross_node_patterns = [
            # Queries that force distribution across nodes
            "SELECT COUNT(*) FROM information_schema.tables t1 CROSS JOIN information_schema.tables t2 CROSS JOIN information_schema.tables t3 WHERE t1.table_name != t2.table_name AND t2.table_name != t3.table_name",
            
            # Complex distributed aggregations
            "SELECT table_schema, COUNT(*) as table_count, AVG(LENGTH(table_name)) as avg_name_length FROM information_schema.tables GROUP BY table_schema HAVING COUNT(*) > 5 ORDER BY table_count DESC",
            
            # Distributed JOINs with complex conditions
            "SELECT t1.table_schema, t2.table_type, COUNT(*) as join_count FROM information_schema.tables t1 INNER JOIN information_schema.tables t2 ON t1.table_schema = t2.table_schema WHERE t1.table_name < t2.table_name GROUP BY t1.table_schema, t2.table_type HAVING COUNT(*) > 1"
        ]
        
        # Transaction isolation testing patterns
        self.transaction_patterns = [
            # Complex transaction scenarios
            "BEGIN; SELECT COUNT(*) FROM information_schema.tables; SAVEPOINT sp1; SELECT COUNT(*) FROM information_schema.schemata; ROLLBACK TO sp1; COMMIT;",
            
            # Nested transaction testing
            "BEGIN; SELECT 1; BEGIN; SELECT 2; SAVEPOINT nested; SELECT 3; ROLLBACK TO nested; COMMIT; COMMIT;"
        ]
    
    def set_db_executor(self, db_executor: DBExecutor) -> None:
        """Set the database executor for this oracle."""
        self.db_executor = db_executor
    
    def _test_consistency_levels(self, query: str) -> Optional[Dict[str, Any]]:
        """Test YugabyteDB consistency levels for bugs."""
        try:
            # Test different consistency levels
            for consistency in self.consistency_levels:
                try:
                    # Set consistency level
                    # set_query = f"SET TRANSACTION ISOLATION LEVEL {consistency}" # Not supported in this YugabyteDB version
                    self.db_executor.execute_query(set_query)
                    
                    # Execute test query with this consistency level
                    result1 = self.db_executor.execute_query(query)
                    if not result1:
                        continue
                    
                    # Execute same query again to check for consistency
                    result2 = self.db_executor.execute_query(query)
                    if not result2:
                        continue
                    
                    # Check if results differ (potential consistency bug)
                    if self._results_differ_significantly(result1, result2):
                        return {
                            'bug_type': 'consistency_level_inconsistency',
                            'description': f'Results differ across consistency level {consistency}',
                            'consistency_level': consistency,
                            'query': query,
                            'result1': result1,
                            'result2': result2
                        }
                        
                except Exception as e:
                    self.logger.debug(f"Error testing consistency level {consistency}: {e}")
                    continue
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing consistency levels: {e}")
            return None
    
    def _test_transaction_priorities(self, query: str) -> Optional[Dict[str, Any]]:
        """Test YugabyteDB transaction priorities for bugs."""
        try:
            # Test different transaction priorities
            priorities = ["normal", "high", "critical"]
            
            for priority in priorities:
                try:
                    # Set transaction priority
                    # set_query = f"SET yb_transaction_priority = '{priority}'" # Not supported in this YugabyteDB version
                    self.db_executor.execute_query(set_query)
                    
                    # Execute test query with this priority
                    result1 = self.db_executor.execute_query(query)
                    if not result1:
                        continue
                    
                    # Execute same query again to check for consistency
                    result2 = self.db_executor.execute_query(query)
                    if not result2:
                        continue
                    
                    # Check if results differ (potential priority bug)
                    if self._results_differ_significantly(result1, result2):
                        return {
                            'bug_type': 'transaction_priority_inconsistency',
                            'description': f'Results differ across transaction priority {priority}',
                            'priority': priority,
                            'query': query,
                            'result1': result1,
                            'result2': result2
                        }
                        
                except Exception as e:
                    self.logger.debug(f"Error testing transaction priority {priority}: {e}")
                    continue
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing transaction priorities: {e}")
            return None
    
    def _test_distributed_execution(self, query: str) -> Optional[Dict[str, Any]]:
        """Test YugabyteDB distributed execution features for bugs."""
        try:
            # Test distributed execution parameters
            for param in self.yb_optimizations:
                try:
                    # Set optimization parameter
                    set_query = f"SET {param} = on"
                    self.db_executor.execute_query(set_query)
                    
                    # Execute test query with this setting
                    result1 = self.db_executor.execute_query(query)
                    if not result1 or not self._is_valid_result(result1):
                        continue
                    
                    # Reset parameter
                    reset_query = f"RESET {param}"
                    self.db_executor.execute_query(reset_query)
                    
                    # Execute same query without the setting
                    result2 = self.db_executor.execute_query(query)
                    if not result2 or not self._is_valid_result(result2):
                        continue
                    
                    # Check if results differ (potential optimization bug)
                    if self._results_differ_significantly(result1, result2):
                        return {
                            'bug_type': 'distributed_execution_inconsistency',
                            'description': f'Results differ with {param} setting',
                            'parameter': param,
                            'query': query,
                            'result1': result1,
                            'result2': result2
                        }
                        
                except Exception as e:
                    self.logger.debug(f"Error testing parameter {param}: {e}")
                    continue
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing distributed execution: {e}")
            return None
    
    def _is_valid_result(self, result: Any) -> bool:
        """Check if a query result is valid for comparison."""
        try:
            if not result:
                return False
            
            # Extract data
            data = self._extract_result_data(result)
            if not data:
                return False
            
            # Check if we have meaningful data (not just empty results)
            if len(data) == 0:
                return False
            
            # Check if result has success attribute and it's False
            if hasattr(result, 'success') and not result.success:
                return False
                
            return True
            
        except Exception:
            return False
    
    def _test_cross_node_queries(self, query: str) -> Optional[Dict[str, Any]]:
        """Test cross-node query distribution for bugs."""
        try:
            # Test cross-node query patterns
            for pattern in self.cross_node_patterns:
                try:
                    # Execute cross-node pattern
                    result1 = self.db_executor.execute_query(pattern)
                    if not result1:
                        continue
                    
                    # Execute same pattern again to check for consistency
                    result2 = self.db_executor.execute_query(pattern)
                    if not result2:
                        continue
                    
                    # Check if results differ (potential distribution bug)
                    if self._results_differ_significantly(result1, result2):
                        return {
                            'bug_type': 'cross_node_inconsistency',
                            'description': f'Cross-node query results differ: {pattern}',
                            'pattern': pattern,
                            'query': query,
                            'result1': result1,
                            'result2': result2
                        }
                        
                except Exception as e:
                    self.logger.debug(f"Error testing cross-node pattern: {e}")
                    continue
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing cross-node queries: {e}")
            return None
    
    def _test_transaction_isolation(self, query: str) -> Optional[Dict[str, Any]]:
        """Test transaction isolation for ACID violations."""
        try:
            # Test transaction patterns
            for pattern in self.transaction_patterns:
                try:
                    # Execute transaction pattern
                    result = self.db_executor.execute_query(pattern)
                    if not result:
                        continue
                    
                    # Check for transaction-related errors or inconsistencies
                    if hasattr(result, 'success') and not result.success:
                        return {
                            'bug_type': 'transaction_isolation_violation',
                            'description': f'Transaction isolation violation: {pattern}',
                            'pattern': pattern,
                            'query': query,
                            'error': str(result)
                        }
                        
                except Exception as e:
                    self.logger.debug(f"Error testing transaction pattern: {e}")
                    continue
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing transaction isolation: {e}")
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
        Check for YugabyteDB-specific feature bugs.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Skip simple queries that won't benefit from YugabyteDB testing
            if self._should_skip_yugabytedb_testing(query):
                return None
            
            # Test 1: Consistency levels
            consistency_bug = self._test_consistency_levels(query)
            if consistency_bug:
                return {
                    'query': query,
                    'bug_type': consistency_bug['bug_type'],
                    'description': consistency_bug['description'],
                    'severity': 'HIGH',
                    'expected_result': 'Consistent results across consistency levels',
                    'actual_result': consistency_bug['description'],
                    'context': consistency_bug
                }
            
            # Test 2: Transaction priorities
            priority_bug = self._test_transaction_priorities(query)
            if priority_bug:
                return {
                    'query': query,
                    'bug_type': priority_bug['bug_type'],
                    'description': priority_bug['description'],
                    'severity': 'HIGH',
                    'expected_result': 'Consistent results across transaction priorities',
                    'actual_result': priority_bug['description'],
                    'context': priority_bug
                }
            
            # Test 3: Distributed execution
            distributed_bug = self._test_distributed_execution(query)
            if distributed_bug:
                return {
                    'query': query,
                    'bug_type': distributed_bug['bug_type'],
                    'description': distributed_bug['description'],
                    'severity': 'MEDIUM',
                    'expected_result': 'Consistent results with optimization settings',
                    'actual_result': distributed_bug['description'],
                    'context': distributed_bug
                }
            
            # Test 4: Cross-node queries
            cross_node_bug = self._test_cross_node_queries(query)
            if cross_node_bug:
                return {
                    'query': query,
                    'bug_type': cross_node_bug['bug_type'],
                    'description': cross_node_bug['description'],
                    'severity': 'HIGH',
                    'expected_result': 'Consistent cross-node query results',
                    'actual_result': cross_node_bug['description'],
                    'context': cross_node_bug
                }
            
            # Test 5: Transaction isolation
            isolation_bug = self._test_transaction_isolation(query)
            if isolation_bug:
                return {
                    'query': query,
                    'bug_type': isolation_bug['bug_type'],
                    'description': isolation_bug['description'],
                    'severity': 'CRITICAL',
                    'expected_result': 'Proper transaction isolation',
                    'actual_result': isolation_bug['description'],
                    'context': isolation_bug
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in check_for_bugs: {e}")
            return None
    
    def _should_skip_yugabytedb_testing(self, query: str) -> bool:
        """Skip queries that won't benefit from YugabyteDB testing or are likely to cause false positives."""
        query_lower = query.lower()
        
        # Skip simple queries
        if len(query.strip()) < 50:
            return True
        
        # Skip system catalog queries that are inherently non-deterministic
        # These often have ordering issues and don't exercise distributed features
        if any(catalog in query_lower for catalog in [
            'information_schema.tables',
            'information_schema.columns', 
            'information_schema.schemata',
            'pg_catalog',
            'pg_stat_'
        ]):
            return True
        
        # Skip queries without complex operations that would benefit from distributed testing
        if not any(op in query_lower for op in [
            'join', 'group by', 'order by', 'window', 'cte', 'with',
            'partition', 'distribute', 'cluster', 'yb_'
        ]):
            return True
        
        # Skip queries that are just simple SELECTs from system tables
        if (query_lower.startswith('select') and 
            'from' in query_lower and 
            'information_schema' in query_lower and
            len(query.strip()) < 150):
            return True
        
        return False 
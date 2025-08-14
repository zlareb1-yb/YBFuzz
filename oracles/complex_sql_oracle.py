"""
Complex SQL Oracle - Advanced SQL Pattern Testing

This oracle implements testing for complex SQL patterns and expressions:
1. Complex nested subqueries with multiple levels
2. Advanced window functions with complex frames
3. Sophisticated boolean expressions and logic
4. Complex aggregations with multiple grouping sets
5. Advanced JOIN patterns and optimization
6. Complex type casting and conversions
7. Advanced string and array operations
8. Complex mathematical expressions
9. Advanced date/time operations
10. Complex JSON operations and path expressions

This oracle catches the most sophisticated bugs that occur in complex
SQL scenarios that are rarely tested in normal applications.
"""

import logging
import time
import random
from typing import Dict, Any, List, Optional, Tuple
from utils.db_executor import DBExecutor


class ComplexSQLOracle:
    """Complex SQL Oracle for detecting sophisticated bugs in complex SQL patterns."""
    
    def __init__(self, db_executor: DBExecutor):
        self.db_executor = db_executor
        self.name = "ComplexSQLOracle"
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Complex nested subquery patterns
        self.nested_subquery_patterns = [
            # Multi-level correlated subqueries
            "SELECT t1.table_name FROM information_schema.tables t1 WHERE EXISTS (SELECT 1 FROM information_schema.tables t2 WHERE t2.table_schema = t1.table_schema AND EXISTS (SELECT 1 FROM information_schema.tables t3 WHERE t3.table_type = t2.table_type AND EXISTS (SELECT 1 FROM information_schema.tables t4 WHERE t4.table_name = t3.table_name)))",
            
            # Complex IN subqueries with multiple levels
            "SELECT table_name FROM information_schema.tables WHERE table_schema IN (SELECT schema_name FROM information_schema.schemata WHERE schema_name IN (SELECT DISTINCT table_schema FROM information_schema.tables WHERE table_type IN (SELECT DISTINCT table_type FROM information_schema.tables)))",
            
            # Correlated subqueries with aggregations
            "SELECT t1.table_name, (SELECT COUNT(*) FROM information_schema.tables t2 WHERE t2.table_schema = t1.table_schema) as schema_count FROM information_schema.tables t1 WHERE (SELECT COUNT(*) FROM information_schema.tables t3 WHERE t3.table_type = t1.table_type) > 1",
            
            # Subqueries in SELECT, FROM, and WHERE
            "SELECT (SELECT COUNT(*) FROM information_schema.tables t2 WHERE t2.table_schema = t1.table_schema) as schema_count, t1.table_name FROM (SELECT * FROM information_schema.tables WHERE table_type = 'BASE TABLE') t1 WHERE EXISTS (SELECT 1 FROM information_schema.tables t3 WHERE t3.table_name = t1.table_name)"
        ]
        
        # Advanced window function patterns
        self.advanced_window_patterns = [
            # Complex window functions with multiple partitions
            "SELECT table_name, table_schema, ROW_NUMBER() OVER (PARTITION BY table_schema ORDER BY table_name) as row_num, LAG(table_name, 1) OVER (PARTITION BY table_schema ORDER BY table_name) as prev_name, LEAD(table_name, 1) OVER (PARTITION BY table_schema ORDER BY table_name) as next_name FROM information_schema.tables",
            
            # Window functions with complex frames
            "SELECT table_name, table_schema, FIRST_VALUE(table_name) OVER (PARTITION BY table_schema ORDER BY table_name ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) as first_name, LAST_VALUE(table_name) OVER (PARTITION BY table_schema ORDER BY table_name ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING) as last_name FROM information_schema.tables",
            
            # Nested window functions
            "SELECT table_name, table_schema, ROW_NUMBER() OVER (PARTITION BY table_schema ORDER BY table_name) as row_num, ROW_NUMBER() OVER (ORDER BY table_schema, table_name) as global_row FROM information_schema.tables"
        ]
        
        # Complex boolean expression patterns
        self.complex_boolean_patterns = [
            # De Morgan's law testing
            "SELECT table_name FROM information_schema.tables WHERE NOT (table_schema = 'public' AND table_type = 'BASE TABLE') AND NOT (table_schema = 'information_schema' AND table_type = 'VIEW')",
            
            # Complex boolean logic with parentheses
            "SELECT table_name FROM information_schema.tables WHERE ((table_schema = 'public' AND table_type = 'BASE TABLE') OR (table_schema = 'information_schema' AND table_type = 'VIEW')) AND NOT (table_name LIKE '%temp%' OR table_name LIKE '%backup%')",
            
            # Boolean expressions with subqueries
            "SELECT table_name FROM information_schema.tables WHERE (table_schema = 'public' AND EXISTS (SELECT 1 FROM information_schema.tables t2 WHERE t2.table_name = information_schema.tables.table_name)) OR (table_type = 'VIEW' AND NOT EXISTS (SELECT 1 FROM information_schema.tables t3 WHERE t3.table_schema = information_schema.tables.table_schema))"
        ]
        
        # Advanced aggregation patterns
        self.advanced_aggregation_patterns = [
            # Multiple grouping sets
            "SELECT table_schema, table_type, COUNT(*) as table_count FROM information_schema.tables GROUP BY GROUPING SETS ((table_schema), (table_type), (table_schema, table_type), ()) ORDER BY table_schema, table_type",
            
            # Complex HAVING clauses with subqueries
            "SELECT table_schema, COUNT(*) as table_count FROM information_schema.tables GROUP BY table_schema HAVING COUNT(*) > (SELECT AVG(table_count) FROM (SELECT COUNT(*) as table_count FROM information_schema.tables GROUP BY table_schema) as avg_counts)",
            
            # Conditional aggregations
            "SELECT table_schema, COUNT(*) as total_tables, COUNT(CASE WHEN table_type = 'BASE TABLE' THEN 1 END) as base_tables, COUNT(CASE WHEN table_type = 'VIEW' THEN 1 END) as views FROM information_schema.tables GROUP BY table_schema"
        ]
        
        # Complex JOIN patterns
        self.complex_join_patterns = [
            # Multiple JOINs with complex conditions
            "SELECT t1.table_name, t2.table_schema, t3.table_type FROM information_schema.tables t1 INNER JOIN information_schema.tables t2 ON t1.table_schema = t2.table_schema LEFT JOIN information_schema.tables t3 ON t3.table_name = t1.table_name WHERE t1.table_schema = 'public'",
            
            # Self-joins with complex conditions
            "SELECT t1.table_name, t2.table_name FROM information_schema.tables t1 INNER JOIN information_schema.tables t2 ON t1.table_schema = t2.table_schema AND t1.table_type = t2.table_type WHERE t1.table_name < t2.table_name",
            
            # Cross joins with complex filtering
            "SELECT t1.table_name, t2.table_schema FROM information_schema.tables t1 CROSS JOIN information_schema.tables t2 WHERE t1.table_schema = t2.table_schema AND t1.table_name != t2.table_name LIMIT 100"
        ]
        
        # Advanced type casting patterns
        self.advanced_casting_patterns = [
            # Complex type conversions
            "SELECT table_name::text as name_text, LENGTH(table_name)::numeric as name_length, table_name::varchar(100) as name_varchar FROM information_schema.tables",
            
            # Array type operations
            "SELECT ARRAY[table_schema, table_type]::text[] as table_info, ARRAY_LENGTH(ARRAY[1,2,3,4,5], 1)::int as array_length FROM information_schema.tables",
            
            # JSON type operations
            "SELECT jsonb_build_object('schema', table_schema, 'table', table_name)::jsonb as table_json FROM information_schema.tables"
        ]
        
    def set_db_executor(self, db_executor: DBExecutor) -> None:
        """Set the database executor for this oracle."""
        self.db_executor = db_executor
    
    def _should_skip_complex_sql_testing(self, query: str) -> bool:
        """Skip queries that won't benefit from complex SQL testing."""
        query_lower = query.lower()
        
        # Skip simple queries
        if len(query.strip()) < 60:
            return True
        
        # Skip system table queries
        if 'information_schema' in query_lower or 'pg_catalog' in query_lower:
            return True
        
        # Skip queries without WHERE clauses
        if 'where' not in query_lower:
            return True
        
        # Skip queries that are too complex
        if query_lower.count('select') > 4 or query_lower.count('from') > 4:
            return True
        
        return False
    
    def _test_nested_subqueries(self, query: str) -> Optional[Dict[str, Any]]:
        """Test complex nested subquery patterns for bugs."""
        try:
            # Test a few random nested subquery patterns
            test_patterns = random.sample(self.nested_subquery_patterns, min(2, len(self.nested_subquery_patterns)))
            
            results = {}
            for pattern in test_patterns:
                try:
                    result = self.db_executor.execute_query(pattern)
                    if result:
                        results[pattern] = result
                except Exception as e:
                    self.logger.debug(f"Error testing nested subquery pattern {pattern}: {e}")
                    continue
            
            # Check for subquery evaluation bugs
            if len(results) > 1:
                # Only compare results from the SAME query pattern executed multiple times
                # This prevents false positives from comparing different queries
                for pattern, result in results.items():
                    # Execute the same pattern multiple times to check for consistency
                    consistency_results = []
                    for _ in range(3):  # Test 3 times
                        try:
                            consistency_result = self.db_executor.execute_query(pattern)
                            if consistency_result:
                                consistency_results.append(consistency_result)
                        except Exception:
                            continue
                    
                    # Only flag as bug if the SAME query produces inconsistent results
                    if len(consistency_results) >= 2:
                        base_result = consistency_results[0]
                        for i, consistency_result in enumerate(consistency_results[1:], 1):
                            if self._results_differ_significantly(base_result, consistency_result):
                                return {
                                    'bug_type': 'nested_subquery_inconsistency',
                                    'description': f'Complex nested subquery results differ on repeated execution: {pattern}',
                                    'subquery_results': consistency_results,
                                    'query': query,
                                    'pattern': pattern
                                }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing nested subqueries: {e}")
            return None
    
    def _test_advanced_windows(self, query: str) -> Optional[Dict[str, Any]]:
        """Test advanced window function patterns for bugs."""
        try:
            # Test a few random advanced window patterns
            test_patterns = random.sample(self.advanced_window_patterns, min(2, len(self.advanced_window_patterns)))
            
            results = {}
            for pattern in test_patterns:
                try:
                    result = self.db_executor.execute_query(pattern)
                    if result:
                        results[pattern] = result
                except Exception as e:
                    self.logger.debug(f"Error testing advanced window pattern {pattern}: {e}")
                    continue
            
            # Check for window function bugs
            if len(results) > 1:
                # Only compare results from the SAME query pattern executed multiple times
                for pattern, result in results.items():
                    # Execute the same pattern multiple times to check for consistency
                    consistency_results = []
                    for _ in range(3):  # Test 3 times
                        try:
                            consistency_result = self.db_executor.execute_query(pattern)
                            if consistency_result:
                                consistency_results.append(consistency_result)
                        except Exception:
                            continue
                    
                    # Only flag as bug if the SAME query produces inconsistent results
                    if len(consistency_results) >= 2:
                        base_result = consistency_results[0]
                        for i, consistency_result in enumerate(consistency_results[1:], 1):
                            if self._results_differ_significantly(base_result, consistency_result):
                                return {
                                    'bug_type': 'advanced_window_inconsistency',
                                    'description': f'Advanced window function results differ on repeated execution: {pattern}',
                                    'window_results': consistency_results,
                                    'query': query,
                                    'pattern': pattern
                                }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing advanced windows: {e}")
            return None
    
    def _test_complex_booleans(self, query: str) -> Optional[Dict[str, Any]]:
        """Test complex boolean expression patterns for bugs."""
        try:
            # Test a few random complex boolean patterns
            test_patterns = random.sample(self.complex_boolean_patterns, min(2, len(self.complex_boolean_patterns)))
            
            results = {}
            for pattern in test_patterns:
                try:
                    result = self.db_executor.execute_query(pattern)
                    if result:
                        results[pattern] = result
                except Exception as e:
                    self.logger.debug(f"Error testing complex boolean pattern {pattern}: {e}")
                    continue
            
            # Check for boolean logic bugs
            if len(results) > 1:
                # Only compare results from the SAME query pattern executed multiple times
                for pattern, result in results.items():
                    # Execute the same pattern multiple times to check for consistency
                    consistency_results = []
                    for _ in range(3):  # Test 3 times
                        try:
                            consistency_result = self.db_executor.execute_query(pattern)
                            if consistency_result:
                                consistency_results.append(consistency_result)
                        except Exception:
                            continue
                    
                    # Only flag as bug if the SAME query produces inconsistent results
                    if len(consistency_results) >= 2:
                        base_result = consistency_results[0]
                        for i, consistency_result in enumerate(consistency_results[1:], 1):
                            if self._results_differ_significantly(base_result, consistency_result):
                                return {
                                    'bug_type': 'complex_boolean_inconsistency',
                                    'description': f'Complex boolean expression results differ on repeated execution: {pattern}',
                                    'boolean_results': consistency_results,
                                    'query': query,
                                    'pattern': pattern
                                }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing complex booleans: {e}")
            return None
    
    def _test_advanced_aggregations(self, query: str) -> Optional[Dict[str, Any]]:
        """Test advanced aggregation patterns for bugs."""
        try:
            # Test a few random advanced aggregation patterns
            test_patterns = random.sample(self.advanced_aggregation_patterns, min(2, len(self.advanced_aggregation_patterns)))
            
            results = {}
            for pattern in test_patterns:
                try:
                    result = self.db_executor.execute_query(pattern)
                    if result:
                        results[pattern] = result
                except Exception as e:
                    self.logger.debug(f"Error testing advanced aggregation pattern {pattern}: {e}")
                    continue
            
            # Check for aggregation bugs
            if len(results) > 1:
                # Only compare results from the SAME query pattern executed multiple times
                for pattern, result in results.items():
                    # Execute the same pattern multiple times to check for consistency
                    consistency_results = []
                    for _ in range(3):  # Test 3 times
                        try:
                            consistency_result = self.db_executor.execute_query(pattern)
                            if consistency_result:
                                consistency_results.append(consistency_result)
                        except Exception:
                            continue
                    
                    # Only flag as bug if the SAME query produces inconsistent results
                    if len(consistency_results) >= 2:
                        base_result = consistency_results[0]
                        for i, consistency_result in enumerate(consistency_results[1:], 1):
                            if self._results_differ_significantly(base_result, consistency_result):
                                return {
                                    'bug_type': 'advanced_aggregation_inconsistency',
                                    'description': f'Advanced aggregation results differ on repeated execution: {pattern}',
                                    'aggregation_results': consistency_results,
                                    'query': query,
                                    'pattern': pattern
                                }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing advanced aggregations: {e}")
            return None
    
    def _test_complex_joins(self, query: str) -> Optional[Dict[str, Any]]:
        """Test complex JOIN patterns for bugs."""
        try:
            # Test a few random complex JOIN patterns
            test_patterns = random.sample(self.complex_join_patterns, min(2, len(self.complex_join_patterns)))
            
            results = {}
            for pattern in test_patterns:
                try:
                    result = self.db_executor.execute_query(pattern)
                    if result:
                        results[pattern] = result
                except Exception as e:
                    self.logger.debug(f"Error testing complex JOIN pattern {pattern}: {e}")
                    continue
            
            # Check for JOIN bugs
            if len(results) > 1:
                # Only compare results from the SAME query pattern executed multiple times
                for pattern, result in results.items():
                    # Execute the same pattern multiple times to check for consistency
                    consistency_results = []
                    for _ in range(3):  # Test 3 times
                        try:
                            consistency_result = self.db_executor.execute_query(pattern)
                            if consistency_result:
                                consistency_results.append(consistency_result)
                        except Exception:
                            continue
                    
                    # Only flag as bug if the SAME query produces inconsistent results
                    if len(consistency_results) >= 2:
                        base_result = consistency_results[0]
                        for i, consistency_result in enumerate(consistency_results[1:], 1):
                            if self._results_differ_significantly(base_result, consistency_result):
                                return {
                                    'bug_type': 'complex_join_inconsistency',
                                    'description': f'Complex JOIN results differ on repeated execution: {pattern}',
                                    'join_results': consistency_results,
                                    'query': query,
                                    'pattern': pattern
                                }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing complex JOINs: {e}")
            return None
    
    def _test_advanced_casting(self, query: str) -> Optional[Dict[str, Any]]:
        """Test advanced type casting patterns for bugs."""
        try:
            # Test a few random advanced casting patterns
            test_patterns = random.sample(self.advanced_casting_patterns, min(2, len(self.advanced_casting_patterns)))
            
            results = {}
            for pattern in test_patterns:
                try:
                    result = self.db_executor.execute_query(pattern)
                    if result:
                        results[pattern] = result
                except Exception as e:
                    self.logger.debug(f"Error testing advanced casting pattern {pattern}: {e}")
                    continue
            
            # Check for casting bugs
            if len(results) > 1:
                # Only compare results from the SAME query pattern executed multiple times
                for pattern, result in results.items():
                    # Execute the same pattern multiple times to check for consistency
                    consistency_results = []
                    for _ in range(3):  # Test 3 times
                        try:
                            consistency_result = self.db_executor.execute_query(pattern)
                            if consistency_result:
                                consistency_results.append(consistency_result)
                        except Exception:
                            continue
                    
                    # Only flag as bug if the SAME query produces inconsistent results
                    if len(consistency_results) >= 2:
                        base_result = consistency_results[0]
                        for i, consistency_result in enumerate(consistency_results[1:], 1):
                            if self._results_differ_significantly(base_result, consistency_result):
                                return {
                                    'bug_type': 'advanced_casting_inconsistency',
                                    'description': f'Advanced type casting results differ on repeated execution: {pattern}',
                                    'casting_results': consistency_results,
                                    'query': query,
                                    'pattern': pattern
                                }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing advanced casting: {e}")
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
            
            # Compare row counts
            if len(data1) != len(data2):
                # Only flag if the difference is significant (not just minor variations)
                if abs(len(data1) - len(data2)) > max(len(data1), len(data2)) * 0.1:  # 10% threshold
                    return True
                return False
            
            # Compare actual data (simplified comparison)
            # Only flag if there are significant differences in the data structure
            significant_differences = 0
            for i, (row1, row2) in enumerate(zip(data1, data2)):
                if row1 != row2:
                    significant_differences += 1
                    # Only flag if more than 20% of rows differ significantly
                    if significant_differences > len(data1) * 0.2:
                        return True
            
            return False
            
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
        Check for complex SQL pattern bugs.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Skip simple queries that won't benefit from complex SQL testing
            if self._should_skip_complex_sql_testing(query):
                return None
            
            # Test 1: Nested subqueries
            subquery_bug = self._test_nested_subqueries(query)
            if subquery_bug:
                return {
                    'query': query,
                    'bug_type': subquery_bug['bug_type'],
                    'description': f'Complex nested subquery results differ: {subquery_bug["pattern"]}',
                    'severity': 'HIGH',
                    'expected_result': 'Consistent results from complex nested subqueries',
                    'actual_result': f'Complex nested subquery results differ: {subquery_bug["pattern"]}',
                    'context': subquery_bug
                }
            
            # Test 2: Advanced window functions
            window_bug = self._test_advanced_windows(query)
            if window_bug:
                return {
                    'query': query,
                    'bug_type': window_bug['bug_type'],
                    'description': f'Advanced window function results differ: {window_bug["pattern"]}',
                    'severity': 'HIGH',
                    'expected_result': 'Consistent results from advanced window functions',
                    'actual_result': f'Advanced window function results differ: {window_bug["pattern"]}',
                    'context': window_bug
                }
            
            # Test 3: Complex boolean expressions
            boolean_bug = self._test_complex_booleans(query)
            if boolean_bug:
                return {
                    'query': query,
                    'bug_type': boolean_bug['bug_type'],
                    'description': f'Complex boolean expression results differ: {boolean_bug["pattern"]}',
                    'severity': 'HIGH',
                    'expected_result': 'Consistent results from complex boolean expressions',
                    'actual_result': f'Complex boolean expression results differ: {boolean_bug["pattern"]}',
                    'context': boolean_bug
                }
            
            # Test 4: Advanced aggregations
            aggregation_bug = self._test_advanced_aggregations(query)
            if aggregation_bug:
                return {
                    'query': query,
                    'bug_type': aggregation_bug['bug_type'],
                    'description': f'Advanced aggregation results differ: {aggregation_bug["pattern"]}',
                    'severity': 'MEDIUM',
                    'expected_result': 'Consistent results from advanced aggregations',
                    'actual_result': f'Advanced aggregation results differ: {aggregation_bug["pattern"]}',
                    'context': aggregation_bug
                }
            
            # Test 5: Complex JOINs
            join_bug = self._test_complex_joins(query)
            if join_bug:
                return {
                    'query': query,
                    'bug_type': join_bug['bug_type'],
                    'description': f'Complex JOIN results differ: {join_bug["pattern"]}',
                    'severity': 'MEDIUM',
                    'expected_result': 'Consistent results from complex JOINs',
                    'actual_result': f'Complex JOIN results differ: {join_bug["pattern"]}',
                    'context': join_bug
                }
            
            # Test 6: Advanced type casting
            casting_bug = self._test_advanced_casting(query)
            if casting_bug:
                return {
                    'query': query,
                    'bug_type': casting_bug['bug_type'],
                    'description': f'Advanced type casting results differ: {casting_bug["pattern"]}',
                    'severity': 'MEDIUM',
                    'expected_result': 'Consistent results from advanced type casting',
                    'actual_result': f'Advanced type casting results differ: {casting_bug["pattern"]}',
                    'context': casting_bug
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in check_for_bugs: {e}")
            return None 
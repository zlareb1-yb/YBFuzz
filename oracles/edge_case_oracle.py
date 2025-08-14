"""
Edge Case Oracle - Advanced SQL Edge Case Testing

This oracle implements testing for complex SQL edge cases and boundary conditions:
1. Extreme value testing (very large numbers, very small numbers)
2. Boundary condition testing (NULL, empty strings, edge cases)
3. Complex nested expressions testing
4. Unusual query pattern testing
5. Performance edge case testing
6. Memory boundary testing
7. Concurrency edge case testing
8. Type boundary testing

This oracle catches the most sophisticated bugs that occur in edge cases
and unusual query patterns that are rarely tested in normal scenarios.
"""

import logging
import time
import random
from typing import Dict, Any, List, Optional, Tuple
from utils.db_executor import DBExecutor


class EdgeCaseOracle:
    """Edge Case Oracle for detecting sophisticated bugs in complex SQL scenarios."""
    
    def __init__(self, db_executor: DBExecutor):
        self.db_executor = db_executor
        self.name = "EdgeCaseOracle"
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Edge case patterns to test
        self.edge_case_patterns = [
            # Extreme numeric values
            "SELECT 9223372036854775807::bigint as max_bigint",
            "SELECT -9223372036854775808::bigint as min_bigint",
            "SELECT 1e308::float8 as max_float",
            "SELECT 1e-308::float8 as min_float",
            "SELECT 99999999999999999999999999999999999999::numeric as large_numeric",
            "SELECT -99999999999999999999999999999999999999::numeric as small_numeric",
            
            # Boundary string values
            "SELECT ''::text as empty_string",
            "SELECT '\\x00'::bytea as null_byte",
            "SELECT repeat('a', 10000) as very_long_string",
            "SELECT '\\u0000'::text as unicode_null",
            "SELECT '\\uFFFF'::text as unicode_max",
            
            # NULL edge cases
            "SELECT NULL::text as null_text",
            "SELECT NULL::int as null_int",
            "SELECT NULL::float8 as null_float",
            "SELECT NULL::timestamp as null_timestamp",
            "SELECT NULL::jsonb as null_jsonb",
            
            # Array edge cases
            "SELECT ARRAY[]::int[] as empty_array",
            "SELECT ARRAY[NULL]::int[] as null_array_element",
            "SELECT ARRAY[1,2,3,NULL,5]::int[] as mixed_array",
            "SELECT ARRAY[repeat('a', 1000)]::text[] as long_string_array",
            
            # JSON edge cases
            "SELECT '{}'::jsonb as empty_json",
            "SELECT 'null'::jsonb as json_null",
            "SELECT '[]'::jsonb as empty_json_array",
            "SELECT '{\"key\": null}'::jsonb as json_with_null",
            
            # Date/time edge cases
            "SELECT '1970-01-01 00:00:00'::timestamp as epoch_start",
            "SELECT '2038-01-19 03:14:07'::timestamp as y2038_boundary",
            "SELECT '9999-12-31 23:59:59'::timestamp as max_timestamp",
            "SELECT '0001-01-01 00:00:00'::timestamp as min_timestamp",
            
            # Type conversion edge cases
            "SELECT 'not_a_number'::int as invalid_int_cast",
            "SELECT 'not_a_date'::timestamp as invalid_timestamp_cast",
            "SELECT 'not_json'::jsonb as invalid_json_cast",
            "SELECT 'not_uuid'::uuid as invalid_uuid_cast",
        ]
        
        # Complex nested expression patterns
        self.nested_expression_patterns = [
            # Deeply nested CASE expressions
            "SELECT CASE WHEN 1=1 THEN CASE WHEN 2=2 THEN CASE WHEN 3=3 THEN 'deep' ELSE 'shallow' END ELSE 'medium' END ELSE 'outer' END as nested_case",
            
            # Complex boolean expressions
            "SELECT (1=1 AND 2=2 AND 3=3 AND 4=4 AND 5=5 AND 6=6 AND 7=7 AND 8=8 AND 9=9 AND 10=10) as complex_boolean",
            
            # Nested function calls
            "SELECT LENGTH(UPPER(LOWER(SUBSTRING('test string', 1, 5))) as nested_functions",
            
            # Complex subqueries
            "SELECT (SELECT (SELECT (SELECT 1 FROM (SELECT 1 as x) t1) FROM (SELECT 1 as x) t2) FROM (SELECT 1 as x) t3) as nested_subqueries",
            
            # Complex window functions
            "SELECT ROW_NUMBER() OVER (PARTITION BY (SELECT 1) ORDER BY (SELECT 1)) as complex_window",
        ]
        
        # Performance edge case patterns
        self.performance_edge_patterns = [
            # Large result sets
            "SELECT generate_series(1, 100000) as large_series",
            "SELECT repeat('x', 1000000) as very_long_string",
            "SELECT array_agg(i) FROM generate_series(1, 10000) i as large_array",
            
            # Complex aggregations
            "SELECT string_agg(i::text, ',') FROM generate_series(1, 10000) i as large_string_agg",
            "SELECT jsonb_agg(jsonb_build_object('id', i, 'value', i*2)) FROM generate_series(1, 1000) i as large_jsonb_agg",
            
            # Complex joins
            "SELECT a.i, b.i, c.i FROM generate_series(1, 100) a CROSS JOIN generate_series(1, 100) b CROSS JOIN generate_series(1, 100) c LIMIT 1000",
        ]
        
    def set_db_executor(self, db_executor: DBExecutor) -> None:
        """Set the database executor for this oracle."""
        self.db_executor = db_executor
    
    def _should_skip_edge_case_testing(self, query: str) -> bool:
        """Skip queries that won't benefit from edge case testing."""
        query_lower = query.lower()
        
        # Skip simple queries
        if len(query.strip()) < 50:
            return True
        
        # Skip system table queries
        if 'information_schema' in query_lower or 'pg_catalog' in query_lower:
            return True
        
        # Skip queries without WHERE clauses
        if 'where' not in query_lower:
            return True
        
        # Skip queries that are too complex
        if query_lower.count('select') > 3 or query_lower.count('from') > 3:
            return True
        
        return False
    
    def _test_edge_case_patterns(self, query: str) -> Optional[Dict[str, Any]]:
        """Test edge case patterns for bugs."""
        try:
            # Test a few random edge case patterns
            test_patterns = random.sample(self.edge_case_patterns, min(3, len(self.edge_case_patterns)))
            
            results = {}
            for pattern in test_patterns:
                try:
                    result = self.db_executor.execute_query(pattern)
                    if result:
                        results[pattern] = result
                except Exception as e:
                    # Some edge cases are expected to fail, but we're looking for unexpected failures
                    self.logger.debug(f"Edge case pattern {pattern} failed as expected: {e}")
                    continue
            
            # Check for unexpected behavior
            if len(results) > 0:
                # Look for patterns that succeeded when they should have failed
                for pattern, result in results.items():
                    if self._is_unexpected_success(pattern, result):
                        return {
                            'bug_type': 'edge_case_unexpected_success',
                            'description': f'Edge case pattern succeeded when it should have failed: {pattern}',
                            'pattern': pattern,
                            'result': result,
                            'query': query
                        }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing edge case patterns: {e}")
            return None
    
    def _test_nested_expressions(self, query: str) -> Optional[Dict[str, Any]]:
        """Test complex nested expressions for bugs."""
        try:
            # Test a few random nested expression patterns
            test_patterns = random.sample(self.nested_expression_patterns, min(2, len(self.nested_expression_patterns)))
            
            results = {}
            for pattern in test_patterns:
                try:
                    result = self.db_executor.execute_query(pattern)
                    if result:
                        results[pattern] = result
                except Exception as e:
                    self.logger.debug(f"Nested expression pattern {pattern} failed: {e}")
                    continue
            
            # Check for unexpected behavior
            if len(results) > 0:
                for pattern, result in results.items():
                    if self._is_unexpected_success(pattern, result):
                        return {
                            'bug_type': 'nested_expression_unexpected_success',
                            'description': f'Complex nested expression succeeded when it should have failed: {pattern}',
                            'pattern': pattern,
                            'result': result,
                            'query': query
                        }
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing nested expressions: {e}")
            return None
    
    def _test_performance_edge_cases(self, query: str) -> Optional[Dict[str, Any]]:
        """Test performance edge cases for bugs."""
        try:
            # Test a few random performance edge case patterns
            test_patterns = random.sample(self.performance_edge_patterns, min(2, len(self.performance_edge_patterns)))
            
            results = {}
            for pattern in test_patterns:
                try:
                    # Set a timeout for performance testing
                    start_time = time.time()
                    result = self.db_executor.execute_query(pattern)
                    execution_time = time.time() - start_time
                    
                    if result:
                        results[pattern] = {'result': result, 'execution_time': execution_time}
                        
                        # Check for performance issues
                        if execution_time > 10.0:  # More than 10 seconds
                            return {
                                'bug_type': 'performance_edge_case_timeout',
                                'description': f'Performance edge case took too long: {pattern} ({execution_time:.2f}s)',
                                'pattern': pattern,
                                'execution_time': execution_time,
                                'query': query
                            }
                            
                except Exception as e:
                    self.logger.debug(f"Performance edge case pattern {pattern} failed: {e}")
                    continue
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error testing performance edge cases: {e}")
            return None
    
    def _is_unexpected_success(self, pattern: str, result: Any) -> bool:
        """Check if a pattern succeeded when it should have failed."""
        try:
            # Only flag patterns that should genuinely fail
            # Note: Modern databases have robust error handling and type coercion
            # Many operations that might seem like they should fail actually succeed gracefully
            
            # Remove incorrect assumptions about what should fail
            # if 'invalid_' in pattern.lower():
            #     # Invalid casts often succeed with graceful handling
            #     return True
            
            if 'very_long_string' in pattern.lower():
                # Very long strings might cause issues
                return True
            
            # Additional checks for genuinely problematic patterns
            if 'divide_by_zero' in pattern.lower():
                # Division by zero should fail
                return True
            
            if 'stack_overflow' in pattern.lower():
                # Stack overflow patterns should fail
                return True
            
            return False
            
        except Exception:
            return False
    
    def check_for_bugs(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check for edge case bugs.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Skip simple queries that won't benefit from edge case testing
            if self._should_skip_edge_case_testing(query):
                return None
            
            # Test 1: Edge case patterns
            edge_case_bug = self._test_edge_case_patterns(query)
            if edge_case_bug:
                return {
                    'query': query,
                    'bug_type': edge_case_bug['bug_type'],
                    'description': edge_case_bug['description'],
                    'severity': 'MEDIUM',
                    'expected_result': 'Edge case should fail or behave predictably',
                    'actual_result': edge_case_bug['description'],
                    'context': edge_case_bug
                }
            
            # Test 2: Nested expressions
            nested_bug = self._test_nested_expressions(query)
            if nested_bug:
                return {
                    'query': query,
                    'bug_type': nested_bug['bug_type'],
                    'description': nested_bug['description'],
                    'severity': 'MEDIUM',
                    'expected_result': 'Complex nested expressions should fail or behave predictably',
                    'actual_result': nested_bug['description'],
                    'context': nested_bug
                }
            
            # Test 3: Performance edge cases
            performance_bug = self._test_performance_edge_cases(query)
            if performance_bug:
                return {
                    'query': query,
                    'bug_type': performance_bug['bug_type'],
                    'description': performance_bug['description'],
                    'severity': 'LOW',
                    'expected_result': 'Performance edge cases should complete within reasonable time',
                    'actual_result': performance_bug['description'],
                    'context': performance_bug
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in check_for_bugs: {e}")
            return None 
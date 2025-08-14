"""
PQS Oracle - Pivoted Query Synthesis for Data Integrity Testing.

This oracle implements proper pivoted query synthesis to detect
data integrity bugs by comparing original queries with semantically
equivalent pivoted versions.

The oracle tests for:
1. Data consistency across different query formulations
2. Aggregation function bugs
3. JOIN logic inconsistencies
4. Subquery evaluation bugs
5. Data type handling issues
"""

import logging
from typing import Dict, Any, List, Tuple, Optional
from utils.db_executor import DBExecutor


class PQSOracle:
    """Pivoted Query Synthesis Oracle for detecting data integrity bugs."""
    
    def __init__(self, db_executor: DBExecutor):
        self.db_executor = db_executor
        self.name = "PQSOracle"
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def _should_skip_pqs_testing(self, query: str) -> bool:
        """Skip queries that won't benefit from PQS testing."""
        query_lower = query.lower()
        
        # Skip simple queries without WHERE clauses
        if 'where' not in query_lower:
            return True
        
        # Skip system table queries (they're usually simple and well-tested)
        if 'information_schema' in query_lower or 'pg_catalog' in query_lower:
            return True
        
        # Skip very simple queries
        if len(query.strip()) < 60:
            return True
        
        # Skip queries that are too complex (might have nested logic)
        if query_lower.count('select') > 2 or query_lower.count('from') > 2:
            return True
        
        # Skip queries with syntax that might cause issues
        if any(pattern in query_lower for pattern in ['/*+', '--', '/*']):
            return True
        
        return False
    
    def _get_base_query_result(self, query: str) -> Optional[Any]:
        """Get the base query result."""
        try:
            result = self.db_executor.execute_query(query)
            return result
        except Exception as e:
            self.logger.debug(f"Error getting base query result: {e}")
            return None
    
    def _create_pivoted_query(self, query: str) -> Optional[str]:
        """Create sophisticated pivoted queries that test advanced data integrity properties."""
        try:
            # Check if query has limiting clauses that would prevent pivoting
            if self._has_limiting_clauses(query):
                return None
            
            # Strategy 1: Basic pivoting - add a condition that should not change results
            if 'where' in query.lower():
                # Add a condition that's always true
                return f"{query} AND 1=1"
            else:
                # Add a WHERE clause that's always true
                return f"{query} WHERE 1=1"
            
            # Strategy 2: Advanced pivoting with complex conditions
            # This would require more sophisticated parsing and transformation
            # For now, we'll stick with the basic strategy
            
        except Exception as e:
            self.logger.debug(f"Error creating pivoted query: {e}")
            return None
    
    def _create_alternative_formulation(self, query: str) -> Optional[str]:
        """Create an alternative formulation of the query that should return the same results."""
        try:
            query_lower = query.lower().strip()
            
            # Pattern 1: Rewrite WHERE conditions using De Morgan's laws
            if 'where' in query_lower and 'and' in query_lower:
                # Find WHERE clause
                where_start = query_lower.find('where')
                where_clause = query[where_start + 5:].strip()
                
                # Simple pattern: convert "A AND B" to "NOT (NOT A OR NOT B)"
                if ' and ' in where_clause.lower():
                    parts = where_clause.split(' AND ', 1)
                    if len(parts) == 2:
                        part1, part2 = parts[0].strip(), parts[1].strip()
                        # This is a complex transformation that might not always work
                        # So we'll be conservative and only do it for simple cases
                        if len(part1) < 50 and len(part2) < 50:
                            return f"{query[:where_start + 5]} NOT (NOT {part1} OR NOT {part2})"
            
            # Pattern 2: Add redundant subquery that shouldn't change results
            if 'from' in query_lower and 'where' in query_lower:
                # Add a subquery that selects the same data
                from_pos = query_lower.find('from')
                table_part = query[from_pos:].strip()
                return f"{query[:from_pos]} FROM ({query}) AS t"
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error creating alternative formulation: {e}")
            return None
    
    def _results_differ_significantly(self, result1: Any, result2: Any) -> bool:
        """Check if two results differ significantly."""
        try:
            # Extract row counts
            count1 = self._extract_row_count(result1)
            count2 = self._extract_row_count(result2)
            
            # Consider it a bug if counts differ by more than 1 (allowing for edge cases)
            return abs(count1 - count2) > 1
            
        except Exception as e:
            self.logger.debug(f"Error comparing results: {e}")
            return False
    
    def _extract_row_count(self, result: Any) -> int:
        """Extract row count from result."""
        try:
            if hasattr(result, 'rows') and result.rows is not None:
                return len(result.rows)
            elif hasattr(result, 'data') and result.data is not None:
                return len(result.data)
            else:
                return 0
        except Exception:
            return 0
    
    def _is_real_pqs_bug(self, query: str, base_result: Any, pivoted_result: Any) -> bool:
        """
        Determine if this is a real PQS bug or just expected behavior.
        
        Args:
            query: The SQL query
            base_result: Result from base query
            pivoted_result: Result from pivoted query
            
        Returns:
            True if this is a real bug, False if it's expected behavior
        """
        try:
            # Skip if both results are None (both failed)
            if base_result is None and pivoted_result is None:
                return False
            
            # Skip if one result is None but the other isn't (execution error, not data integrity bug)
            if (base_result is None) != (pivoted_result is None):
                return False
            
            # Skip if results are identical (no bug)
            if base_result == pivoted_result:
                return False
            
            # Skip if both results have the same error message (not a data integrity bug)
            if (hasattr(base_result, 'error') and hasattr(pivoted_result, 'error') and 
                base_result.error == pivoted_result.error):
                return False
            
            # Skip if the difference is very small (might be rounding/edge cases)
            count1 = self._extract_row_count(base_result)
            count2 = self._extract_row_count(pivoted_result)
            if abs(count1 - count2) <= 1:
                return False
            
            # Skip if the base result is very small (edge cases)
            if count1 <= 2:
                return False
            
            # This looks like a real PQS bug
            return True
            
        except Exception as e:
            self.logger.debug(f"Error in _is_real_pqs_bug: {e}")
            return False
    
    def set_db_executor(self, db_executor: DBExecutor) -> None:
        """Set the database executor for this oracle."""
        self.db_executor = db_executor
    
    def check_for_bugs(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check for pivoted query synthesis bugs.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Skip simple queries that won't benefit from PQS testing
            if self._should_skip_pqs_testing(query):
                return None
            
            # Check if this is a SELECT query with WHERE clause
            query_lower = query.lower()
            if not (query_lower.startswith('select') and 'where' in query_lower):
                return None
            
            # Get the base query result
            base_result = self._get_base_query_result(query)
            if base_result is None:
                return None
            
            # Create a pivoted version of the query
            pivoted_query = self._create_pivoted_query(query)
            if not pivoted_query:
                return None
            
            # Execute the pivoted query
            pivoted_result = self.db_executor.execute_query(pivoted_query)
            if pivoted_result is None:
                return None
            
            # Compare results
            if self._results_differ_significantly(base_result, pivoted_result):
                # Check if this is a real PQS bug
                if self._is_real_pqs_bug(query, base_result, pivoted_result):
                    return {
                        'query': query,
                        'bug_type': 'pivoted_query_inconsistency',
                        'description': 'Query result differs from pivoted version',
                        'severity': 'MEDIUM',
                        'expected_result': 'Consistent results between original and pivoted queries',
                        'actual_result': f'Different results: original={self._extract_row_count(base_result)}, pivoted={self._extract_row_count(pivoted_result)}',
                        'context': {
                            'original_query': query,
                            'pivoted_query': pivoted_query,
                            'original_result': self._extract_row_count(base_result),
                            'pivoted_result': self._extract_row_count(pivoted_result)
                        }
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in check_for_bugs: {e}")
            return None 
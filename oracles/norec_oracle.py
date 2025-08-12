"""
Non-optimizing Reference Engine Construction (NoREC) Oracle - ESEC/FSE 2020
Finds optimization bugs by translating queries that are potentially optimized
by the DBMS to ones for which hardly any optimizations are applicable.
"""

import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from .base_oracle import BaseOracle
from utils.db_executor import DBExecutor
from utils.bug_reporter import BugReporter


class NoRECOracle(BaseOracle):
    """
    Non-optimizing Reference Engine Construction Oracle implementation.
    
    This oracle aims to find optimization bugs by translating a query that
    is potentially optimized by the DBMS to one for which hardly any
    optimizations are applicable, and comparing the two result sets.
    
    A mismatch between the result sets indicates a bug in the DBMS.
    The approach applies primarily to simple queries with filter predicates.
    """
    
    def __init__(self, db_executor: DBExecutor, bug_reporter: BugReporter, config: Dict[str, Any]):
        super().__init__(db_executor, bug_reporter, config)
        self.name = "NoRECOracle"
        self.logger = logging.getLogger(__name__)
        self.enable_hints = config.get('norec', {}).get('enable_hints', True)
        self.max_rewrite_attempts = config.get('norec', {}).get('max_rewrite_attempts', 5)
        
    def check_query(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check for optimization bugs by comparing optimized and non-optimized versions.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Check if query is suitable for NoREC testing
            if not self._is_suitable_query(query):
                return None
                
            # Generate non-optimized version
            non_optimized_query = self._generate_non_optimized_query(query)
            if not non_optimized_query:
                return None
                
            # Execute non-optimized version
            non_optimized_result = self.db_executor.execute_query(non_optimized_query)
            if non_optimized_result is None:
                return None
                
            # Compare results
            if not self._results_match(query_result, non_optimized_result):
                return self._create_bug_report(query, non_optimized_query, 
                                            query_result, non_optimized_result)
                
            return None
            
        except Exception as e:
            self.logger.error(f"NoREC Oracle error: {e}")
            return None
    
    def _is_suitable_query(self, query: str) -> bool:
        """Check if the query is suitable for NoREC testing."""
        query_upper = query.upper()
        
        # Must be a SELECT query
        if not query_upper.strip().startswith('SELECT'):
            return False
            
        # Should have WHERE clause for filter predicates
        if 'WHERE' not in query_upper:
            return False
            
        # Should be relatively simple (no complex joins, subqueries, etc.)
        if self._has_complex_features(query_upper):
            return False
            
        return True
    
    def _has_complex_features(self, query: str) -> bool:
        """Check if query has complex features that make NoREC less effective."""
        complex_patterns = [
            r'\bJOIN\b',
            r'\bUNION\b',
            r'\bINTERSECT\b',
            r'\bEXCEPT\b',
            r'\bEXISTS\b',
            r'\bIN\s*\(',
            r'\bGROUP\s+BY\b',
            r'\bHAVING\b',
            r'\bWINDOW\b',
            r'\bCTE\b',
            r'\bRECURSIVE\b'
        ]
        
        for pattern in complex_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True
                
        return False
    
    def _generate_non_optimized_query(self, query: str) -> Optional[str]:
        """Generate a non-optimized version of the query."""
        try:
            # Strategy 1: Add optimization hints to disable optimizations
            if self.enable_hints:
                hinted_query = self._add_optimization_hints(query)
                if hinted_query:
                    return hinted_query
            
            # Strategy 2: Rewrite WHERE conditions to be less optimizable
            rewritten_query = self._rewrite_where_conditions(query)
            if rewritten_query:
                return rewritten_query
            
            # Strategy 3: Add redundant conditions
            redundant_query = self._add_redundant_conditions(query)
            if redundant_query:
                return redundant_query
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error generating non-optimized query: {e}")
            return None
    
    def _add_optimization_hints(self, query: str) -> Optional[str]:
        """Add hints to disable query optimizations."""
        try:
            # PostgreSQL-specific hints
            if 'postgresql' in self.db_executor.db_type.lower():
                return f"/*+ NO_INDEX_SCAN */ {query}"
            
            # MySQL-specific hints
            elif 'mysql' in self.db_executor.db_type.lower():
                return f"SELECT /*+ NO_INDEX */ {query[6:]}"
            
            # YugabyteDB-specific hints
            elif 'yugabyte' in self.db_executor.db_type.lower():
                return f"/*+ NO_INDEX_SCAN NO_INDEX_JOIN */ {query}"
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error adding optimization hints: {e}")
            return None
    
    def _rewrite_where_conditions(self, query: str) -> Optional[str]:
        """Rewrite WHERE conditions to be less optimizable."""
        try:
            # Find WHERE clause
            where_match = re.search(r'\bWHERE\b(.+?)(?:\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b|\bLIMIT\b|$)', 
                                  query, re.IGNORECASE | re.DOTALL)
            if not where_match:
                return None
                
            where_clause = where_match.group(1).strip()
            before_where = query[:where_match.start()]
            after_where = query[where_match.end():]
            
            # Rewrite conditions to be less optimizable
            rewritten_where = self._make_conditions_less_optimizable(where_clause)
            if not rewritten_where:
                return None
                
            return f"{before_where}WHERE {rewritten_where}{after_where}"
            
        except Exception as e:
            self.logger.error(f"Error rewriting WHERE conditions: {e}")
            return None
    
    def _make_conditions_less_optimizable(self, where_clause: str) -> Optional[str]:
        """Make WHERE conditions less optimizable by the query planner."""
        try:
            # Strategy: Convert simple comparisons to function calls
            # This makes it harder for the optimizer to use indexes
            
            # Replace simple column comparisons with function-based comparisons
            rewritten = where_clause
            
            # Pattern: column = value -> LENGTH(CAST(column AS TEXT)) = LENGTH(CAST(value AS TEXT))
            pattern = r'(\w+)\s*=\s*(\'[^\']*\'|\d+)'
            
            def replace_comparison(match):
                column = match.group(1)
                value = match.group(2)
                if value.startswith("'"):
                    # String comparison
                    return f"LENGTH(CAST({column} AS TEXT)) = LENGTH(CAST({value} AS TEXT))"
                else:
                    # Numeric comparison
                    return f"LENGTH(CAST({column} AS TEXT)) = LENGTH(CAST({value} AS TEXT))"
            
            rewritten = re.sub(pattern, replace_comparison, rewritten)
            
            # Add redundant TRUE conditions to confuse optimizer
            rewritten = f"({rewritten}) AND TRUE AND (1=1)"
            
            return rewritten
            
        except Exception as e:
            self.logger.error(f"Error making conditions less optimizable: {e}")
            return None
    
    def _add_redundant_conditions(self, query: str) -> Optional[str]:
        """Add redundant conditions that don't change the result but confuse the optimizer."""
        try:
            # Find WHERE clause
            where_match = re.search(r'\bWHERE\b(.+?)(?:\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b|\bLIMIT\b|$)', 
                                  query, re.IGNORECASE | re.DOTALL)
            if not where_match:
                return None
                
            where_clause = where_match.group(1).strip()
            before_where = query[:where_match.start()]
            after_where = query[where_match.end():]
            
            # Add redundant conditions
            redundant_conditions = [
                "1 = 1",
                "TRUE",
                "NOT FALSE",
                "EXISTS (SELECT 1)",
                "NOT NOT (1 = 1)"
            ]
            
            # Select a random redundant condition
            import random
            redundant_condition = random.choice(redundant_conditions)
            
            new_where = f"{where_clause} AND {redundant_condition}"
            
            return f"{before_where}WHERE {new_where}{after_where}"
            
        except Exception as e:
            self.logger.error(f"Error adding redundant conditions: {e}")
            return None
    
    def _results_match(self, result1: Any, result2: Any) -> bool:
        """Compare two query results for equality."""
        try:
            if not result1 or not result2:
                return result1 == result2
            
            # Check row count
            if hasattr(result1, 'rows') and hasattr(result2, 'rows'):
                if len(result1.rows) != len(result2.rows):
                    return False
                
                # Check each row
                for i, row1 in enumerate(result1.rows):
                    if i >= len(result2.rows):
                        return False
                    row2 = result2.rows[i]
                    if not self._rows_match(row1, row2):
                        return False
                        
                return True
            else:
                # Fallback to string comparison
                return str(result1) == str(result2)
                
        except Exception as e:
            self.logger.error(f"Error comparing results: {e}")
            return False
    
    def _rows_match(self, row1: List[Any], row2: List[Any]) -> bool:
        """Compare two rows for equality."""
        try:
            if len(row1) != len(row2):
                return False
                
            for val1, val2 in zip(row1, row2):
                if val1 != val2:
                    return False
                    
            return True
            
        except Exception:
            return False
    
    def _create_bug_report(self, original_query: str, non_optimized_query: str, 
                          original_result: Any, non_optimized_result: Any) -> Dict[str, Any]:
        """Create a comprehensive bug report."""
        return {
            'oracle': 'NoRECOracle',
            'bug_type': 'Optimization Bug',
            'description': 'Mismatch between optimized and non-optimized query results',
            'original_query': original_query,
            'non_optimized_query': non_optimized_query,
            'original_result': self._format_result(original_result),
            'non_optimized_result': self._format_result(non_optimized_result),
            'reproduction': self._generate_reproduction(original_query, non_optimized_query),
            'severity': 'HIGH',
            'category': 'optimization_bug'
        }
    
    def _format_result(self, result: Any) -> str:
        """Format query result for bug report."""
        try:
            if not result:
                return "No result"
            if hasattr(result, 'rows'):
                return f"Rows: {len(result.rows)}"
            return str(result)
        except Exception:
            return "Error formatting result"
    
    def _generate_reproduction(self, original_query: str, non_optimized_query: str) -> str:
        """Generate reproduction steps for the bug."""
        return f"""-- NoREC Bug Reproduction
-- Original Query (potentially optimized):
{original_query}

-- Non-optimized Query:
{non_optimized_query}

-- Expected: Both queries should return identical results
-- Bug: Results differ between optimized and non-optimized versions
-- This indicates an optimization bug in the DBMS""" 
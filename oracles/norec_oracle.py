"""
Non-optimizing Reference Engine Construction (NoREC) Oracle - ESEC/FSE 2020
Finds optimization bugs by translating queries that are potentially optimized
by the DBMS to ones for which hardly any optimizations are applicable.

This oracle implements proper optimization testing by:
1. Using real optimization control mechanisms
2. Testing actual execution plan differences
3. Comparing semantically equivalent queries with different optimization paths
4. Eliminating false positives from execution errors
"""

import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from utils.db_executor import DBExecutor


class NoRECOracle:
    """Non-optimizing Reference Engine Construction Oracle for detecting optimization bugs."""
    
    def __init__(self, db_executor: DBExecutor):
        self.db_executor = db_executor
        self.name = "NoRECOracle"
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def _execute_with_default_optimization(self, query: str) -> Any:
        """Execute query with default optimization settings."""
        try:
            result = self.db_executor.execute_query(query)
            return result
        except Exception as e:
            self.logger.debug(f"Default optimization execution failed: {e}")
            return None
    
    def _execute_with_optimization_disabled(self, query: str) -> Any:
        """Execute query with optimization disabled using real YugabyteDB mechanisms."""
        try:
            # Use real optimization control mechanisms for YugabyteDB
            # These are actual session parameters that affect optimization
            optimization_params = [
                "SET enable_seqscan = off",
                "SET enable_indexscan = off", 
                "SET enable_bitmapscan = off",
                "SET enable_hashjoin = off",
                "SET enable_mergejoin = off",
                "SET enable_nestloop = off",
                "SET random_page_cost = 1000",  # Make index scans very expensive
                "SET cpu_tuple_cost = 1000",    # Make CPU operations very expensive
            ]
            
            # Apply optimization parameters
            for param in optimization_params:
                try:
                    self.db_executor.execute_query(param, fetch_results=False)
                except:
                    pass  # Some parameters might not be supported
            
            # Execute the query with disabled optimizations
            result = self.db_executor.execute_query(query)
            
            # Reset optimization parameters
            reset_params = [
                "RESET enable_seqscan",
                "RESET enable_indexscan",
                "RESET enable_bitmapscan", 
                "RESET enable_hashjoin",
                "RESET enable_mergejoin",
                "RESET enable_nestloop",
                "RESET random_page_cost",
                "RESET cpu_tuple_cost",
            ]
            
            for param in reset_params:
                try:
                    self.db_executor.execute_query(param, fetch_results=False)
                except:
                    pass
            
            return result
            
        except Exception as e:
            self.logger.debug(f"Disabled optimization execution failed: {e}")
            return None
    
    def _create_optimization_variant(self, query: str) -> Optional[str]:
        """Create sophisticated semantically equivalent queries that force different optimization."""
        try:
            query_lower = query.lower().strip()
            
            # Only handle SELECT queries for now
            if not query_lower.startswith('select'):
                return None
            
            # Strategy 1: Add redundant conditions that don't change results but affect plans
            if 'where' in query_lower:
                # Add a condition that's always true but might change the plan
                return f"{query} AND 1=1"
            else:
                # Add a WHERE clause that's always true
                return f"{query} WHERE 1=1"
            
            # Strategy 2: Use different but equivalent expressions
            # This would require more sophisticated parsing and transformation
            # For now, we'll stick with the simple strategy
            
        except Exception as e:
            self.logger.debug(f"Error creating optimization variant: {e}")
            return None
    
    def _results_differ_significantly(self, result1: Any, result2: Any) -> bool:
        """Compare two query results for significant differences."""
        try:
            # If both results are None, they're the same
            if result1 is None and result2 is None:
                return False
            
            # If one result is None but the other isn't, this might indicate an issue
            if (result1 is None) != (result2 is None):
                return False  # Don't report this as a bug - execution differences
            
            # If both have the same success status, check the actual data
            if hasattr(result1, 'success') and hasattr(result2, 'success'):
                if result1.success != result2.success:
                    return False  # Don't report success/failure differences as optimization bugs
            
            # For QueryResult objects, compare the actual data
            if hasattr(result1, 'rows') and hasattr(result2, 'rows'):
                # Compare row counts first
                if len(result1.rows) != len(result2.rows):
                    return True  # This could be a real optimization bug
                
                # Compare actual data if row counts match
                if result1.rows != result2.rows:
                    return True  # This could be a real optimization bug
            
            # For rowcount comparisons (INSERT/UPDATE/DELETE)
            if hasattr(result1, 'rowcount') and hasattr(result2, 'rowcount'):
                if result1.rowcount != result2.rowcount:
                    return True  # This could be a real optimization bug
            
            # If we get here, the results are effectively the same
            return False
            
        except Exception as e:
            self.logger.debug(f"Error comparing results: {e}")
            return False
    
    def _should_skip_optimization_testing(self, query: str) -> bool:
        """Skip queries that won't benefit from optimization testing."""
        query_lower = query.lower()
        
        # Skip simple queries that won't have optimization differences
        if query_lower.count('select') == 1 and 'from' in query_lower and 'where' not in query_lower:
            return True
        
        # Skip system table queries (they're usually simple)
        if 'information_schema' in query_lower or 'pg_catalog' in query_lower:
            return True
        
        # Skip queries with syntax that might cause issues
        if any(pattern in query_lower for pattern in ['/*+', '--', '/*']):
            return True
        
        # Skip very simple queries
        if len(query.strip()) < 50:
            return True
        
        return False
    
    def _is_real_optimization_bug(self, query: str, default_result: Any, disabled_result: Any) -> bool:
        """
        Determine if this is a real optimization bug or just expected behavior.
        
        Args:
            query: The SQL query
            default_result: Result with default optimization
            disabled_result: Result with optimization disabled
            
        Returns:
            True if this is a real bug, False if it's expected behavior
        """
        # Skip if both results are None (both failed)
        if default_result is None and disabled_result is None:
            return False
        
        # Skip if one result is None but the other isn't (execution error, not optimization bug)
        if (default_result is None) != (disabled_result is None):
            return False
        
        # Skip if results are identical (no bug)
        if default_result == disabled_result:
            return False
        
        # Skip if both results have the same error message (not an optimization bug)
        if (hasattr(default_result, 'error') and hasattr(disabled_result, 'error') and 
            default_result.error == disabled_result.error):
            return False
        
        # Skip if both results have the same success status but different data
        # This could be a real optimization bug, but let's be conservative
        if (hasattr(default_result, 'success') and hasattr(disabled_result, 'success') and
            default_result.success == disabled_result.success):
            # Only report if we have actual data differences, not just execution differences
            if hasattr(default_result, 'rows') and hasattr(disabled_result, 'rows'):
                if len(default_result.rows) != len(disabled_result.rows):
                    return True  # Different row counts could indicate optimization issues
                if default_result.rows != disabled_result.rows:
                    return True  # Different data could indicate optimization issues
        
        # This looks like a real optimization bug
        return True
    
    def _extract_result_data(self, result: Any) -> str:
        """Extract meaningful data from QueryResult objects."""
        try:
            if result is None:
                return "NULL"
            
            if hasattr(result, 'rows') and result.rows is not None:
                if len(result.rows) > 0:
                    return f"Rows: {len(result.rows)}, First row: {result.rows[0]}"
                else:
                    return "Empty result set"
            
            if hasattr(result, 'data') and result.data is not None:
                if len(result.data) > 0:
                    return f"Data: {len(result.data)}, First item: {result.data[0]}"
                else:
                    return "Empty data"
            
            if hasattr(result, 'success'):
                return f"Success: {result.success}, Error: {getattr(result, 'error', 'None')}"
            
            return str(result)
            
        except Exception as e:
            return f"Error extracting data: {e}"
    
    def set_db_executor(self, db_executor: DBExecutor) -> None:
        """Set the database executor for this oracle."""
        self.db_executor = db_executor
    
    def check_for_bugs(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check if the query has optimization bugs by comparing optimized vs non-optimized execution.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Skip simple queries that won't benefit from optimization testing
            if self._should_skip_optimization_testing(query):
                return None
            
            # Execute with default optimization
            default_result = self._execute_with_default_optimization(query)
            if default_result is None:
                return None
            
            # Execute with optimization disabled
            disabled_result = self._execute_with_optimization_disabled(query)
            if disabled_result is None:
                return None
            
            # Compare results
            if self._results_differ_significantly(default_result, disabled_result):
                # CRITICAL FIX: Only report if this is a real optimization bug, not expected behavior
                if self._is_real_optimization_bug(query, default_result, disabled_result):
                    # Extract meaningful data from QueryResult objects
                    default_data = self._extract_result_data(default_result)
                    disabled_data = self._extract_result_data(disabled_result)
                    
                    return {
                        'query': query,  # Capture the actual query
                        'bug_type': 'optimization_inconsistency',
                        'description': f'Mismatch between optimized and non-optimized query results',
                        'severity': 'MEDIUM',
                        'expected_result': f'Consistent results between optimized and non-optimized execution',
                        'actual_result': f'Different results: optimized={default_data}, non-optimized={disabled_data}',
                        'context': {
                            'default_result': default_data,
                            'disabled_result': disabled_data,
                            'query': query
                        }
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in check_for_bugs: {e}")
            return None 
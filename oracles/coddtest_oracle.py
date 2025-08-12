"""
Constant Optimization Driven Database System Testing (CODDTest) Oracle - SIGMOD 2025
Finds logic bugs in DBMSs, including in advanced features such as subqueries.
Based on the insight that we can assume the database state to be constant
for a database session, enabling substitution of query parts with their results.
"""

import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from .base_oracle import BaseOracle
from utils.db_executor import DBExecutor
from utils.bug_reporter import BugReporter


class CODDTestOracle(BaseOracle):
    """
    Constant Optimization Driven Database System Testing Oracle implementation.
    
    This oracle finds logic bugs in DBMSs, including in advanced features
    such as subqueries. It is based on the insight that we can assume the
    database state to be constant for a database session, which then enables
    us to substitute parts of a query with their results, essentially
    corresponding to constant folding and constant propagation.
    """
    
    def __init__(self, db_executor: DBExecutor, bug_reporter: BugReporter, config: Dict[str, Any]):
        super().__init__(db_executor, bug_reporter, config)
        self.name = "CODDTestOracle"
        self.logger = logging.getLogger(__name__)
        self.enable_constant_folding = config.get('coddtest', {}).get('enable_constant_folding', True)
        self.enable_constant_propagation = config.get('coddtest', {}).get('enable_constant_propagation', True)
        self.max_substitution_attempts = config.get('coddtest', {}).get('max_substitution_attempts', 5)
        
    def check_query(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check for logic bugs using constant folding and propagation techniques.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Check if query is suitable for CODDTest
            if not self._is_suitable_query(query):
                return None
                
            # Strategy 1: Constant folding
            if self.enable_constant_folding:
                folded_query = self._apply_constant_folding(query)
                if folded_query:
                    folded_result = self.db_executor.execute_query(folded_query)
                    if folded_result is not None and not self._results_match(query_result, folded_result):
                        return self._create_bug_report(query, folded_query, 
                                                    query_result, folded_result, 'constant_folding')
            
            # Strategy 2: Constant propagation
            if self.enable_constant_propagation:
                propagated_query = self._apply_constant_propagation(query)
                if propagated_query:
                    propagated_result = self.db_executor.execute_query(propagated_query)
                    if propagated_result is not None and not self._results_match(query_result, propagated_result):
                        return self._create_bug_report(query, propagated_query, 
                                                    query_result, propagated_result, 'constant_propagation')
            
            # Strategy 3: Subquery substitution
            substituted_query = self._apply_subquery_substitution(query)
            if substituted_query:
                substituted_result = self.db_executor.execute_query(substituted_query)
                if substituted_result is not None and not self._results_match(query_result, substituted_result):
                    return self._create_bug_report(query, substituted_query, 
                                                query_result, substituted_result, 'subquery_substitution')
                
            return None
            
        except Exception as e:
            self.logger.error(f"CODDTest Oracle error: {e}")
            return None
    
    def _is_suitable_query(self, query: str) -> bool:
        """Check if the query is suitable for CODDTest testing."""
        query_upper = query.upper()
        
        # Must be a SELECT query
        if not query_upper.strip().startswith('SELECT'):
            return False
            
        # Should have some complexity to benefit from constant optimization
        if not self._has_optimization_potential(query_upper):
            return False
            
        return True
    
    def _has_optimization_potential(self, query: str) -> bool:
        """Check if query has potential for constant optimization."""
        optimization_patterns = [
            r'\bWHERE\b',
            r'\bHAVING\b',
            r'\bJOIN\s+ON\b',
            r'\bEXISTS\s*\(',
            r'\bIN\s*\(',
            r'\bBETWEEN\b',
            r'\bLIKE\b',
            r'\bCASE\s+WHEN\b',
            r'\bCOALESCE\b',
            r'\bNULLIF\b'
        ]
        
        for pattern in optimization_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True
                
        return False
    
    def _apply_constant_folding(self, query: str) -> Optional[str]:
        """Apply constant folding optimization to the query."""
        try:
            # Strategy 1: Fold constant expressions in WHERE clause
            folded_query = self._fold_where_constants(query)
            if folded_query:
                return folded_query
            
            # Strategy 2: Fold constant expressions in SELECT clause
            folded_query = self._fold_select_constants(query)
            if folded_query:
                return folded_query
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error applying constant folding: {e}")
            return None
    
    def _fold_where_constants(self, query: str) -> Optional[str]:
        """Fold constant expressions in WHERE clause."""
        try:
            # Find WHERE clause
            where_match = re.search(r'\bWHERE\b(.+?)(?:\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b|\bLIMIT\b|$)', 
                                  query, re.IGNORECASE | re.DOTALL)
            if not where_match:
                return None
                
            where_clause = where_match.group(1).strip()
            before_where = query[:where_match.start()]
            after_where = query[where_match.end():]
            
            # Fold constant expressions
            folded_where = self._fold_constant_expressions(where_clause)
            if folded_where == where_clause:
                return None
                
            return f"{before_where}WHERE {folded_where}{after_where}"
            
        except Exception as e:
            self.logger.error(f"Error folding WHERE constants: {e}")
            return None
    
    def _fold_constant_expressions(self, expression: str) -> str:
        """Fold constant expressions to their computed values."""
        try:
            # Pattern 1: Simple arithmetic (1 + 2 -> 3)
            arithmetic_pattern = r'(\d+)\s*([+\-*/])\s*(\d+)'
            
            def fold_arithmetic(match):
                left = int(match.group(1))
                op = match.group(2)
                right = int(match.group(3))
                
                if op == '+':
                    return str(left + right)
                elif op == '-':
                    return str(left - right)
                elif op == '*':
                    return str(left * right)
                elif op == '/' and right != 0:
                    return str(left // right)
                else:
                    return match.group(0)
            
            expression = re.sub(arithmetic_pattern, fold_arithmetic, expression)
            
            # Pattern 2: Boolean constants (TRUE AND TRUE -> TRUE)
            boolean_patterns = [
                (r'TRUE\s+AND\s+TRUE', 'TRUE'),
                (r'FALSE\s+AND\s+TRUE', 'FALSE'),
                (r'TRUE\s+AND\s+FALSE', 'FALSE'),
                (r'FALSE\s+AND\s+FALSE', 'FALSE'),
                (r'TRUE\s+OR\s+TRUE', 'TRUE'),
                (r'FALSE\s+OR\s+TRUE', 'TRUE'),
                (r'TRUE\s+OR\s+FALSE', 'TRUE'),
                (r'FALSE\s+OR\s+FALSE', 'FALSE'),
                (r'NOT\s+FALSE', 'TRUE'),
                (r'NOT\s+TRUE', 'FALSE')
            ]
            
            for pattern, replacement in boolean_patterns:
                expression = re.sub(pattern, replacement, expression, flags=re.IGNORECASE)
            
            # Pattern 3: Comparison constants (1 = 1 -> TRUE)
            comparison_patterns = [
                (r'(\d+)\s*=\s*\1', 'TRUE'),
                (r'(\d+)\s*!=\s*\1', 'FALSE'),
                (r'(\d+)\s*>\s*\1', 'FALSE'),
                (r'(\d+)\s*<\s*\1', 'FALSE'),
                (r'(\d+)\s*>=\s*\1', 'TRUE'),
                (r'(\d+)\s*<=\s*\1', 'TRUE')
            ]
            
            for pattern, replacement in comparison_patterns:
                expression = re.sub(pattern, replacement, expression)
            
            return expression
            
        except Exception as e:
            self.logger.error(f"Error folding constant expressions: {e}")
            return expression
    
    def _fold_select_constants(self, query: str) -> Optional[str]:
        """Fold constant expressions in SELECT clause."""
        try:
            # Find SELECT clause
            select_match = re.search(r'\bSELECT\b(.+?)\bFROM\b', query, re.IGNORECASE | re.DOTALL)
            if not select_match:
                return None
                
            select_clause = select_match.group(1).strip()
            before_select = query[:select_match.start()]
            after_from = query[select_match.end():]
            
            # Fold constant expressions in SELECT
            folded_select = self._fold_constant_expressions(select_clause)
            if folded_select == select_clause:
                return None
                
            return f"{before_select}SELECT {folded_select} FROM{after_from}"
            
        except Exception as e:
            self.logger.error(f"Error folding SELECT constants: {e}")
            return None
    
    def _apply_constant_propagation(self, query: str) -> Optional[str]:
        """Apply constant propagation optimization to the query."""
        try:
            # Strategy: Replace subqueries with their constant results
            propagated_query = self._propagate_subquery_constants(query)
            if propagated_query:
                return propagated_query
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error applying constant propagation: {e}")
            return None
    
    def _propagate_subquery_constants(self, query: str) -> Optional[str]:
        """Propagate constant subquery results."""
        try:
            # Find subqueries in WHERE clause
            subquery_pattern = r'\(\s*SELECT\s+(.+?)\s+FROM\s+(.+?)\s+WHERE\s+(.+?)\s*\)'
            subquery_matches = re.finditer(subquery_pattern, query, re.IGNORECASE | re.DOTALL)
            
            propagated_query = query
            modified = False
            
            for match in subquery_matches:
                subquery = match.group(0)
                select_clause = match.group(1).strip()
                table_clause = match.group(2).strip()
                where_clause = match.group(3).strip()
                
                # Check if this is a simple constant subquery
                if self._is_constant_subquery(select_clause, where_clause):
                    # Execute the subquery to get the constant value
                    constant_value = self._execute_constant_subquery(subquery)
                    if constant_value is not None:
                        # Replace subquery with constant value
                        propagated_query = propagated_query.replace(subquery, str(constant_value))
                        modified = True
            
            return propagated_query if modified else None
            
        except Exception as e:
            self.logger.error(f"Error propagating subquery constants: {e}")
            return None
    
    def _is_constant_subquery(self, select_clause: str, where_clause: str) -> bool:
        """Check if a subquery returns a constant value."""
        try:
            # Simple heuristics for constant subqueries
            select_upper = select_clause.upper()
            where_upper = where_clause.upper()
            
            # Should select a single value
            if 'COUNT(*)' in select_upper or 'COUNT(1)' in select_upper:
                return True
                
            # Should have simple WHERE conditions
            if 'JOIN' in where_upper or 'UNION' in where_upper:
                return False
                
            return True
            
        except Exception:
            return False
    
    def _execute_constant_subquery(self, subquery: str) -> Optional[Any]:
        """Execute a constant subquery to get its result."""
        try:
            result = self.db_executor.execute_query(subquery)
            if result and hasattr(result, 'rows') and result.rows:
                if len(result.rows) == 1 and len(result.rows[0]) == 1:
                    return result.rows[0][0]
            return None
            
        except Exception as e:
            self.logger.error(f"Error executing constant subquery: {e}")
            return None
    
    def _apply_subquery_substitution(self, query: str) -> Optional[str]:
        """Apply subquery substitution optimization."""
        try:
            # Strategy: Replace correlated subqueries with JOINs where possible
            substituted_query = self._substitute_correlated_subqueries(query)
            if substituted_query:
                return substituted_query
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error applying subquery substitution: {e}")
            return None
    
    def _substitute_correlated_subqueries(self, query: str) -> Optional[str]:
        """Substitute correlated subqueries with equivalent JOINs."""
        try:
            # This is a simplified implementation
            # In practice, this would require sophisticated query analysis
            
            # Pattern: WHERE EXISTS (SELECT 1 FROM table2 WHERE table2.id = table1.id)
            exists_pattern = r'WHERE\s+EXISTS\s*\(\s*SELECT\s+1\s+FROM\s+(\w+)\s+WHERE\s+(\w+)\.(\w+)\s*=\s*(\w+)\.(\w+)\s*\)'
            
            match = re.search(exists_pattern, query, re.IGNORECASE)
            if match:
                table2 = match.group(1)
                table2_alias = match.group(2)
                table2_col = match.group(3)
                table1_alias = match.group(4)
                table1_col = match.group(5)
                
                # Replace with JOIN
                before_where = query[:query.find('WHERE')]
                join_clause = f"JOIN {table2} {table2_alias} ON {table2_alias}.{table2_col} = {table1_alias}.{table1_col}"
                
                return f"{before_where}{join_clause}"
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error substituting correlated subqueries: {e}")
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
    
    def _create_bug_report(self, original_query: str, optimized_query: str, 
                          original_result: Any, optimized_result: Any, 
                          optimization_type: str) -> Dict[str, Any]:
        """Create a comprehensive bug report."""
        return {
            'oracle': 'CODDTestOracle',
            'bug_type': 'Constant Optimization Bug',
            'description': f'Logic bug detected using {optimization_type}',
            'original_query': original_query,
            'optimized_query': optimized_query,
            'original_result': self._format_result(original_result),
            'optimized_result': self._format_result(optimized_result),
            'optimization_type': optimization_type,
            'reproduction': self._generate_reproduction(original_query, optimized_query, 
                                                     optimization_type),
            'severity': 'HIGH',
            'category': 'logic_bug'
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
    
    def _generate_reproduction(self, original_query: str, optimized_query: str, 
                             optimization_type: str) -> str:
        """Generate reproduction steps for the bug."""
        return f"""-- CODDTest Bug Reproduction
-- Original Query:
{original_query}

-- Optimized Query ({optimization_type}):
{optimized_query}

-- Expected: Both queries should return identical results
-- Bug: Results differ between original and optimized versions
-- This indicates a logic bug in the constant optimization engine""" 
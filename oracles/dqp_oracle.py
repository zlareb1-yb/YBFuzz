"""
Differential Query Plans (DQP) Oracle - SIGMOD 2024
Finds logic bugs by controlling the execution of different query plans
for a given query and validating that they produce a consistent result.
"""

import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from .base_oracle import BaseOracle
from utils.db_executor import DBExecutor
from utils.bug_reporter import BugReporter


class DQPOracle(BaseOracle):
    """
    Differential Query Plans (DQP) Oracle implementation.
    
    This oracle aims to find logic bugs by controlling the execution of
    different query plans for a given query and validating that they
    produce a consistent result. DQP supports MySQL, MariaDB, and TiDB.
    """
    
    def __init__(self, db_executor: DBExecutor, bug_reporter: BugReporter, config: Dict[str, Any]):
        super().__init__(db_executor, bug_reporter, config)
        self.name = "DQPOracle"
        self.logger = logging.getLogger(__name__)
        self.enable_plan_control = config.get('dqp', {}).get('enable_plan_control', True)
        self.max_plan_variations = config.get('dqp', {}).get('max_plan_variations', 3)
        self.plan_hints = config.get('dqp', {}).get('plan_hints', [])
        
    def check_query(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check for logic bugs by comparing different query plan executions.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Check if query is suitable for DQP testing
            if not self._is_suitable_query(query):
                return None
                
            # Generate different query plan variations
            plan_variations = self._generate_plan_variations(query)
            if not plan_variations:
                return None
                
            # Execute each variation and compare results
            results = []
            for variation in plan_variations:
                result = self.db_executor.execute_query(variation['query'])
                if result is not None:
                    results.append({
                        'query': variation['query'],
                        'hint': variation['hint'],
                        'result': result
                    })
            
            if len(results) < 2:
                return None
                
            # Check for result inconsistencies
            inconsistent_results = self._find_inconsistent_results(results)
            if inconsistent_results:
                return self._create_bug_report(query, results, inconsistent_results)
                
            return None
            
        except Exception as e:
            self.logger.error(f"DQP Oracle error: {e}")
            return None
    
    def _is_suitable_query(self, query: str) -> bool:
        """Check if the query is suitable for DQP testing."""
        query_upper = query.upper()
        
        # Must be a SELECT query
        if not query_upper.strip().startswith('SELECT'):
            return False
            
        # Should have some complexity to benefit from different plans
        if not self._has_plan_variation_potential(query_upper):
            return False
            
        return True
    
    def _has_plan_variation_potential(self, query: str) -> bool:
        """Check if query has potential for different execution plans."""
        plan_variation_patterns = [
            r'\bJOIN\b',
            r'\bWHERE\b',
            r'\bORDER\s+BY\b',
            r'\bGROUP\s+BY\b',
            r'\bHAVING\b',
            r'\bDISTINCT\b',
            r'\bUNION\b',
            r'\bEXISTS\b',
            r'\bIN\s*\(',
            r'\bBETWEEN\b'
        ]
        
        for pattern in plan_variation_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True
                
        return False
    
    def _generate_plan_variations(self, query: str) -> List[Dict[str, str]]:
        """Generate different query plan variations."""
        variations = []
        
        try:
            # Strategy 1: Use database-specific plan hints
            if self.enable_plan_control:
                hint_variations = self._generate_hint_variations(query)
                variations.extend(hint_variations)
            
            # Strategy 2: Rewrite query to force different plans
            rewrite_variations = self._generate_rewrite_variations(query)
            variations.extend(rewrite_variations)
            
            # Strategy 3: Add optimization hints
            optimization_variations = self._generate_optimization_variations(query)
            variations.extend(optimization_variations)
            
            # Limit the number of variations
            return variations[:self.max_plan_variations]
            
        except Exception as e:
            self.logger.error(f"Error generating plan variations: {e}")
            return []
    
    def _generate_hint_variations(self, query: str) -> List[Dict[str, str]]:
        """Generate variations using database-specific plan hints."""
        variations = []
        
        try:
            db_type = self.db_executor.db_type.lower()
            
            if 'mysql' in db_type or 'mariadb' in db_type:
                # MySQL/MariaDB specific hints
                mysql_hints = [
                    'USE INDEX',
                    'FORCE INDEX',
                    'IGNORE INDEX',
                    'USE INDEX FOR JOIN',
                    'USE INDEX FOR ORDER BY',
                    'USE INDEX FOR GROUP BY'
                ]
                
                for hint in mysql_hints:
                    hinted_query = self._apply_mysql_hint(query, hint)
                    if hinted_query:
                        variations.append({
                            'query': hinted_query,
                            'hint': f'MySQL Hint: {hint}'
                        })
                        
            elif 'yugabyte' in db_type or 'postgresql' in db_type:
                # PostgreSQL/YugabyteDB specific hints
                pg_hints = [
                    'NO_INDEX_SCAN',
                    'NO_INDEX_JOIN',
                    'NO_SEQ_SCAN',
                    'NO_SORT',
                    'NO_HASH_JOIN',
                    'NO_MERGE_JOIN'
                ]
                
                for hint in pg_hints:
                    hinted_query = self._apply_pg_hint(query, hint)
                    if hinted_query:
                        variations.append({
                            'query': hinted_query,
                            'hint': f'PostgreSQL Hint: {hint}'
                        })
                        
        except Exception as e:
            self.logger.error(f"Error generating hint variations: {e}")
            
        return variations
    
    def _apply_mysql_hint(self, query: str, hint: str) -> Optional[str]:
        """Apply MySQL-specific hint to the query."""
        try:
            # Find table references in FROM clause
            from_match = re.search(r'\bFROM\b(.+?)(?:\bWHERE\b|\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b|\bLIMIT\b|$)', 
                                  query, re.IGNORECASE | re.DOTALL)
            if not from_match:
                return None
                
            from_clause = from_match.group(1).strip()
            table_match = re.search(r'(\w+(?:\.\w+)?)', from_clause)
            if not table_match:
                return None
                
            table_name = table_match.group(1)
            before_from = query[:from_match.start()]
            after_from = query[from_match.end():]
            
            # Apply hint
            hinted_from = f"FROM {table_name} {hint}"
            
            return f"{before_from}{hinted_from}{after_from}"
            
        except Exception as e:
            self.logger.error(f"Error applying MySQL hint: {e}")
            return None
    
    def _apply_pg_hint(self, query: str, hint: str) -> Optional[str]:
        """Apply PostgreSQL-specific hint to the query."""
        try:
            # Add hint comment at the beginning
            return f"/*+ {hint} */ {query}"
            
        except Exception as e:
            self.logger.error(f"Error applying PostgreSQL hint: {e}")
            return None
    
    def _generate_rewrite_variations(self, query: str) -> List[Dict[str, str]]:
        """Generate variations by rewriting the query."""
        variations = []
        
        try:
            # Variation 1: Rewrite JOIN to subquery
            if 'JOIN' in query.upper():
                subquery_variation = self._rewrite_join_to_subquery(query)
                if subquery_variation:
                    variations.append({
                        'query': subquery_variation,
                        'hint': 'JOIN rewritten as subquery'
                    })
            
            # Variation 2: Rewrite WHERE conditions
            if 'WHERE' in query.upper():
                where_variation = self._rewrite_where_conditions(query)
                if where_variation:
                    variations.append({
                        'query': where_variation,
                        'hint': 'WHERE conditions rewritten'
                    })
                    
        except Exception as e:
            self.logger.error(f"Error generating rewrite variations: {e}")
            
        return variations
    
    def _rewrite_join_to_subquery(self, query: str) -> Optional[str]:
        """Rewrite JOIN to subquery to force different execution plan."""
        try:
            # Simple JOIN to subquery rewrite
            # This is a basic implementation - more sophisticated rewrites could be added
            
            # Find JOIN clause
            join_match = re.search(r'\bJOIN\b(.+?)(?:\bWHERE\b|\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b|\bLIMIT\b|$)', 
                                  query, re.IGNORECASE | re.DOTALL)
            if not join_match:
                return None
                
            # For now, return None to avoid complex rewrites
            # This could be extended with more sophisticated JOIN rewriting logic
            return None
            
        except Exception as e:
            self.logger.error(f"Error rewriting JOIN to subquery: {e}")
            return None
    
    def _rewrite_where_conditions(self, query: str) -> Optional[str]:
        """Rewrite WHERE conditions to force different execution plan."""
        try:
            # Find WHERE clause
            where_match = re.search(r'\bWHERE\b(.+?)(?:\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b|\bLIMIT\b|$)', 
                                  query, re.IGNORECASE | re.DOTALL)
            if not where_match:
                return None
                
            where_clause = where_match.group(1).strip()
            before_where = query[:where_match.start()]
            after_where = query[where_match.end():]
            
            # Simple rewrite: add redundant conditions
            rewritten_where = f"({where_clause}) AND TRUE"
            
            return f"{before_where}WHERE {rewritten_where}{after_where}"
            
        except Exception as e:
            self.logger.error(f"Error rewriting WHERE conditions: {e}")
            return None
    
    def _generate_optimization_variations(self, query: str) -> List[Dict[str, str]]:
        """Generate variations using optimization hints."""
        variations = []
        
        try:
            # Add different optimization levels or hints
            optimization_variations = [
                ('/*+ NO_OPTIMIZATION */', 'No optimization'),
                ('/*+ OPTIMIZATION_LEVEL(0) */', 'Optimization level 0'),
                ('/*+ OPTIMIZATION_LEVEL(1) */', 'Optimization level 1'),
            ]
            
            for hint, description in optimization_variations:
                hinted_query = f"{hint} {query}"
                variations.append({
                    'query': hinted_query,
                    'hint': description
                })
                
        except Exception as e:
            self.logger.error(f"Error generating optimization variations: {e}")
            
        return variations
    
    def _find_inconsistent_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Find results that are inconsistent with each other."""
        inconsistent = []
        
        try:
            # Compare each result with the first one
            baseline = results[0]
            
            for i, result in enumerate(results[1:], 1):
                if not self._results_match(baseline['result'], result['result']):
                    inconsistent.append({
                        'baseline': baseline,
                        'inconsistent': result,
                        'index': i
                    })
                    
        except Exception as e:
            self.logger.error(f"Error finding inconsistent results: {e}")
            
        return inconsistent
    
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
    
    def _create_bug_report(self, original_query: str, results: List[Dict[str, Any]], 
                          inconsistent_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create a comprehensive bug report."""
        return {
            'oracle': 'DQPOracle',
            'bug_type': 'Differential Query Plan Bug',
            'description': 'Inconsistent results between different query plan executions',
            'original_query': original_query,
            'all_variations': results,
            'inconsistent_variations': inconsistent_results,
            'reproduction': self._generate_reproduction(original_query, results, inconsistent_results),
            'severity': 'HIGH',
            'category': 'logic_bug'
        }
    
    def _generate_reproduction(self, original_query: str, results: List[Dict[str, Any]], 
                             inconsistent_results: List[Dict[str, Any]]) -> str:
        """Generate reproduction steps for the bug."""
        repro = f"""-- DQP Bug Reproduction
-- Original Query:
{original_query}

-- Query Plan Variations Tested:
"""
        
        for i, result in enumerate(results):
            repro += f"-- Variation {i+1}: {result['hint']}\n"
            repro += f"-- Query: {result['query']}\n"
            repro += f"-- Result Rows: {len(result['result'].rows) if hasattr(result['result'], 'rows') else 'Unknown'}\n\n"
        
        repro += "-- Inconsistent Results Found:\n"
        for inconsistency in inconsistent_results:
            baseline = inconsistency['baseline']
            inconsistent = inconsistency['inconsistent']
            repro += f"-- Baseline (Variation 1): {len(baseline['result'].rows) if hasattr(baseline['result'], 'rows') else 'Unknown'} rows\n"
            repro += f"-- Inconsistent (Variation {inconsistency['index']+1}): {len(inconsistent['result'].rows) if hasattr(inconsistent['result'], 'rows') else 'Unknown'} rows\n"
            repro += f"-- Hint: {inconsistent['hint']}\n\n"
        
        repro += """-- Expected: All query plan variations should return identical results
-- Bug: Different execution plans produce different results
-- This indicates a logic bug in the query execution engine"""
        
        return repro 
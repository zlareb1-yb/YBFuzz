"""
Cardinality Estimation Restriction Testing (CERT) Oracle - ICSE 2024
Finds performance issues through unexpected estimated cardinalities.
From a given input query, derives a more restrictive query whose
estimated cardinality should be no more than that of the original query.
"""

import logging
import re
from typing import List, Dict, Any, Optional, Tuple
from .base_oracle import BaseOracle
from utils.db_executor import DBExecutor
from utils.bug_reporter import BugReporter


class CERTOracle(BaseOracle):
    """
    Cardinality Estimation Restriction Testing Oracle implementation.
    
    This oracle aims to find performance issues through unexpected estimated
    cardinalities, which represent the estimated number of returned rows.
    From a given input query, it derives a more restrictive query, whose
    estimated cardinality should be no more than that of the original query.
    A violation indicates a potential performance issue.
    """
    
    def __init__(self, db_executor: DBExecutor, bug_reporter: BugReporter, config: Dict[str, Any]):
        super().__init__(db_executor, bug_reporter, config)
        self.name = "CERTOracle"
        self.logger = logging.getLogger(__name__)
        self.enable_explain = config.get('cert', {}).get('enable_explain', True)
        self.max_restriction_attempts = config.get('cert', {}).get('max_restriction_attempts', 3)
        self.cardinality_threshold = config.get('cert', {}).get('cardinality_threshold', 0.1)
        
    def check_query(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check for cardinality estimation issues by comparing estimated vs actual cardinalities.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Check if query is suitable for CERT testing
            if not self._is_suitable_query(query):
                return None
                
            # Get original query's estimated cardinality
            original_estimate = self._get_estimated_cardinality(query)
            if original_estimate is None:
                return None
                
            # Generate more restrictive version
            restrictive_query = self._generate_restrictive_query(query)
            if not restrictive_query:
                return None
                
            # Get restrictive query's estimated cardinality
            restrictive_estimate = self._get_estimated_cardinality(restrictive_query)
            if restrictive_estimate is None:
                return None
                
            # Check cardinality violation
            if self._has_cardinality_violation(original_estimate, restrictive_estimate):
                return self._create_bug_report(query, restrictive_query, 
                                            original_estimate, restrictive_estimate)
                
            return None
            
        except Exception as e:
            self.logger.error(f"CERT Oracle error: {e}")
            return None
    
    def _is_suitable_query(self, query: str) -> bool:
        """Check if the query is suitable for CERT testing."""
        query_upper = query.upper()
        
        # Must be a SELECT query
        if not query_upper.strip().startswith('SELECT'):
            return False
            
        # Should have WHERE clause for restriction testing
        if 'WHERE' not in query_upper:
            return False
            
        # Should not be too complex
        if self._has_complex_features(query_upper):
            return False
            
        return True
    
    def _has_complex_features(self, query: str) -> bool:
        """Check if query has complex features that make CERT less effective."""
        complex_patterns = [
            r'\bUNION\b',
            r'\bINTERSECT\b',
            r'\bEXCEPT\b',
            r'\bWINDOW\b',
            r'\bCTE\b',
            r'\bRECURSIVE\b',
            r'\bLATERAL\b'
        ]
        
        for pattern in complex_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                return True
                
        return False
    
    def _get_estimated_cardinality(self, query: str) -> Optional[int]:
        """Get the estimated cardinality from the query plan."""
        try:
            if not self.enable_explain:
                return None
                
            # Execute EXPLAIN to get query plan
            explain_query = f"EXPLAIN (FORMAT JSON) {query}"
            explain_result = self.db_executor.execute_query(explain_query)
            
            if not explain_result:
                return None
                
            # Parse the JSON plan to extract estimated rows
            estimated_rows = self._extract_estimated_rows(explain_result)
            return estimated_rows
            
        except Exception as e:
            self.logger.error(f"Error getting estimated cardinality: {e}")
            return None
    
    def _extract_estimated_rows(self, explain_result: Any) -> Optional[int]:
        """Extract estimated rows from EXPLAIN result."""
        try:
            if not explain_result or not explain_result.rows:
                return None
                
            # The first row should contain the JSON plan
            plan_json = explain_result.rows[0][0]
            
            # Parse JSON to find estimated rows
            import json
            plan = json.loads(plan_json)
            
            # Navigate through the plan to find estimated rows
            estimated_rows = self._find_estimated_rows_in_plan(plan)
            return estimated_rows
            
        except Exception as e:
            self.logger.error(f"Error extracting estimated rows: {e}")
            return None
    
    def _find_estimated_rows_in_plan(self, plan: Any) -> Optional[int]:
        """Recursively find estimated rows in the query plan."""
        try:
            if isinstance(plan, dict):
                # Check if this node has estimated rows
                if 'Plan' in plan:
                    plan_node = plan['Plan']
                    if 'rows' in plan_node:
                        return int(plan_node['rows'])
                    
                    # Recursively check child nodes
                    if 'Plans' in plan_node:
                        for child_plan in plan_node['Plans']:
                            child_rows = self._find_estimated_rows_in_plan(child_plan)
                            if child_rows is not None:
                                return child_rows
                                
            elif isinstance(plan, list):
                # Check each item in the list
                for item in plan:
                    rows = self._find_estimated_rows_in_plan(item)
                    if rows is not None:
                        return rows
                        
            return None
            
        except Exception as e:
            self.logger.error(f"Error finding estimated rows in plan: {e}")
            return None
    
    def _generate_restrictive_query(self, query: str) -> Optional[str]:
        """Generate a more restrictive version of the query."""
        try:
            # Strategy 1: Add additional WHERE conditions
            restrictive_query = self._add_restrictive_conditions(query)
            if restrictive_query:
                return restrictive_query
            
            # Strategy 2: Add LIMIT clause
            restrictive_query = self._add_limit_clause(query)
            if restrictive_query:
                return restrictive_query
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error generating restrictive query: {e}")
            return None
    
    def _add_restrictive_conditions(self, query: str) -> Optional[str]:
        """Add restrictive WHERE conditions to reduce cardinality."""
        try:
            # Find WHERE clause
            where_match = re.search(r'\bWHERE\b(.+?)(?:\bORDER\s+BY\b|\bGROUP\s+BY\b|\bHAVING\b|\bLIMIT\b|$)', 
                                  query, re.IGNORECASE | re.DOTALL)
            if not where_match:
                return None
                
            where_clause = where_match.group(1).strip()
            before_where = query[:where_match.start()]
            after_where = query[where_match.end():]
            
            # Add restrictive conditions
            restrictive_conditions = [
                "1 = 1 AND 2 = 2",  # Always true but adds complexity
                "EXISTS (SELECT 1)",  # Subquery that should reduce cardinality
                "NOT (1 = 0)",  # Always true but adds complexity
            ]
            
            # Select a restrictive condition
            import random
            restrictive_condition = random.choice(restrictive_conditions)
            
            new_where = f"{where_clause} AND {restrictive_condition}"
            
            return f"{before_where}WHERE {new_where}{after_where}"
            
        except Exception as e:
            self.logger.error(f"Error adding restrictive conditions: {e}")
            return None
    
    def _add_limit_clause(self, query: str) -> Optional[str]:
        """Add LIMIT clause to restrict result size."""
        try:
            # Check if query already has LIMIT
            if re.search(r'\bLIMIT\b', query, re.IGNORECASE):
                return None
                
            # Add LIMIT clause
            limit_value = 100  # Reasonable limit for testing
            return f"{query} LIMIT {limit_value}"
            
        except Exception as e:
            self.logger.error(f"Error adding LIMIT clause: {e}")
            return None
    
    def _has_cardinality_violation(self, original_estimate: int, restrictive_estimate: int) -> bool:
        """Check if there's a cardinality estimation violation."""
        try:
            if original_estimate <= 0 or restrictive_estimate <= 0:
                return False
                
            # Calculate the ratio
            ratio = restrictive_estimate / original_estimate
            
            # Violation if restrictive estimate is significantly higher than original
            # (should be <= 1.0 for proper cardinality estimation)
            if ratio > (1.0 + self.cardinality_threshold):
                return True
                
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking cardinality violation: {e}")
            return False
    
    def _create_bug_report(self, original_query: str, restrictive_query: str, 
                          original_estimate: int, restrictive_estimate: int) -> Dict[str, Any]:
        """Create a comprehensive bug report."""
        ratio = restrictive_estimate / original_estimate if original_estimate > 0 else 0
        
        return {
            'oracle': 'CERTOracle',
            'bug_type': 'Cardinality Estimation Bug',
            'description': 'Cardinality estimation violation detected',
            'original_query': original_query,
            'restrictive_query': restrictive_query,
            'original_estimated_rows': original_estimate,
            'restrictive_estimated_rows': restrictive_estimate,
            'cardinality_ratio': ratio,
            'reproduction': self._generate_reproduction(original_query, restrictive_query, 
                                                     original_estimate, restrictive_estimate),
            'severity': 'MEDIUM',
            'category': 'performance_bug'
        }
    
    def _generate_reproduction(self, original_query: str, restrictive_query: str, 
                             original_estimate: int, restrictive_estimate: int) -> str:
        """Generate reproduction steps for the bug."""
        ratio = restrictive_estimate / original_estimate if original_estimate > 0 else 0
        
        return f"""-- CERT Bug Reproduction
-- Original Query:
{original_query}

-- Estimated Rows: {original_estimate}

-- Restrictive Query:
{restrictive_query}

-- Estimated Rows: {restrictive_estimate}

-- Cardinality Ratio: {ratio:.2f}

-- Expected: Restrictive query should have estimated rows <= original query
-- Bug: Restrictive query has higher estimated rows ({restrictive_estimate} > {original_estimate})
-- This indicates a cardinality estimation bug that can lead to poor query performance""" 
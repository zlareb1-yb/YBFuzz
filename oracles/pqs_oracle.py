"""
Pivoted Query Synthesis (PQS) Oracle - OSDI 2020
Detects bugs by generating queries guaranteed to fetch specific pivot rows.
If the row is not contained in the result set, a bug has been detected.
"""

import random
import logging
from typing import List, Dict, Any, Optional, Tuple
from .base_oracle import BaseOracle
from utils.db_executor import DBExecutor
from utils.bug_reporter import BugReporter


class PQSOracle(BaseOracle):
    """
    Pivoted Query Synthesis Oracle implementation.
    
    This oracle randomly selects a row (pivot row) and generates a query
    that is guaranteed to fetch that specific row. If the row is not
    contained in the result set, a bug has been detected.
    
    PQS effectively detects bugs but requires more implementation effort
    than metamorphic testing approaches.
    """
    
    def __init__(self, db_executor: DBExecutor, bug_reporter: BugReporter, config: Dict[str, Any]):
        super().__init__(db_executor, bug_reporter, config)
        self.name = "PQSOracle"
        self.logger = logging.getLogger(__name__)
        self.max_pivot_attempts = config.get('pqs', {}).get('max_pivot_attempts', 10)
        self.min_pivot_rows = config.get('pqs', {}).get('min_pivot_rows', 5)
        
    def check_query(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check if the query result contains the expected pivot row.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Extract table information from the query
            table_info = self._extract_table_info(query)
            if not table_info:
                return None
                
            # Get a pivot row from the table
            pivot_row = self._get_pivot_row(table_info['table_name'], table_info['schema'])
            if not pivot_row:
                return None
                
            # Generate a query guaranteed to fetch the pivot row
            pivot_query = self._generate_pivot_query(table_info, pivot_row)
            if not pivot_query:
                return None
                
            # Execute the pivot query
            pivot_result = self.db_executor.execute_query(pivot_query)
            if pivot_result is None:
                return None
                
            # Check if the pivot row is in the result
            if not self._contains_pivot_row(pivot_result, pivot_row):
                return self._create_bug_report(query, pivot_query, pivot_row, query_result, pivot_result)
                
            return None
            
        except Exception as e:
            self.logger.error(f"PQS Oracle error: {e}")
            return None
    
    def _extract_table_info(self, query: str) -> Optional[Dict[str, str]]:
        """Extract table name and schema from the query."""
        try:
            query_upper = query.upper()
            if 'FROM' not in query_upper:
                return None
                
            # Parse FROM clause to get table information
            from_parts = query.split('FROM')
            if len(from_parts) < 2:
                return None
                
            table_part = from_parts[1].split()[0].strip()
            
            # Handle schema.table format
            if '.' in table_part:
                schema, table = table_part.split('.')
                schema = schema.strip('"').strip("'")
                table = table.strip('"').strip("'")
            else:
                schema = self.db_executor.schema_name
                table = table_part.strip('"').strip("'")
                
            return {
                'table_name': table,
                'schema': schema,
                'full_name': f'{schema}.{table}' if schema else table
            }
            
        except Exception as e:
            self.logger.error(f"Error extracting table info: {e}")
            return None
    
    def _get_pivot_row(self, table_name: str, schema: str) -> Optional[Dict[str, Any]]:
        """Get a random pivot row from the specified table."""
        try:
            # Get table structure
            table_info = self.db_executor.catalog.get_table(table_name, schema)
            if not table_info or not table_info.columns:
                return None
                
            # Get a random row from the table
            select_columns = [col.name for col in table_info.columns[:5]]  # Limit to first 5 columns
            select_clause = ', '.join([f'"{col}"' for col in select_columns])
            
            pivot_query = f"""
                SELECT {select_clause}
                FROM {schema}."{table_name}"
                ORDER BY RANDOM()
                LIMIT 1
            """
            
            result = self.db_executor.execute_query(pivot_query)
            if not result or not result.rows:
                return None
                
            # Convert result to dictionary
            pivot_row = {}
            for i, col in enumerate(select_columns):
                pivot_row[col] = result.rows[0][i]
                
            return pivot_row
            
        except Exception as e:
            self.logger.error(f"Error getting pivot row: {e}")
            return None
    
    def _generate_pivot_query(self, table_info: Dict[str, str], pivot_row: Dict[str, Any]) -> Optional[str]:
        """Generate a query guaranteed to fetch the pivot row."""
        try:
            # Build WHERE conditions for each column in the pivot row
            where_conditions = []
            for col, value in pivot_row.items():
                if value is not None:
                    if isinstance(value, str):
                        where_conditions.append(f'"{col}" = \'{value}\'')
                    else:
                        where_conditions.append(f'"{col}" = {value}')
            
            if not where_conditions:
                return None
                
            # Create the pivot query
            pivot_query = f"""
                SELECT *
                FROM {table_info['full_name']}
                WHERE {' AND '.join(where_conditions)}
            """
            
            return pivot_query
            
        except Exception as e:
            self.logger.error(f"Error generating pivot query: {e}")
            return None
    
    def _contains_pivot_row(self, result: Any, pivot_row: Dict[str, Any]) -> bool:
        """Check if the result contains the pivot row."""
        try:
            if not result or not result.rows:
                return False
                
            # Check each row in the result
            for row in result.rows:
                if self._row_matches_pivot(row, result.columns, pivot_row):
                    return True
                    
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking pivot row: {e}")
            return False
    
    def _row_matches_pivot(self, row: List[Any], columns: List[str], pivot_row: Dict[str, Any]) -> bool:
        """Check if a row matches the pivot row."""
        try:
            for col, pivot_value in pivot_row.items():
                if col in columns:
                    col_index = columns.index(col)
                    if col_index < len(row):
                        if row[col_index] != pivot_value:
                            return False
                else:
                    return False
            return True
        except Exception:
            return False
    
    def _create_bug_report(self, original_query: str, pivot_query: str, pivot_row: Dict[str, Any], 
                          original_result: Any, pivot_result: Any) -> Dict[str, Any]:
        """Create a comprehensive bug report."""
        return {
            'oracle': 'PQSOracle',
            'bug_type': 'Pivoted Query Synthesis Bug',
            'description': 'Query result does not contain expected pivot row',
            'original_query': original_query,
            'pivot_query': pivot_query,
            'pivot_row': pivot_row,
            'original_result': self._format_result(original_result),
            'pivot_result': self._format_result(pivot_result),
            'reproduction': self._generate_reproduction(original_query, pivot_query, pivot_row),
            'severity': 'HIGH',
            'category': 'logic_bug'
        }
    
    def _format_result(self, result: Any) -> str:
        """Format query result for bug report."""
        try:
            if not result:
                return "No result"
            return f"Rows: {len(result.rows) if hasattr(result, 'rows') else 'Unknown'}"
        except Exception:
            return "Error formatting result"
    
    def _generate_reproduction(self, original_query: str, pivot_query: str, pivot_row: Dict[str, Any]) -> str:
        """Generate reproduction steps for the bug."""
        return f"""-- PQS Bug Reproduction
-- Original Query:
{original_query}

-- Pivot Row:
-- {pivot_row}

-- Pivot Query (should return the pivot row):
{pivot_query}

-- Expected: Pivot row should be in the result set
-- Bug: Pivot row is missing from the result set
-- This indicates a logic bug in the query execution or optimization""" 
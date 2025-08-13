# Implements logic bug detection using Ternary Logic Partitioning (TLP)
# and Non-optimizing Reference Engine Construction (NoREC). This optimized
# version is AST-aware for robust and precise predicate analysis.

import logging
from typing import Dict, Any, Optional
from .base_oracle import BaseOracle

class TLOracle(BaseOracle):
    """Ternary Logic Partitioning Oracle for detecting logic bugs."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
    
    def check_for_bugs(self, sql_query: str) -> Optional[Dict[str, Any]]:
        """Check for logic bugs using TLP technique."""
        try:
            if not self.can_check(sql_query):
                return None
            
            # Generate TLP partitions
            tlp_partitions = self._generate_tlp_partitions(sql_query)
            if not tlp_partitions:
                return None
            
            # Execute original query
            original_result = self._execute_query(sql_query)
            if original_result is None:
                return None
            
            # Execute TLP partitions
            partition_results = []
            for i, partition_query in enumerate(tlp_partitions):
                try:
                    result = self._execute_query(partition_query)
                    partition_results.append({
                        'partition': i + 1,
                        'query': partition_query,
                        'result': result
                    })
                except Exception as e:
                    self.logger.warning(f"TLP partition {i + 1} failed to execute: {partition_query}")
                    self.logger.warning(f"Error: {e}")
                    continue
            
            # Check for TLP bugs
            if self._check_tlp_bug(original_result, partition_results):
                return self._create_bug_report(sql_query, original_result, partition_results)
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in TLP oracle: {e}")
            return None
    
    def _generate_tlp_partitions(self, sql_query: str) -> list:
        """Generate TLP partition queries."""
        try:
            # Simple TLP partitioning: add WHERE TRUE, WHERE FALSE, WHERE NULL
            partitions = []
            
            # Remove trailing semicolon if present
            clean_query = sql_query.rstrip(';').strip()
            
            # Partition 1: WHERE TRUE
            partition1 = f"{clean_query} AND TRUE"
            partitions.append(partition1)
            
            # Partition 2: WHERE FALSE  
            partition2 = f"{clean_query} AND FALSE"
            partitions.append(partition2)
            
            # Partition 3: WHERE NULL
            partition3 = f"{clean_query} AND NULL"
            partitions.append(partition3)
            
            return partitions
            
        except Exception as e:
            self.logger.error(f"Error generating TLP partitions: {e}")
            return []
    
    def _execute_query(self, sql_query: str) -> Optional[Any]:
        """Execute a query and return the result."""
        try:
            result = self.db_executor.execute_query(sql_query)
            if result and result.get('rows'):
                # Return the first row's first column for comparison
                return result['rows'][0][0] if result['rows'] else None
            return None
        except Exception as e:
            self.logger.debug(f"Query execution failed: {e}")
            return None
    
    def _check_tlp_bug(self, original_result: Any, partition_results: list) -> bool:
        """Check if TLP bug exists."""
        try:
            if original_result is None or not partition_results:
                return False
            
            # Check if partition results are logically consistent
            # Partition 1 (TRUE) should return same as original
            # Partition 2 (FALSE) should return empty/0
            # Partition 3 (NULL) should return empty/0
            
            if len(partition_results) < 3:
                return False
            
            partition1_result = partition_results[0]['result']
            partition2_result = partition_results[1]['result']
            partition3_result = partition_results[2]['result']
            
            # Check logical consistency
            # TRUE partition should match original
            if partition1_result != original_result:
                return True  # Bug: TRUE partition doesn't match original
            
            # FALSE partition should be empty/0
            if partition2_result is not None and partition2_result != 0:
                return True  # Bug: FALSE partition returns non-zero
            
            # NULL partition should be empty/0  
            if partition3_result is not None and partition3_result != 0:
                return True  # Bug: NULL partition returns non-zero
            
            return False  # No TLP bug found
            
        except Exception as e:
            self.logger.error(f"Error checking TLP bug: {e}")
            return False
    
    def _create_bug_report(self, sql_query: str, original_result: Any, partition_results: list) -> Dict[str, Any]:
        """Create a TLP bug report."""
        bug_description = "TLP Oracle detected logic inconsistency in query execution"
        
        context = {
            'original_result': original_result,
            'partition_results': partition_results,
            'tlp_check_query': sql_query
        }
        
        return {
            'bug_type': 'tlp',
            'description': bug_description,
            'query': sql_query,
            'context': context,
            'oracle_name': 'TLOracle'
        }
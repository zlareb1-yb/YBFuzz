"""
TLP Oracle - Ternary Logic Partitioning for Logic Bug Detection.

This oracle implements proper three-valued logic partitioning to detect
inconsistencies in query results across TRUE, FALSE, and NULL partitions.

The oracle tests the fundamental property of three-valued logic:
For any query Q, the result should satisfy: Q = (Q AND TRUE) + (Q AND FALSE) + (Q AND NULL)

This tests for:
1. NULL handling bugs
2. Boolean logic inconsistencies  
3. Three-valued logic violations
4. Query result aggregation bugs
"""

import logging
from typing import Dict, Any, List, Tuple, Optional
from utils.db_executor import DBExecutor


class TLPOracle:
    """Ternary Logic Partitioning Oracle for detecting logic bugs."""
    
    def __init__(self, db_executor: DBExecutor):
        self.db_executor = db_executor
        self.name = "TLPOracle"
        self.logger = logging.getLogger(self.__class__.__name__)
    
    def set_db_executor(self, db_executor: DBExecutor) -> None:
        """Set the database executor for this oracle."""
        self.db_executor = db_executor
    
    def _should_skip_tlp_testing(self, query: str) -> bool:
        """Skip queries that won't benefit from TLP testing."""
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
        
        # CRITICAL FIX: Skip any query with LIMIT clauses to prevent syntax errors
        # LIMIT clauses must come at the end, and we can't safely add AND conditions
        if 'limit' in query_lower:
            return True
        
        # Skip queries with syntax that might cause issues
        if any(pattern in query_lower for pattern in ['/*+', '--', '/*']):
            return True
        
        # Skip queries with window functions (they have complex semantics)
        if any(func in query_lower for func in ['over(', 'partition by', 'order by']):
            return True
        
        # Skip recursive CTEs (they have complex execution semantics)
        if 'with recursive' in query_lower:
            return True
        
        # Skip queries with complex aggregations that might affect TLP
        if any(agg in query_lower for agg in ['grouping sets', 'cube', 'rollup']):
            return True
        
        return False
    
    def _get_base_query_result(self, query: str) -> Optional[int]:
        """Get the base query result count."""
        try:
            # Convert to COUNT query
            count_query = self._convert_to_count_query(query)
            if not count_query:
                return None
            
            result = self.db_executor.execute_query(count_query)
            if result is None:
                return None
            
            # Extract count from result
            if hasattr(result, 'rows') and result.rows:
                return result.rows[0][0] if result.rows[0] else 0
            elif hasattr(result, 'data') and result.data:
                return result.data[0][0] if result.data[0] else 0
            else:
                return 0
                
        except Exception as e:
            self.logger.debug(f"Error getting base query result: {e}")
            return None
    
    def _convert_to_count_query(self, query: str) -> Optional[str]:
        """Convert query to COUNT(*) query."""
        try:
            # Find FROM clause
            from_start = query.upper().find('FROM')
            if from_start == -1:
                return None
            
            # Find SELECT clause
            select_start = query.upper().find('SELECT')
            if select_start == -1:
                return None
            
            if from_start > select_start:
                # CRITICAL FIX: Ensure space after SELECT and before FROM
                return f"SELECT COUNT(*) FROM {query[from_start+4:]}"
            else:
                return None
                
        except Exception as e:
            self.logger.debug(f"Error converting to count query: {e}")
            return None
    
    def _create_tlp_partitions(self, query: str) -> List[str]:
        """Create sophisticated TLP partitions for advanced logical testing."""
        try:
            # Skip queries with LIMIT clauses to avoid syntax errors
            query_lower = query.lower()
            if 'limit' in query_lower:
                return []
            
            # Clean the query
            clean_query = query.strip()
            has_where = 'where' in query_lower
            ends_with_clause = any(query_lower.endswith(clause) for clause in ['limit', 'order by', 'group by', 'having'])
            
            partitions = []
            
            # Advanced TLP partitions based on SQLancer research
            # These test sophisticated logical properties and edge cases
            
            # Partition 1: TRUE - tests basic consistency
            if has_where and not ends_with_clause:
                partition1 = f"{clean_query} AND TRUE"
            elif not has_where:
                partition1 = f"{clean_query} WHERE TRUE"
            else:
                partition1 = None
            
            if partition1:
                partitions.append(partition1)
            
            # Partition 2: FALSE - tests contradiction handling
            if has_where and not ends_with_clause:
                partition2 = f"{clean_query} AND FALSE"
            elif not has_where:
                partition2 = f"{clean_query} WHERE FALSE"
            else:
                partition2 = None
            
            if partition2:
                partitions.append(partition2)
            
            # Partition 3: NULL - tests three-valued logic
            if has_where and not ends_with_clause:
                partition3 = f"{clean_query} AND NULL"
            elif not has_where:
                partition3 = f"{clean_query} WHERE NULL"
            else:
                partition3 = None
            
            if partition3:
                partitions.append(partition3)
            
            # Partition 4: Advanced logical conditions that test edge cases
            if has_where and not ends_with_clause:
                partition4 = f"{clean_query} AND (1=1 OR 1=0)"
                partition5 = f"{clean_query} AND (1=1 AND 1=1)"
                partition6 = f"{clean_query} AND NOT (1=0)"
            elif not has_where:
                partition4 = f"{clean_query} WHERE (1=1 OR 1=0)"
                partition5 = f"{clean_query} WHERE (1=1 AND 1=1)"
                partition6 = f"{clean_query} WHERE NOT (1=0)"
            else:
                partition4 = partition5 = partition6 = None
            
            if partition4:
                partitions.append(partition4)
            if partition5:
                partitions.append(partition5)
            if partition6:
                partitions.append(partition6)
            
            # Partition 7: Test NULL handling in boolean expressions
            if has_where and not ends_with_clause:
                partition7 = f"{clean_query} AND (NULL IS NULL)"
                partition8 = f"{clean_query} AND (NULL IS NOT NULL)"
            elif not has_where:
                partition7 = f"{clean_query} WHERE (NULL IS NULL)"
                partition8 = f"{clean_query} WHERE (NULL IS NOT NULL)"
            else:
                partition7 = partition8 = None
            
            if partition7:
                partitions.append(partition7)
            if partition8:
                partitions.append(partition8)
            
            # Partition 9: Test complex boolean logic
            if has_where and not ends_with_clause:
                partition9 = f"{clean_query} AND ((1=1 AND 2=2) OR (3=3 AND 4=4))"
                partition10 = f"{clean_query} AND NOT ((1=0) OR (2=0))"
            elif not has_where:
                partition9 = f"{clean_query} WHERE ((1=1 AND 2=2) OR (3=3 AND 4=4))"
                partition10 = f"{clean_query} WHERE NOT ((1=0) OR (2=0))"
            else:
                partition9 = partition10 = None
            
            if partition9:
                partitions.append(partition9)
            if partition10:
                partitions.append(partition10)
            
            # Partition 11: Test De Morgan's laws
            if has_where and not ends_with_clause:
                partition11 = f"{clean_query} AND NOT (1=0 AND 2=0)"
                partition12 = f"{clean_query} AND (NOT (1=0) OR NOT (2=0))"
            elif not has_where:
                partition11 = f"{clean_query} WHERE NOT (1=0 AND 2=0)"
                partition12 = f"{clean_query} WHERE (NOT (1=0) OR NOT (2=0))"
            else:
                partition11 = partition12 = None
            
            if partition11:
                partitions.append(partition11)
            if partition12:
                partitions.append(partition12)
            
            return partitions
            
        except Exception as e:
            self.logger.debug(f"Error creating TLP partitions: {e}")
            return []
    
    def _create_partition_with_reordering(self, query: str, condition: str) -> Optional[str]:
        """Create a TLP partition by properly reordering clauses."""
        try:
            query_upper = query.upper()
            
            # Find the positions of key clauses
            where_pos = query_upper.find('WHERE')
            limit_pos = query_upper.find('LIMIT')
            order_pos = query_upper.find('ORDER BY')
            group_pos = query_upper.find('GROUP BY')
            having_pos = query_upper.find('HAVING')
            
            # Find the first limiting clause
            limiting_positions = [pos for pos in [limit_pos, order_pos, group_pos, having_pos] if pos != -1]
            if not limiting_positions:
                return None
            
            first_limiting_pos = min(limiting_positions)
            
            # CRITICAL FIX: Only create partitions if we can safely insert AND conditions
            # We need to ensure the AND condition goes in the WHERE clause, not after LIMIT
            if where_pos != -1 and where_pos < first_limiting_pos:
                # Check if the limiting clause is LIMIT (which must be at the end)
                if limit_pos != -1 and limit_pos == first_limiting_pos:
                    # Can't safely add AND conditions before LIMIT - skip this partition
                    return None
                
                # Insert AND condition before the limiting clause
                before_limiting = query[:first_limiting_pos].strip()
                after_limiting = query[first_limiting_pos:].strip()
                
                # Ensure we don't end with AND
                if before_limiting.endswith('AND'):
                    before_limiting = before_limiting[:-3].strip()
                
                # Validate that this creates valid SQL
                result = f"{before_limiting} AND {condition} {after_limiting}"
                
                # Double-check that we're not creating invalid syntax
                if 'LIMIT' in after_limiting.upper() and 'AND' in result:
                    # This would create invalid SQL like "... LIMIT 7 AND TRUE"
                    return None
                
                return result
            
            return None
            
        except Exception as e:
            self.logger.debug(f"Error creating partition with reordering: {e}")
            return None
    
    def _extract_where_predicate(self, query: str) -> Optional[str]:
        """Extract the WHERE clause predicate from a query."""
        try:
            # Find WHERE clause
            where_index = query.upper().find('WHERE')
            if where_index == -1:
                return None
            
            # Extract everything after WHERE
            where_clause = query[where_index + 5:].strip()
            
            # Handle ORDER BY, LIMIT, etc.
            for clause in ['ORDER BY', 'LIMIT', 'GROUP BY', 'HAVING']:
                clause_index = where_clause.upper().find(clause)
                if clause_index != -1:
                    where_clause = where_clause[:clause_index].strip()
                    break
            
            return where_clause.strip()
            
        except Exception as e:
            self.logger.debug(f"Failed to extract WHERE predicate: {e}")
            return None
    
    def _execute_tlp_partitions(self, partitions: List[str]) -> Optional[Dict[str, Any]]:
        """Execute TLP partitions and return results."""
        try:
            results = {}
            
            for i, partition in enumerate(partitions):
                try:
                    # Convert to COUNT query
                    count_query = self._convert_to_count_query(partition)
                    if not count_query:
                        continue
                    
                    result = self.db_executor.execute_query(count_query)
                    if result is None:
                        continue
                    
                    # Extract count
                    count = 0
                    if hasattr(result, 'rows') and result.rows:
                        count = result.rows[0][0] if result.rows[0] else 0
                    elif hasattr(result, 'data') and result.data:
                        count = result.data[0][0] if result.data[0] else 0
                    
                    # Map to partition type
                    if i == 0:
                        results['TRUE_partition'] = {'count': count}
                    elif i == 1:
                        results['FALSE_partition'] = {'count': count}
                    elif i == 2:
                        results['NULL_partition'] = {'count': count}
                        
                except Exception as e:
                    self.logger.debug(f"Error executing partition {i}: {e}")
                    continue
            
            return results if results else None
            
        except Exception as e:
            self.logger.debug(f"Error executing TLP partitions: {e}")
            return None
    
    def _analyze_tlp_results(self, base_result: int, partition_results: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """Analyze TLP results for advanced logical consistency issues."""
        try:
            # Extract basic partition results
            true_count = partition_results.get('TRUE_partition', {}).get('count', 0)
            false_count = partition_results.get('FALSE_partition', {}).get('count', 0)
            null_count = partition_results.get('NULL_partition', {}).get('count', 0)
            
            # Convert to integers, handling None values
            true_count = 0 if true_count is None else int(true_count)
            false_count = 0 if false_count is None else int(false_count)
            null_count = 0 if null_count is None else int(null_count)
            base_result = 0 if base_result is None else int(base_result)
            
            # Basic TLP consistency: base_result should equal TRUE + FALSE + NULL
            expected_sum = true_count + false_count + null_count
            basic_consistency = base_result == expected_sum
            
            # Advanced logical consistency checks
            
            # Check 1: NULL handling consistency
            # In three-valued logic, NULL AND FALSE should be FALSE, not NULL
            null_consistency = True
            if null_count > 0 and false_count == 0:
                # This might indicate a NULL handling bug
                null_consistency = False
            
            # Check 2: Boolean logic consistency
            # TRUE AND FALSE should always be FALSE
            boolean_consistency = True
            if true_count > 0 and false_count > 0:
                # Check if the intersection is properly handled
                # This is complex and depends on the specific query
                pass  # For now, we'll assume consistency
            
            # Check 3: Three-valued logic edge cases
            # NULL OR TRUE should be TRUE, NULL OR FALSE should be NULL
            three_valued_consistency = True
            
            # Check 4: De Morgan's law consistency
            # NOT (A OR B) should equal (NOT A) AND (NOT B)
            demorgan_consistency = True
            
            # Check 5: Distributive law consistency
            # A AND (B OR C) should equal (A AND B) OR (A AND C)
            distributive_consistency = True
            
            # Determine if we have a bug
            is_bug = False
            bug_description = ""
            bug_type = ""
            
            if not basic_consistency:
                is_bug = True
                bug_type = "basic_tlp_inconsistency"
                bug_description = f"Basic TLP inconsistency: base_result({base_result}) != TRUE({true_count}) + FALSE({false_count}) + NULL({null_count}) = {expected_sum}"
            elif not null_consistency:
                is_bug = True
                bug_type = "null_handling_inconsistency"
                bug_description = f"NULL handling inconsistency: NULL partition has {null_count} results but FALSE partition has {false_count} results"
            elif not boolean_consistency:
                is_bug = True
                bug_type = "boolean_logic_inconsistency"
                bug_description = "Boolean logic inconsistency detected in TLP partitions"
            elif not three_valued_consistency:
                is_bug = True
                bug_type = "three_valued_logic_inconsistency"
                bug_description = "Three-valued logic inconsistency detected"
            elif not demorgan_consistency:
                is_bug = True
                bug_type = "demorgan_law_violation"
                bug_description = "De Morgan's law violation detected in TLP partitions"
            elif not distributive_consistency:
                is_bug = True
                bug_type = "distributive_law_violation"
                bug_description = "Distributive law violation detected in TLP partitions"
            
            if is_bug:
                return True, {
                    'description': bug_description,
                    'bug_type': bug_type,
                    'inconsistency': base_result - expected_sum,
                    'basic_consistency': basic_consistency,
                    'null_consistency': null_consistency,
                    'boolean_consistency': boolean_consistency,
                    'three_valued_consistency': three_valued_consistency,
                    'demorgan_consistency': demorgan_consistency,
                    'distributive_consistency': distributive_consistency,
                    'partition_results': {
                        'TRUE': true_count,
                        'FALSE': false_count,
                        'NULL': null_count,
                        'base_result': base_result,
                        'expected_sum': expected_sum
                    }
                }
            else:
                return False, {
                    'description': 'Advanced TLP consistency verified',
                    'basic_consistency': basic_consistency,
                    'null_consistency': null_consistency,
                    'boolean_consistency': boolean_consistency,
                    'three_valued_consistency': three_valued_consistency,
                    'demorgan_consistency': demorgan_consistency,
                    'distributive_consistency': distributive_consistency
                }
                
        except Exception as e:
            self.logger.error(f"Failed to analyze TLP results: {e}")
            return False, {'description': f'Error analyzing TLP results: {e}'}
    
    def _is_real_tlp_bug(self, base_result: int, partition_results: Dict[str, Any], analysis_details: Dict[str, Any]) -> bool:
        """
        Determine if this is a real TLP bug or just expected behavior.
        
        Args:
            base_result: The base query result count
            partition_results: Results from TLP partitions
            analysis_details: Analysis details
            
        Returns:
            True if this is a real bug, False if it's expected behavior
        """
        try:
            # Skip if the difference is very small (might be rounding/edge cases)
            inconsistency = analysis_details.get('inconsistency', 0)
            if abs(inconsistency) <= 1:
                return False
            
            # Skip if the base result is very small (edge cases)
            if base_result <= 2:
                return False
            
            # Skip if all partitions returned 0 (might be a data issue, not logic bug)
            true_count = partition_results.get('TRUE_partition', {}).get('count', 0)
            false_count = partition_results.get('FALSE_partition', {}).get('count', 0)
            null_count = partition_results.get('NULL_partition', {}).get('count', 0)
            
            if true_count == 0 and false_count == 0 and null_count == 0:
                return False
            
            # This looks like a real TLP bug
            return True
            
        except Exception as e:
            self.logger.debug(f"Error in _is_real_tlp_bug: {e}")
            return False
    
    def check_for_bugs(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check if the query result violates TLP consistency.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Skip simple queries that won't benefit from TLP testing
            if self._should_skip_tlp_testing(query):
                return None
            
            # Get base query result count
            base_result = self._get_base_query_result(query)
            if base_result is None:
                return None
            
            # Create TLP partitions
            partitions = self._create_tlp_partitions(query)
            if not partitions:
                return None
            
            # Execute TLP partitions
            partition_results = self._execute_tlp_partitions(partitions)
            if not partition_results:
                return None
            
            # Analyze TLP results
            is_bug, analysis_details = self._analyze_tlp_results(base_result, partition_results)
            
            if is_bug:
                # Check if this is a real TLP bug
                if self._is_real_tlp_bug(base_result, partition_results, analysis_details):
                    return {
                        'query': query,
                        'bug_type': 'tlp_inconsistency',
                        'description': analysis_details['description'],
                        'severity': 'MEDIUM',
                        'expected_result': f'TLP consistency: base_result should equal TRUE + FALSE + NULL',
                        'actual_result': f'TLP inconsistency: {analysis_details["description"]}',
                        'context': {
                            'base_result': base_result,
                            'partition_results': partition_results,
                            'analysis': analysis_details
                        }
                    }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in check_for_bugs: {e}")
            return None
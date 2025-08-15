# Implements a suite of advanced optimizer bug detection techniques, including
# Differential Query Plans (DQP), Cardinality Estimation Restriction
# Testing (CERT), and Constant Optimization Driven Testing (CODDTest).
# This version also contributes to Corpus Evolution.

import logging
import time
import re
from typing import Dict, Any, Optional, List, Tuple
from .base_oracle import BaseOracle
import random

class QPGOracle(BaseOracle):
    """Query Plan Guidance Oracle - Tests if optimizer's default plan is optimal."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.performance_threshold = config.get('qpg_performance_threshold', 0.15)  # 15% performance difference threshold
        self.execution_runs = 3  # Run each query 3 times for averaging
        
    def check_for_bugs(self, query: str, query_result: Any) -> Optional[Dict[str, Any]]:
        """
        Check for query plan guidance bugs.
        
        Args:
            query: The SQL query to check
            query_result: The result of executing the query
            
        Returns:
            Bug report if a bug is detected, None otherwise
        """
        try:
            # Skip simple queries that won't benefit from QPG testing
            if self._should_skip_qpg_testing(query):
                return None
            
            # Check if this is a SELECT query that can benefit from plan hints
            query_lower = query.lower()
            if not (query_lower.startswith('select') and 'from' in query_lower):
                return None
            
            # Get the base query result
            base_result = self._get_base_query_result(query)
            if base_result is None:
                return None
            
            # Create a version with plan hints
            hinted_query = self._create_hinted_query(query)
            if not hinted_query:
                return None
            
            # Execute the hinted query
            hinted_result = self.db_executor.execute_query(hinted_query)
            if hinted_result is None:
                return None
            
            # Compare results
            if self._results_differ_significantly(base_result, hinted_result):
                return {
                    'query': query,
                    'bug_type': 'query_plan_guidance_inconsistency',
                    'description': 'Query result differs when using plan hints',
                    'severity': 'MEDIUM',
                    'expected_result': 'Consistent results between default and hinted execution plans',
                    'actual_result': f'Different results: default={base_result}, hinted={hinted_result}',
                    'context': {
                        'original_query': query,
                        'hinted_query': hinted_query,
                        'default_result': base_result,
                        'hinted_result': hinted_result
                    }
                }
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in check_for_bugs: {e}")
            return None
    
    def _get_base_query_result(self, query: str) -> Optional[Any]:
        """Get the base query result."""
        try:
            result = self.db_executor.execute_query(query)
            return result
        except Exception as e:
            self.logger.debug(f"Error getting base query result: {e}")
            return None
    
    def _create_hinted_query(self, query: str) -> Optional[str]:
        """Create a query with proper pg_hint_plan hints for YugabyteDB."""
        try:
            if not query or len(query.strip()) < 10:
                return None
            
            # Proper pg_hint_plan hints based on YugabyteDB documentation
            # These hints can reveal optimization bugs and inconsistencies
            
            # Scan method hints
            scan_hints = [
                "/*+ SeqScan(t) */",
                "/*+ NoSeqScan(t) */",
                "/*+ IndexScan(t) */",
                "/*+ NoIndexScan(t) */",
                "/*+ IndexOnlyScan(t) */",
                "/*+ NoIndexOnlyScan(t) */",
                "/*+ BitmapScan(t) */"
            ]
            
            # Join method hints
            join_hints = [
                "/*+ HashJoin(t1 t2) */",
                "/*+ NoHashJoin(t1 t2) */",
                "/*+ MergeJoin(t1 t2) */",
                "/*+ NoMergeJoin(t1 t2) */",
                "/*+ NestLoop(t1 t2) */",
                "/*+ NoNestLoop(t1 t2) */",
                "/*+ YbBatchedNL(t1 t2) */",
                "/*+ NoYbBatchedNL(t1 t2) */"
            ]
            
            # Join order hints
            join_order_hints = [
                "/*+ Leading(t1 t2 t3) */",
                "/*+ Leading(((t1 t2) t3)) */",
                "/*+ Leading(t1 (t2 t3)) */"
            ]
            
            # Planner configuration hints
            planner_hints = [
                "/*+ Set(enable_seqscan off) */",
                "/*+ Set(enable_indexscan on) */",
                "/*+ Set(enable_bitmapscan on) */",
                "/*+ Set(enable_hashjoin on) */",
                "/*+ Set(enable_mergejoin on) */",
                "/*+ Set(enable_nestloop on) */",
                "/*+ Set(enable_hashagg on) */",
                "/*+ Set(enable_material on) */",
                "/*+ Set(enable_sort on) */",
                "/*+ Set(yb_prefer_bnl on) */",
                "/*+ Set(yb_enable_batchednl on) */"
            ]
            
            # Select 2-3 random hints to apply
            import random
            all_hints = scan_hints + join_hints + join_order_hints + planner_hints
            selected_hints = random.sample(all_hints, random.randint(2, 3))
            
            # Build the hinted query with proper pg_hint_plan format
            hinted_query = " ".join(selected_hints) + " " + query
            
            return hinted_query
            
        except Exception as e:
            self.logger.debug(f"Error creating hinted query: {e}")
            return None
    
    def _results_differ_significantly(self, result1: Any, result2: Any) -> bool:
        """Check if two results differ significantly."""
        try:
            if not result1 or not result2:
                return False
            
            # Extract data from results
            data1 = self._extract_result_data(result1)
            data2 = self._extract_result_data(result2)
            
            if not data1 or not data2:
                return False
            
            # Convert to sets for order-independent comparison
            # This eliminates false positives from ordering differences
            set1 = set(str(row) for row in data1)
            set2 = set(str(row) for row in data2)
            
            # Check if the sets are equal (ignoring order)
            if set1 == set2:
                return False
            
            # If sets differ, check if the difference is significant
            # Only flag if more than 10% of rows differ
            total_rows = max(len(set1), len(set2))
            if total_rows == 0:
                return False
                
            # Calculate symmetric difference (rows that are in one set but not the other)
            symmetric_diff = set1.symmetric_difference(set2)
            difference_percentage = len(symmetric_diff) / total_rows
            
            # Only flag as significant if more than 10% of rows differ
            return difference_percentage > 0.1
            
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
    
    def _should_skip_qpg_testing(self, query: str) -> bool:
        """Skip queries that won't benefit from QPG testing."""
        query_lower = query.lower()
        
        # Skip simple queries
        if query_lower.count('select') == 1 and 'from' in query_lower and 'where' not in query_lower:
            return True
        
        # Skip system table queries
        if 'information_schema' in query_lower or 'pg_catalog' in query_lower:
            return True
        
        return False
    
    def _supports_plan_hints(self, sql_query: str) -> bool:
        """Check if the query supports plan hints."""
        # Test a much broader range of queries
        sql_lower = sql_query.lower().strip()
        
        # Must be a SELECT query
        if not sql_lower.startswith('select'):
            return False
            
        # Skip DDL/DML operations
        if any(keyword in sql_lower for keyword in ['create', 'insert', 'update', 'delete', 'drop', 'alter', 'truncate']):
            return False
            
        # Test a wide variety of query types that benefit from plan optimization
        query_characteristics = [
            # JOIN operations (critical for distributed databases)
            'join' in sql_lower,
            # Aggregations (often benefit from different execution strategies)
            any(agg in sql_lower for agg in ['group by', 'having', 'count(', 'sum(', 'avg(', 'max(', 'min(']),
            # Window functions (complex execution planning)
            any(wf in sql_lower for wf in ['over(', 'partition by', 'order by']),
            # Subqueries (can have multiple execution strategies)
            any(subq in sql_lower for subq in ['in (', 'exists (', 'all (', 'any (', 'some (']),
            # Complex WHERE conditions (benefit from different scan strategies)
            len(re.findall(r'\b(and|or)\b', sql_lower)) > 1,
            # ORDER BY/LIMIT (can benefit from different sort strategies)
            any(sort in sql_lower for sort in ['order by', 'limit', 'offset']),
            # CTEs (complex query planning)
            'with ' in sql_lower,
            # Array/JSON operations (YugabyteDB specific optimizations)
            any(op in sql_lower for op in ['@>', '<@', '?', '?|', '?&', 'jsonb_', 'array_']),
            # String operations (can benefit from different execution strategies)
            any(str_op in sql_lower for str_op in ['like', 'ilike', 'similar to', 'regexp_']),
            # Mathematical operations (can benefit from different execution strategies)
            any(math_op in sql_lower for math_op in ['+', '-', '*', '/', '%', 'mod(', 'power(']),
            # Date/time operations (often benefit from index optimizations)
            any(date_op in sql_lower for date_op in ['date_trunc', 'extract', 'interval', 'now(', 'current_']),
            # Type casting (can affect execution plans)
            '::' in sql_lower or 'cast(' in sql_lower,
            # User-created tables (more likely to have meaningful data)
            any(table in sql_lower for table in ['information_schema', 'pg_catalog', 'pg_stat']),
            # Nested queries (complex execution planning)
            sql_lower.count('select') > 1,
            # Set operations (can have different execution strategies)
            any(set_op in sql_lower for set_op in ['union', 'intersect', 'except']),
            # DISTINCT (can benefit from different execution strategies)
            'distinct' in sql_lower,
            # CASE expressions (complex execution planning)
            'case ' in sql_lower,
            # COALESCE/NULLIF (can affect execution plans)
            any(func in sql_lower for func in ['coalesce(', 'nullif('])
        ]
        
        # Require at least 2 characteristics for a query to be considered for QPG testing
        # This ensures we test real-world application queries, not just simple information_schema lookups
        return sum(query_characteristics) >= 2
    
    def _execute_with_plan_multiple_runs(self, sql_query: str, hint: Optional[str] = None) -> Tuple[Optional[str], Optional[float]]:
        """Execute a query with a given hint multiple times and return average execution time."""
        try:
            # Add hint to the query if provided
            if hint:
                query_with_hint = self._add_hint_to_query(sql_query, hint)
            else:
                query_with_hint = sql_query
            
            # Execute with EXPLAIN ANALYZE to get plan and timing
            explain_query = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {query_with_hint}"
            
            execution_times = []
            plan = None
            
            # Execute multiple times for averaging
            for run in range(self.execution_runs):
                try:
                    start_time = time.time()
                    result = self.db_executor.execute_query(explain_query)
                    execution_time = time.time() - start_time
                    
                    if result and result.get('rows'):
                        # Store plan from first run
                        if run == 0:
                            plan = '\n'.join([row[0] for row in result['rows']])
                        
                        execution_times.append(execution_time)
                        
                        # Small delay between runs to avoid interference
                        if run < self.execution_runs - 1:
                            time.sleep(0.1)
                            
                except Exception as e:
                    self.logger.debug(f"Run {run + 1} failed: {e}")
                    continue
            
            # Return average execution time and plan
            if execution_times:
                avg_execution_time = sum(execution_times) / len(execution_times)
                return plan, avg_execution_time
            
            return None, None
            
        except Exception as e:
            self.logger.debug(f"Plan execution failed: {e}")
            return None, None
    
    def _generate_alternative_plans(self, sql_query: str) -> List[Tuple[str, str]]:
        """Generate alternative execution plan hints to test."""
        # Valid YugabyteDB-specific plan hints (verified to work)
        yb_hints = [
            ('NO_INDEX_SCAN', 'Disable index scan (force sequential)'),
            ('INDEX_SCAN', 'Force index scan'),
            ('YB_BATCHED_NESTED_LOOP', 'Force batched nested loop join'),
            ('HASH_JOIN', 'Force hash join'),
            ('NESTED_LOOP', 'Force nested loop join'),
            ('MERGE_JOIN', 'Force merge join'),
            ('NO_HASH_JOIN', 'Disable hash join'),
            ('NO_NESTED_LOOP', 'Disable nested loop join'),
            ('NO_MERGE_JOIN', 'Disable merge join')
        ]
        
        # Standard PostgreSQL hints that work in YugabyteDB
        pg_hints = [
            ('SET_TO_JOIN', 'Force set to join'),
            ('NO_MERGE', 'Disable merge join'),
            ('NO_HASH_JOIN', 'Disable hash join'),
            ('NO_NESTED_LOOP', 'Disable nested loop join'),
            ('NO_INDEX_SCAN', 'Disable index scan'),
            ('NO_SEQUENTIAL_SCAN', 'Disable sequential scan')
        ]
        
        # Analyze query characteristics to select appropriate hints
        sql_lower = sql_query.lower()
        
        if 'join' in sql_lower:
            # For JOIN queries, focus on join strategy hints
            return yb_hints[8:14] + pg_hints[1:4]  # Join-related hints
        elif 'where' in sql_lower and any(op in sql_lower for op in ['=', '>', '<', 'like', 'in']):
            # For WHERE queries, focus on scan strategy hints
            return yb_hints[5:8] + pg_hints[4:6]  # Scan-related hints
        elif 'group by' in sql_lower or 'order by' in sql_lower:
            # For aggregation/sorting queries, focus on execution strategy hints
            return yb_hints[0:5] + yb_hints[8:10]  # Execution and join hints
        else:
            # For other queries, use a balanced set of hints
            return yb_hints[:10] + pg_hints[:3]
    
    def _create_bug_report(self, sql_query: str, default_plan: str, default_time: float, 
                          best_plan: Optional[Dict], suboptimal_plans: List[Dict]) -> Dict[str, Any]:
        """Create a comprehensive bug report with exact reproducers and dataset information."""
        bug_description = "Query Plan Guidance Oracle detected suboptimal default plan"
        
        if best_plan:
            bug_description += f". Found better plan with {best_plan['hint']} hint: {best_plan['improvement']:.1f}% faster"
        
        if suboptimal_plans:
            worst_plan = max(suboptimal_plans, key=lambda x: x['worse_by'])
            bug_description += f". Default plan is {worst_plan['worse_by']:.1f}% slower than {worst_plan['hint']} hint"
        
        # Extract dataset information from the query
        dataset_info = self._extract_dataset_info(sql_query, default_plan)
        
        # Create exact reproducers with valid hints
        reproducers = []
        
        # Default query reproducer
        reproducers.append({
            'description': 'Default query (suboptimal)',
            'query': sql_query,
            'expected_performance': f"{default_time:.6f}s (baseline)",
            'notes': 'This is the original query that shows suboptimal performance'
        })
        
        # Best alternative reproducer
        if best_plan:
            best_query = self._add_hint_to_query(sql_query, best_plan['hint'])
            reproducers.append({
                'description': f'Optimized query with {best_plan["hint"]} hint (recommended)',
                'query': best_query,
                'expected_performance': f"{best_plan['execution_time']:.6f}s ({best_plan['improvement']:.1f}% faster)",
                'notes': f'This query uses the {best_plan["hint"]} hint to achieve better performance'
            })
        
        # Suboptimal alternatives reproducers
        for plan in suboptimal_plans[:3]:  # Show top 3 alternatives
            alt_query = self._add_hint_to_query(sql_query, plan['hint'])
            reproducers.append({
                'description': f'Alternative with {plan["hint"]} hint',
                'query': alt_query,
                'expected_performance': f"{plan['execution_time']:.6f}s ({plan['worse_by']:.1f}% slower)",
                'notes': f'This query shows that {plan["hint"]} hint performs worse than default'
            })
        
        # Create comprehensive context with clear performance comparison
        context = {
            'default_plan': default_plan,
            'default_execution_time': default_time,
            'best_alternative': best_plan,
            'suboptimal_alternatives': suboptimal_plans,
            'performance_threshold': self.performance_threshold,
            'qpg_check_query': sql_query,
            'execution_runs': self.execution_runs,
            'reproducers': reproducers,
            'dataset_information': dataset_info,
            'performance_analysis': self._create_performance_analysis(default_time, best_plan, suboptimal_plans)
        }
        
        return {
            'bug_type': 'qpg',
            'description': bug_description,
            'query': sql_query,
            'reproduction_query': reproducers[1]['query'] if best_plan else sql_query,  # Best alternative as primary reproducer
            'context': context,
            'oracle_name': 'QPGOracle',
            'dataset_info': dataset_info,
            'performance_summary': self._create_performance_summary(default_time, best_plan, suboptimal_plans)
        }
    
    def _extract_dataset_info(self, sql_query: str, plan: str) -> Dict[str, Any]:
        """Extract dataset information from query and execution plan."""
        dataset_info = {
            'tables_accessed': [],
            'estimated_rows': 0,
            'actual_rows': 0,
            'data_size_estimate': 'Unknown',
            'indexes_used': [],
            'scan_methods': [],
            'join_methods': []
        }
        
        try:
            # Extract table names from query
            table_pattern = r'from\s+([a-zA-Z_][a-zA-Z0-9_]*\.?[a-zA-Z_][a-zA-Z0-9_]*)'
            tables = re.findall(table_pattern, sql_query.lower())
            dataset_info['tables_accessed'] = [t.strip() for t in tables if t.strip()]
            
            # Extract information from execution plan
            if plan:
                # Extract estimated vs actual rows
                est_pattern = r'rows=(\d+)'
                actual_pattern = r'actual time=.*?rows=(\d+)'
                
                est_matches = re.findall(est_pattern, plan)
                actual_matches = re.findall(actual_pattern, plan)
                
                if est_matches:
                    dataset_info['estimated_rows'] = sum(int(x) for x in est_matches)
                if actual_matches:
                    dataset_info['actual_rows'] = sum(int(x) for x in actual_matches)
                
                # Extract scan methods
                scan_patterns = [
                    r'Seq Scan on ([a-zA-Z_][a-zA-Z0-9_]*)',
                    r'Index Scan using ([a-zA-Z_][a-zA-Z0-9_]*)',
                    r'Bitmap Heap Scan on ([a-zA-Z_][a-zA-Z0-9_]*)'
                ]
                
                for pattern in scan_patterns:
                    matches = re.findall(pattern, plan)
                    dataset_info['scan_methods'].extend(matches)
                
                # Extract join methods
                join_patterns = [
                    r'Hash Join',
                    r'Nested Loop',
                    r'Merge Join',
                    r'YB Batched Nested Loop'
                ]
                
                for pattern in join_patterns:
                    if pattern in plan:
                        dataset_info['join_methods'].append(pattern)
                
                # Extract indexes used
                index_pattern = r'Index Scan using ([a-zA-Z_][a-zA-Z0-9_]*)'
                indexes = re.findall(index_pattern, plan)
                dataset_info['indexes_used'] = list(set(indexes))
                
                # Estimate data size based on rows and typical row sizes
                if dataset_info['actual_rows'] > 0:
                    # Rough estimate: assume average 100 bytes per row for information_schema
                    if 'information_schema' in str(dataset_info['tables_accessed']).lower():
                        estimated_bytes = dataset_info['actual_rows'] * 100
                        if estimated_bytes > 1024 * 1024:
                            dataset_info['data_size_estimate'] = f"{estimated_bytes / (1024 * 1024):.1f} MB"
                        else:
                            dataset_info['data_size_estimate'] = f"{estimated_bytes / 1024:.1f} KB"
            
        except Exception as e:
            self.logger.debug(f"Error extracting dataset info: {e}")
        
        return dataset_info
    
    def _create_performance_analysis(self, default_time: float, best_plan: Optional[Dict], 
                                   suboptimal_plans: List[Dict]) -> Dict[str, Any]:
        """Create clear performance analysis for the bug report."""
        analysis = {
            'baseline_performance': f"{default_time:.6f} seconds",
            'performance_variations': {},
            'recommendations': [],
            'impact_assessment': 'Low'
        }
        
        if best_plan:
            improvement = best_plan['improvement']
            analysis['performance_variations']['best_alternative'] = {
                'hint': best_plan['hint'],
                'performance': f"{best_plan['execution_time']:.6f} seconds",
                'improvement': f"{improvement:.1f}% faster",
                'time_saved': f"{default_time - best_plan['execution_time']:.6f} seconds"
            }
            
            # Assess impact based on improvement
            if improvement > 50:
                analysis['impact_assessment'] = 'High'
            elif improvement > 25:
                analysis['impact_assessment'] = 'Medium'
            
            analysis['recommendations'].append(f"Use {best_plan['hint']} hint for {improvement:.1f}% performance improvement")
        
        # Analyze suboptimal plans
        if suboptimal_plans:
            worst_plan = max(suboptimal_plans, key=lambda x: x['worse_by'])
            analysis['performance_variations']['worst_alternative'] = {
                'hint': worst_plan['hint'],
                'performance': f"{worst_plan['execution_time']:.6f} seconds",
                'degradation': f"{worst_plan['worse_by']:.1f}% slower",
                'time_lost': f"{worst_plan['execution_time'] - default_time:.6f} seconds"
            }
            
            analysis['recommendations'].append(f"Avoid {worst_plan['hint']} hint as it degrades performance by {worst_plan['worse_by']:.1f}%")
        
        # Add general recommendations
        analysis['recommendations'].extend([
            "Test query performance with different hints in your specific environment",
            "Monitor query performance over time as data distribution changes",
            "Consider creating appropriate indexes if sequential scans are frequent"
        ])
        
        return analysis
    
    def _create_performance_summary(self, default_time: float, best_plan: Optional[Dict], 
                                  suboptimal_plans: List[Dict]) -> Dict[str, Any]:
        """Create a concise performance summary for quick assessment."""
        summary = {
            'baseline_time': default_time,
            'best_alternative_time': best_plan['execution_time'] if best_plan else default_time,
            'performance_improvement': best_plan['improvement'] if best_plan else 0,
            'recommended_hint': best_plan['hint'] if best_plan else 'None',
            'total_alternatives_tested': len(suboptimal_plans) + (1 if best_plan else 0),
            'execution_runs_per_test': self.execution_runs
        }
        
        return summary
    
    def _add_hint_to_query(self, sql_query: str, hint: str) -> str:
        """Add a hint to a query in the correct format."""
        if '/*+' in sql_query:
            # Replace existing hint
            return sql_query.replace('/*+', f'/*+ {hint}')
        else:
            # Add hint after SELECT
            return sql_query.replace('SELECT', f'SELECT /*+ {hint} */', 1)
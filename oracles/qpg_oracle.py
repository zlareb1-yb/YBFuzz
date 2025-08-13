# Implements a suite of advanced optimizer bug detection techniques, including
# Differential Query Plans (DQP), Cardinality Estimation Restriction
# Testing (CERT), and Constant Optimization Driven Testing (CODDTest).
# This version also contributes to Corpus Evolution.

import logging
import time
from typing import Dict, Any, Optional, List, Tuple
from .base_oracle import BaseOracle

class QPGOracle(BaseOracle):
    """Query Plan Guidance Oracle - Tests if optimizer's default plan is optimal."""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.logger = logging.getLogger(__name__)
        self.performance_threshold = config.get('qpg_performance_threshold', 0.1)  # 10% performance difference threshold
        
    def check_for_bugs(self, sql_query: str) -> Optional[Dict[str, Any]]:
        """Check if the optimizer's default plan is optimal by testing alternative plans."""
        try:
            # Skip if query doesn't support plan hints
            if not self._supports_plan_hints(sql_query):
                return None
                
            # Get the default plan and execution time
            default_plan, default_time = self._execute_with_plan(sql_query, None)
            if not default_plan or default_time is None:
                return None
                
            # Generate alternative plans with hints
            alternative_plans = self._generate_alternative_plans(sql_query)
            
            # Test each alternative plan
            best_plan = None
            best_time = default_time
            suboptimal_plans = []
            
            for hint, hint_description in alternative_plans:
                try:
                    plan, execution_time = self._execute_with_plan(sql_query, hint)
                    if plan and execution_time is not None:
                        # Check if this plan is significantly better than default
                        if execution_time < best_time * (1 - self.performance_threshold):
                            best_plan = {
                                'hint': hint,
                                'description': hint_description,
                                'execution_time': execution_time,
                                'default_time': default_time,
                                'improvement': ((default_time - execution_time) / default_time) * 100
                            }
                            best_time = execution_time
                        # Check if default plan is significantly worse than alternatives
                        elif execution_time < default_time * (1 - self.performance_threshold):
                            suboptimal_plans.append({
                                'hint': hint,
                                'description': hint_description,
                                'execution_time': execution_time,
                                'default_time': default_time,
                                'worse_by': ((execution_time - default_time) / default_time) * 100
                            })
                            
                except Exception as e:
                    self.logger.debug(f"Alternative plan failed: {e}")
                    continue
            
            # Report bugs if we found better plans or if default is significantly suboptimal
            if best_plan or suboptimal_plans:
                return self._create_bug_report(sql_query, default_plan, default_time, best_plan, suboptimal_plans)
                
            return None
            
        except Exception as e:
            self.logger.error(f"Error in QPG oracle: {e}")
            return None
    
    def _supports_plan_hints(self, sql_query: str) -> bool:
        """Check if the query supports plan hints."""
        # Only test SELECT queries that can benefit from plan hints
        sql_lower = sql_query.lower().strip()
        return (
            sql_lower.startswith('select') and
            'information_schema' in sql_lower and
            not any(keyword in sql_lower for keyword in ['create', 'insert', 'update', 'delete', 'drop'])
        )
    
    def _execute_with_plan(self, sql_query: str, hint: Optional[str]) -> Tuple[Optional[str], Optional[float]]:
        """Execute query with optional plan hint and return plan and execution time."""
        try:
            if hint:
                # Add hint to the query
                if '/*+' in sql_query:
                    # Replace existing hint
                    query_with_hint = sql_query.replace('/*+', f'/*+ {hint}')
                else:
                    # Add hint after SELECT
                    query_with_hint = sql_query.replace('SELECT', f'SELECT /*+ {hint} */', 1)
            else:
                query_with_hint = sql_query
            
            # Execute with EXPLAIN ANALYZE to get plan and timing
            explain_query = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {query_with_hint}"
            
            start_time = time.time()
            result = self.db_executor.execute_query(explain_query)
            execution_time = time.time() - start_time
            
            if result and result.get('rows'):
                plan = '\n'.join([row[0] for row in result['rows']])
                return plan, execution_time
            
            return None, None
            
        except Exception as e:
            self.logger.debug(f"Plan execution failed: {e}")
            return None, None
    
    def _generate_alternative_plans(self, sql_query: str) -> List[Tuple[str, str]]:
        """Generate alternative execution plan hints to test."""
        # YugabyteDB-specific plan hints
        yb_hints = [
            ('LEADER_LOCAL', 'Force local leader execution'),
            ('LEADER_READ', 'Force leader read execution'),
            ('LEADER_WRITE', 'Force leader write execution'),
            ('PREFER_LOCAL', 'Prefer local execution'),
            ('PREFER_REMOTE', 'Prefer remote execution'),
            ('NO_INDEX_SCAN', 'Force sequential scan'),
            ('INDEX_SCAN', 'Force index scan'),
            ('SEQUENTIAL_SCAN', 'Force sequential scan'),
            ('YB_BATCHED_NESTED_LOOP', 'Force batched nested loop'),
            ('HASH_JOIN', 'Force hash join'),
            ('NESTED_LOOP', 'Force nested loop join'),
            ('MERGE_JOIN', 'Force merge join')
        ]
        
        # Standard PostgreSQL hints
        pg_hints = [
            ('SET_TO_JOIN', 'Force set to join'),
            ('NO_MERGE', 'Disable merge join'),
            ('NO_HASH_JOIN', 'Disable hash join'),
            ('NO_NESTED_LOOP', 'Disable nested loop join'),
            ('NO_INDEX_SCAN', 'Disable index scan'),
            ('NO_SEQUENTIAL_SCAN', 'Disable sequential scan')
        ]
        
        # Combine hints based on query characteristics
        if 'join' in sql_query.lower():
            return yb_hints + pg_hints
        elif 'where' in sql_query.lower():
            return yb_hints[:8] + pg_hints[4:]  # Focus on scan and join hints
        else:
            return yb_hints[:6]  # Basic execution hints
    
    def _create_bug_report(self, sql_query: str, default_plan: str, default_time: float, 
                          best_plan: Optional[Dict], suboptimal_plans: List[Dict]) -> Dict[str, Any]:
        """Create a comprehensive bug report."""
        bug_description = "Query Plan Guidance Oracle detected suboptimal default plan"
        
        if best_plan:
            bug_description += f". Found better plan with {best_plan['hint']} hint: {best_plan['improvement']:.1f}% faster"
        
        if suboptimal_plans:
            worst_plan = max(suboptimal_plans, key=lambda x: x['worse_by'])
            bug_description += f". Default plan is {worst_plan['worse_by']:.1f}% slower than {worst_plan['hint']} hint"
        
        context = {
            'default_plan': default_plan,
            'default_execution_time': default_time,
            'best_alternative': best_plan,
            'suboptimal_alternatives': suboptimal_plans,
            'performance_threshold': self.performance_threshold,
            'qpg_check_query': sql_query
        }
        
        return {
            'bug_type': 'qpg',
            'description': bug_description,
            'query': sql_query,
            'context': context,
            'oracle_name': 'QPGOracle'
        }
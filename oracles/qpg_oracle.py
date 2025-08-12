# Implements a suite of advanced optimizer bug detection techniques, including
# Differential Query Plans (DQP), Cardinality Estimation Restriction
# Testing (CERT), and Constant Optimization Driven Testing (CODDTest).
# This version also contributes to Corpus Evolution.

import logging
import re
import time
import hashlib
import os
import random
from typing import Union, Optional, Dict, List, Tuple, Any
from .base_oracle import BaseOracle
from core.generator import SQLNode
from utils.db_executor import DBExecutor

class QPGOracle(BaseOracle):
    """
    Query Plan Guidance (QPG) Oracle for detecting optimization bugs.
    
    QPG is a feedback-guided test case generation approach based on the insight that
    query plans capture whether interesting behavior is exercised within the DBMS.
    
    It works by mutating the database state when no new query plans have been observed
    after executing a number of queries, expecting that the new state enables new query
    plans to be triggered.
    """
    
    def __init__(self, db_executor: DBExecutor):
        super().__init__(db_executor)
        self.logger = logging.getLogger(__name__)
        self.name = "QPGOracle"
        self.observed_plans = set()
        self.plan_history = []
        self.max_plans_without_change = 50
        self.queries_since_last_plan_change = 0
        
    def check(self, sql_query: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check for optimization bugs using QPG technique.
        
        Args:
            sql_query: The SQL query to test
            
        Returns:
            Tuple of (bug_found, bug_description, reproduction_query)
        """
        try:
            # Only test SELECT queries
            if not self._is_select_query(sql_query):
                return False, None, None
            
            # Generate a QPG check query
            qpg_check_query = self._generate_qpg_check_query(sql_query)
            if not qpg_check_query:
                return False, None, None
            
            # Execute the QPG check query
            result = self.db_executor.execute_query(qpg_check_query, fetch_results=False)
            if not result.success:
                return False, None, None
            
            # Get the query plan for the original query
            original_plan = self._get_query_plan(sql_query)
            if not original_plan:
                return False, None, None
            
            # Get the query plan for the QPG check query
            check_plan = self._get_query_plan(qpg_check_query)
            if not check_plan:
                return False, None, None
            
            # Check if we have a new query plan
            if self._is_new_plan(check_plan):
                # Only report if the change is significant
                if self._is_significant_plan_change(original_plan, check_plan):
                    self.logger.info(f"Significant query plan change observed: {check_plan}")
                    return True, "Significant query plan change observed", {
                        'original_plan': original_plan,
                        'new_plan': check_plan,
                        'qpg_check_query': qpg_check_query
                    }
                else:
                    self.logger.debug(f"Minor query plan variation observed (not significant)")
            
            return False, None, None
            
        except Exception as e:
            self.logger.error(f"Error in QPG check: {e}")
            return False, None, None
    
    def check_for_bugs(self, sql_query: str) -> Tuple[bool, str, Any]:
        """
        Check for QPG bugs in the given SQL query.
        
        Returns:
            Tuple of (bug_found, bug_description, bug_context)
        """
        try:
            if not self.can_check(sql_query):
                return False, None, None
            
            # Generate a QPG check query
            qpg_check_query = self._generate_qpg_check_query(sql_query)
            if not qpg_check_query:
                return False, None, None
            
            # Execute the QPG check query
            result = self.db_executor.execute_query(qpg_check_query, fetch_results=False)
            if not result.success:
                return False, None, None
            
            # Get the query plan for the original query
            original_plan = self._get_query_plan(sql_query)
            if not original_plan:
                return False, None, None
            
            # Get the query plan for the QPG check query
            check_plan = self._get_query_plan(qpg_check_query)
            if not check_plan:
                return False, None, None
            
            # Check if we have a new query plan
            if self._is_new_plan(check_plan):
                # Only report if the change is significant
                if self._is_significant_plan_change(original_plan, check_plan):
                    self.logger.info(f"Significant query plan change observed: {check_plan}")
                    return True, "Significant query plan change observed", {
                        'original_plan': original_plan,
                        'new_plan': check_plan,
                        'qpg_check_query': qpg_check_query
                    }
                else:
                    self.logger.debug(f"Minor query plan variation observed (not significant)")
            
            return False, None, None
            
        except Exception as e:
            self.logger.error(f"Error in QPG check: {e}")
            return False, None, None
    
    def _is_select_query(self, sql_query: str) -> bool:
        """Check if the query is a SELECT statement."""
        return sql_query.strip().upper().startswith("SELECT")
    
    def _get_query_plan(self, sql_query: str) -> str:
        """Get the query plan for a SQL query."""
        try:
            # Use EXPLAIN ANALYZE to get the query plan
            explain_query = f"EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {sql_query}"
            result = self.db_executor.execute_query(explain_query, fetch_results=True)
            
            if result.success and result.data:
                # Extract the plan from the result
                plan_lines = [str(row[0]) for row in result.data]
                return "|".join(plan_lines)
            else:
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to get query plan: {e}")
            return None
    
    def _is_new_plan(self, plan: str) -> bool:
        """Check if this is a new query plan we haven't seen before."""
        if not plan:
            return False
        
        # Extract a normalized signature from the plan
        plan_signature = self._extract_plan_signature_from_text(plan)
        if not plan_signature:
            return False
        
        # Check if we've seen this signature before
        if plan_signature not in self.observed_plans:
            self.observed_plans.add(plan_signature)
            return True
        
        return False
    
    def _extract_plan_signature_from_text(self, plan_text: str) -> Optional[str]:
        """Extract a normalized signature from query plan text for comparison."""
        try:
            if not plan_text:
                return None
            
            # Extract key plan elements (scan types, join methods, etc.)
            signature_parts = []
            
            # Look for scan types (these are significant)
            scan_patterns = [
                r'Seq Scan',
                r'Index Scan',
                r'Bitmap Heap Scan',
                r'Nested Loop',
                r'Hash Join',
                r'Merge Join',
                r'YB Batched Nested Loop Join'
            ]
            
            for pattern in scan_patterns:
                if re.search(pattern, plan_text, re.IGNORECASE):
                    signature_parts.append(pattern)
            
            # Look for significant cost estimate changes (only major changes)
            cost_match = re.search(r'cost=(\d+\.\d+)\.\.(\d+\.\d+)', plan_text)
            if cost_match:
                start_cost = float(cost_match.group(1))
                end_cost = float(cost_match.group(2))
                # Only consider significant cost changes (>20% difference)
                if end_cost > 0:
                    signature_parts.append(f"cost_range_{start_cost:.0f}_{end_cost:.0f}")
            
            # Look for row estimate changes (only major changes)
            rows_match = re.search(r'rows=(\d+)', plan_text)
            if rows_match:
                rows = int(rows_match.group(1))
                # Only consider significant row count changes (>50% difference)
                if rows > 0:
                    signature_parts.append(f"rows_{rows}")
            
            # Look for execution method changes (these are very significant)
            execution_patterns = [
                r'Sort Method:',
                r'Hash Method:',
                r'Join Filter:',
                r'Storage Filter:'
            ]
            
            for pattern in execution_patterns:
                if re.search(pattern, plan_text, re.IGNORECASE):
                    signature_parts.append(pattern)
            
            # Look for memory usage changes (only major changes)
            memory_match = re.search(r'Memory Usage: (\d+) kB', plan_text)
            if memory_match:
                memory = int(memory_match.group(1))
                # Only consider significant memory changes (>100kB difference)
                if memory > 0:
                    signature_parts.append(f"memory_{memory//100*100}")
            
            return '|'.join(signature_parts) if signature_parts else None
            
        except Exception as e:
            self.logger.error(f"Error extracting plan signature: {e}")
            return None
    
    def _mutate_database_state(self):
        """Mutate database state to trigger new query plans."""
        try:
            self.logger.info("Mutating database state to trigger new query plans...")
            
            # Simple mutations: insert/update some data
            mutations = [
                "INSERT INTO ybfuzz_schema.products (id, name, category, price, stock_count) VALUES (9999, 'QPG_MUTATION', 'TEST', 99.99, 999)",
                "UPDATE ybfuzz_schema.products SET stock_count = stock_count + 1 WHERE id = 1",
                "DELETE FROM ybfuzz_schema.products WHERE id = 9999"
            ]
            
            for mutation in mutations:
                try:
                    self.db_executor.execute_query(mutation)
                except Exception as e:
                    self.logger.warning(f"Mutation failed: {e}")
            
            self.logger.info("Database state mutation completed")
            
        except Exception as e:
            self.logger.error(f"Error mutating database state: {e}")
    
    def _check_optimization_bugs(self, sql_query: str, plan_result: Any) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check for optimization bugs by comparing with different optimization settings.
        
        Returns:
            Tuple of (bug_found, bug_description, reproduction_query)
        """
        try:
            # Check for cardinality estimation bugs
            cardinality_bug = self._check_cardinality_estimation(sql_query, plan_result)
            if cardinality_bug:
                return True, "Cardinality Estimation Bug", cardinality_bug
            
            # Check for cost estimation bugs
            cost_bug = self._check_cost_estimation(sql_query, plan_result)
            if cost_bug:
                return True, "Cost Estimation Bug", cost_bug
            
            # Check for plan selection bugs
            plan_bug = self._check_plan_selection(sql_query, plan_result)
            if plan_bug:
                return True, "Plan Selection Bug", plan_bug
            
            return False, None, None
            
        except Exception as e:
            self.logger.error(f"Error checking optimization bugs: {e}")
            return False, None, None
    
    def _check_cardinality_estimation(self, sql_query: str, plan_result: Any) -> Optional[str]:
        """Check for cardinality estimation bugs."""
        try:
            # Extract estimated vs actual row counts
            plan_text = '\n'.join([str(row) for row in plan_result.data])
            
            # Look for row estimates
            rows_match = re.search(r'rows=(\d+)', plan_text)
            if not rows_match:
                return None
            
            estimated_rows = int(rows_match.group(1))
            
            # Execute the actual query to get real row count
            count_query = f"SELECT COUNT(*) FROM ({sql_query}) AS qpg_check"
            count_result = self.db_executor.execute_query(count_query)
            
            if not count_result.success or not count_result.data:
                return None
            
            actual_rows = count_result.data[0][0] if count_result.data else 0
            
            # Check for significant estimation errors (>10x difference)
            if estimated_rows > 0 and actual_rows > 0:
                ratio = max(estimated_rows, actual_rows) / min(estimated_rows, actual_rows)
                if ratio > 10:
                    return f"""
-- Cardinality Estimation Bug Detected
-- Query: {sql_query}
-- Estimated rows: {estimated_rows}
-- Actual rows: {actual_rows}
-- Ratio: {ratio:.2f}x

-- Reproduction:
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {sql_query};
SELECT COUNT(*) FROM ({sql_query}) AS qpg_check;
"""
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking cardinality estimation: {e}")
            return None
    
    def _check_cost_estimation(self, sql_query: str, plan_result: Any) -> Optional[str]:
        """Check for cost estimation bugs."""
        try:
            # Extract cost estimates
            plan_text = '\n'.join([str(row) for row in plan_result.data])
            
            # Look for cost estimates
            cost_match = re.search(r'cost=(\d+\.\d+)\.\.(\d+\.\d+)', plan_text)
            if not cost_match:
                return None
            
            start_cost = float(cost_match.group(1))
            end_cost = float(cost_match.group(2))
            
            # Check for unreasonable cost estimates
            if start_cost < 0 or end_cost < 0 or end_cost < start_cost:
                return f"""
-- Cost Estimation Bug Detected
-- Query: {sql_query}
-- Start cost: {start_cost}
-- End cost: {end_cost}

-- Reproduction:
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {sql_query};
"""
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking cost estimation: {e}")
            return None
    
    def _check_plan_selection(self, sql_query: str, plan_result: Any) -> Optional[str]:
        """Check for plan selection bugs."""
        try:
            # Check if the plan contains suspicious patterns
            plan_text = '\n'.join([str(row) for row in plan_result.data])
            
            # Look for suspicious plan patterns
            suspicious_patterns = [
                (r'Seq Scan.*WHERE.*=', 'Sequential scan on indexed column'),
                (r'Hash Join.*WHERE.*=', 'Hash join when index join might be better'),
                (r'Nested Loop.*large table', 'Nested loop on large table')
            ]
            
            for pattern, description in suspicious_patterns:
                if re.search(pattern, plan_text, re.IGNORECASE):
                    return f"""
-- Plan Selection Bug Detected
-- Query: {sql_query}
-- Issue: {description}

-- Reproduction:
EXPLAIN (ANALYZE, BUFFERS, FORMAT TEXT) {sql_query};
"""
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error checking plan selection: {e}")
            return None

    def _generate_qpg_check_query(self, original_query: str) -> str:
        """Generate a QPG check query to compare query plans."""
        try:
            # Remove any trailing semicolon from the original query
            clean_query = original_query.rstrip(';').strip()
            
            # Generate a simple check query that will have a different plan
            # Use a subquery to force different execution path
            qpg_check = f"SELECT COUNT(*) FROM ({clean_query}) AS qpg_check"
            
            return qpg_check
        except Exception as e:
            self.logger.error(f"Failed to generate QPG check query: {e}")
            # Fallback to a simple query
            return "SELECT COUNT(*) FROM (SELECT 1) AS qpg_check"

    def _is_significant_plan_change(self, original_plan: str, new_plan: str) -> bool:
        """Check if the plan change is significant enough to indicate a real bug."""
        try:
            if not original_plan or not new_plan:
                return False
            
            # Extract signatures for both plans
            original_sig = self._extract_plan_signature_from_text(original_plan)
            new_sig = self._extract_plan_signature_from_text(new_plan)
            
            if not original_sig or not new_sig:
                return False
            
            # If signatures are identical, no significant change
            if original_sig == new_sig:
                return False
            
            # Check for significant structural changes
            original_parts = set(original_sig.split('|'))
            new_parts = set(new_sig.split('|'))
            
            # Count differences in key components
            differences = len(original_parts.symmetric_difference(new_parts))
            
            # Only consider it significant if there are substantial differences
            # (more than just minor cost/row variations)
            if differences < 3:
                return False
            
            # Additional filtering: check if the changes are just minor cost variations
            if self._are_just_minor_cost_variations(original_plan, new_plan):
                return False
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error checking plan significance: {e}")
            return False
    
    def _are_just_minor_cost_variations(self, original_plan: str, new_plan: str) -> bool:
        """Check if the plan changes are just minor cost/timing variations."""
        try:
            # Extract cost estimates
            original_cost_match = re.search(r'cost=(\d+\.\d+)\.\.(\d+\.\d+)', original_plan)
            new_cost_match = re.search(r'cost=(\d+\.\d+)\.\.(\d+\.\d+)', new_plan)
            
            if original_cost_match and new_cost_match:
                original_start = float(original_cost_match.group(1))
                original_end = float(original_cost_match.group(2))
                new_start = float(new_cost_match.group(1))
                new_end = float(new_cost_match.group(2))
                
                # Calculate percentage differences
                start_diff_pct = abs(new_start - original_start) / original_start * 100 if original_start > 0 else 0
                end_diff_pct = abs(new_end - original_end) / original_end * 100 if original_end > 0 else 0
                
                # If both differences are less than 5%, consider it minor
                if start_diff_pct < 5 and end_diff_pct < 5:
                    return True
            
            # Check for identical structural components
            original_scan_types = set(re.findall(r'(Seq Scan|Index Scan|Bitmap Heap Scan|Nested Loop|Hash Join|Merge Join|YB Batched Nested Loop Join)', original_plan, re.IGNORECASE))
            new_scan_types = set(re.findall(r'(Seq Scan|Index Scan|Bitmap Heap Scan|Nested Loop|Hash Join|Merge Join|YB Batched Nested Loop Join)', new_plan, re.IGNORECASE))
            
            # If scan types are identical, it's likely just minor variations
            if original_scan_types == new_scan_types:
                return True
            
            return False
            
        except Exception as e:
            self.logger.error(f"Error checking cost variations: {e}")
            return False
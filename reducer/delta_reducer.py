# This module contains the definitive implementation of the automatic test case
# reducer. It uses a multi-strategy, iterative delta debugging algorithm to
# shrink a failing query down to the smallest possible version that still
# reproduces the bug.

import logging
import re
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from utils.db_executor import DBExecutor
    from utils.bug_reporter import BugReporter

class DeltaReducer:
    """
    Reduces a failing SQL query to its minimal form using a multi-strategy
    delta debugging algorithm.
    """
    def __init__(self, db_executor: 'DBExecutor', bug_reporter: 'BugReporter'):
        self.db_executor = db_executor
        self.bug_reporter = bug_reporter
        self.logger = logging.getLogger(self.__class__.__name__)

    def _check_if_bug_persists(self, sql_query: str, original_bug_signature: str) -> bool:
        """
        Executes a reduced query to see if it still triggers the original bug.
        """
        # Temporarily lower the log level for the executor to avoid spamming
        # the main log with expected failures during reduction.
        original_level = self.db_executor.logger.level
        self.db_executor.logger.setLevel(logging.ERROR)
        
        _ , exception = self.db_executor.execute_query(sql_query)
        
        # Restore the original log level
        self.db_executor.logger.setLevel(original_level)

        if not exception:
            return False
        
        current_signature = self.bug_reporter._get_bug_signature("REDUCER_CHECK", exception)
        return current_signature == original_bug_signature

    def reduce(self, original_query: str, bug_signature: str) -> str:
        """
        Performs the delta debugging loop, applying multiple reduction
        strategies until the query can no longer be minimized.

        Args:
            original_query: The large query that triggered a bug.
            bug_signature: The unique signature of the bug to be reproduced.

        Returns:
            The smallest query that could be found that still triggers the bug.
        """
        self.logger.info(f"Starting reduction for bug signature: {bug_signature}")
        self.logger.debug(f"Original failing query:\n{original_query}")
        
        minimized_query = original_query
        
        # --- Iterative Reduction Loop ---
        # Keep trying to reduce the query until a full pass of all strategies
        # fails to make it any smaller.
        while True:
            query_before_pass = minimized_query
            
            # Apply reduction strategies in order of simplicity
            minimized_query = self._reduce_optional_clauses(minimized_query, bug_signature)
            minimized_query = self._reduce_select_list(minimized_query, bug_signature)
            minimized_query = self._reduce_where_clause(minimized_query, bug_signature)
            
            # If the query is unchanged after a full pass, we're done.
            if minimized_query == query_before_pass:
                break
        
        self.logger.info("Reduction finished.")
        self.logger.debug(f"Minimized query:\n{minimized_query}")
        return minimized_query

    def _reduce_optional_clauses(self, query: str, bug_signature: str) -> str:
        """Strategy 1: Try to remove entire optional clauses."""
        self.logger.debug("Attempting to reduce optional clauses (ORDER BY, LIMIT, etc.)...")
        clauses_to_remove = [
            r'\s+ORDER BY.*',
            r'\s+LIMIT\s+\d+',
            r'\s+GROUP BY.*?(?=HAVING|ORDER BY|LIMIT|$)',
            r'\s+HAVING.*?(?=ORDER BY|LIMIT|$)'
        ]
        
        reduced_query = query
        for clause_regex in clauses_to_remove:
            temp_query = re.sub(clause_regex, '', reduced_query, flags=re.IGNORECASE | re.DOTALL)
            if temp_query != reduced_query and self._check_if_bug_persists(temp_query, bug_signature):
                self.logger.info(f"Successfully removed clause matching: {clause_regex}")
                reduced_query = temp_query
        
        return reduced_query

    def _reduce_select_list(self, query: str, bug_signature: str) -> str:
        """Strategy 2: Try to remove items from the SELECT list."""
        self.logger.debug("Attempting to reduce SELECT list...")
        # This regex is a simplification and might not handle all cases, but is good for a start.
        match = re.search(r'SELECT\s+(.*?)\s+FROM', query, re.IGNORECASE | re.DOTALL)
        if not match:
            return query
            
        select_list_str = match.group(1)
        columns = [c.strip() for c in select_list_str.split(',')]
        
        # We can only reduce if there's more than one column
        if len(columns) <= 1:
            return query
            
        # Try removing each column one by one
        for i in range(len(columns)):
            temp_columns = columns[:i] + columns[i+1:]
            new_select_list = ", ".join(temp_columns)
            temp_query = query.replace(select_list_str, new_select_list, 1)
            
            if self._check_if_bug_persists(temp_query, bug_signature):
                self.logger.info(f"Successfully removed '{columns[i]}' from SELECT list.")
                # If it still fails, this is our new baseline. Restart the reduction.
                return self.reduce(temp_query, bug_signature)
                
        return query

    def _reduce_where_clause(self, query: str, bug_signature: str) -> str:
        """Strategy 3: Try to remove individual 'AND' or 'OR' predicates."""
        self.logger.debug("Attempting to reduce WHERE clause predicates...")
        where_match = re.search(r'(WHERE\s+)(.*)', query, re.IGNORECASE | re.DOTALL)
        if not where_match:
            return query

        prefix = where_match.group(1)
        predicates_str = where_match.group(2)
        
        # Split predicates by AND/OR, keeping the delimiters. This is a simplification.
        predicates = re.split(r'(\s+AND\s+|\s+OR\s+)', predicates_str)
        
        if len(predicates) <= 1:
            return query

        # Try removing each predicate one by one (in reverse order for safety)
        for i in range(len(predicates) - 1, -1, -1):
            # We can only remove the predicate itself, not the AND/OR keyword
            if 'AND' in predicates[i].upper() or 'OR' in predicates[i].upper():
                continue

            temp_predicates = predicates[:i] + predicates[i+1:]
            
            # Clean up dangling AND/OR at the start or end
            if temp_predicates and re.match(r'^\s*(AND|OR)\s*', temp_predicates[0], re.IGNORECASE):
                temp_predicates = temp_predicates[1:]
            if temp_predicates and re.match(r'.*\s*(AND|OR)\s*$', temp_predicates[-1], re.IGNORECASE):
                temp_predicates = temp_predicates[:-1]
            
            if not temp_predicates: continue

            reduced_predicate_str = "".join(temp_predicates)
            reduced_query = query.replace(predicates_str, reduced_predicate_str, 1)
            
            if self._check_if_bug_persists(reduced_query, bug_signature):
                self.logger.info(f"Successfully removed predicate '{predicates[i].strip()}' from WHERE clause.")
                # If it still fails, this is our new baseline. Restart the reduction.
                return self.reduce(reduced_query, bug_signature)

        return query
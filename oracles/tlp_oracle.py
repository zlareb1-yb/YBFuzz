# Implements logic bug detection using Ternary Logic Partitioning (TLP)
# and Non-optimizing Reference Engine Construction (NoREC). This optimized
# version is AST-aware for robust and precise predicate analysis.

import logging
import random
import re
from typing import Union, Optional
from .base_oracle import BaseOracle
from core.generator import SQLNode, WhereClauseNode, SelectNode, SequenceNode

class TLOracle(BaseOracle):
    """
    Detects logic bugs using TLP (for WHERE clause correctness) and
    NoREC (for optimizer-induced logic errors).
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger(self.name)
        self.oracle_config = self.config.get('oracles', {}).get(self.name, {})
        self.norec_settings = self.oracle_config.get('norec_settings', [])

    def can_check(self, sql_or_ast: Union[str, 'SQLNode'], exception: Optional[Exception]) -> bool:
        """
        This oracle is only interested in successful SELECT queries.
        """
        if exception:
            return False
        
        # Check if it's a SELECT statement, whether from AST or string
        if isinstance(sql_or_ast, SQLNode):
            return isinstance(sql_or_ast, SelectNode)
        else:
            return sql_or_ast.strip().upper().startswith("SELECT")

    def check(self, sql_or_ast: Union[str, 'SQLNode'], result: Optional[list], exception: Optional[Exception]):
        """Orchestrates the TLP and NoREC checks."""
        sql_query = sql_or_ast if isinstance(sql_or_ast, str) else sql_or_ast.to_sql()

        # Run NoREC check on the original query result
        if self.oracle_config.get('enable_norec', False):
            self.logger.debug("Running NoREC check...")
            self._run_norec_check(sql_query, result)

        # Run TLP check, which requires the AST for robust analysis
        if self.oracle_config.get('enable_tlp', False) and isinstance(sql_or_ast, SQLNode):
            self.logger.debug("Running TLP check...")
            self._run_tlp_check(sql_or_ast)

    def _run_norec_check(self, original_query: str, original_result: Optional[list]):
        """
        Implements NoREC by re-running the query with different optimizer
        settings disabled and comparing the results.
        """
        if not self.norec_settings or original_result is None:
            return

        for setting in self.norec_settings:
            disable_command = f"SET {setting} = off;"
            enable_command = f"SET {setting} = on;"
            
            norec_result, exc = self.executor.execute_query_with_setup([disable_command], original_query, [enable_command])

            if exc:
                self.reporter.report_bug(self.name, "NoREC - Exception", f"Query failed with '{setting}' disabled.", original_query=original_query, exception=exc)
                continue

            # A robust comparison should be type-aware and order-agnostic
            if len(original_result) != len(norec_result) or set(map(str, original_result)) != set(map(str, norec_result)):
                self.reporter.report_bug(
                    oracle_name=self.name,
                    bug_type="NoREC - Inconsistent Results",
                    description=f"Query returned different results with '{setting}' disabled.",
                    original_query=original_query,
                    original_result_count=len(original_result),
                    variant_result_count=len(norec_result)
                )

    def _run_tlp_check(self, statement_node: SQLNode):
        """
        Validates the logic of a WHERE clause by checking if the row counts for
        (P), (NOT P), and (P IS NULL) sum to the total number of rows.
        """
        # --- AST-based extraction for robustness ---
        from_clause_node = statement_node.find_child_of_type(SequenceNode) # Brittle, assumes first sequence is FROM
        if not from_clause_node: return
        # Reconstruct the "FROM table" part of the query
        base_from_sql = from_clause_node.to_sql()

        where_clause_node = statement_node.find_child_of_type(WhereClauseNode)
        
        # Determine the predicate and the total count query
        if where_clause_node and len(where_clause_node.children) > 1:
            predicate_sql = where_clause_node.children[1].to_sql()
            total_query = f"SELECT COUNT(*) FROM {base_from_sql.replace('FROM ', '', 1)}"
        else:
            # If there's no WHERE clause, the TLP check is simpler.
            # The "TRUE" partition is the whole table.
            predicate_sql = "TRUE"
            total_query = f"SELECT COUNT(*) FROM {base_from_sql.replace('FROM ', '', 1)}"

        # Generate the three partitioning queries
        query_true = f"SELECT COUNT(*) FROM {base_from_sql.replace('FROM ', '', 1)} WHERE {predicate_sql}"
        query_false = f"SELECT COUNT(*) FROM {base_from_sql.replace('FROM ', '', 1)} WHERE NOT ({predicate_sql})"
        query_null = f"SELECT COUNT(*) FROM {base_from_sql.replace('FROM ', '', 1)} WHERE ({predicate_sql}) IS NULL"

        # Execute all queries
        res_true, exc_true = self.executor.execute_query(query_true)
        res_false, exc_false = self.executor.execute_query(query_false)
        res_null, exc_null = self.executor.execute_query(query_null)
        res_total, exc_total = self.executor.execute_query(total_query)

        if exc_true or exc_false or exc_null or exc_total:
            self.reporter.report_bug(self.name, "TLP - Exception", "One of the TLP partitioning queries failed.", original_query=statement_node.to_sql(), exception=exc_true or exc_false or exc_null or exc_total)
            return

        count_true = res_true[0][0] if res_true else 0
        count_false = res_false[0][0] if res_false else 0
        count_null = res_null[0][0] if res_null else 0
        count_total = res_total[0][0] if res_total else 0
        
        partition_sum = count_true + count_false + count_null

        if partition_sum != count_total:
            self.reporter.report_bug(
                oracle_name=self.name,
                bug_type="TLP - Inconsistent Partition",
                description="The sum of TRUE, FALSE, and NULL partitions for a predicate did not equal the total number of rows.",
                original_predicate=predicate_sql,
                true_count=count_true,
                false_count=count_false,
                null_count=count_null,
                total_count=count_total
            )
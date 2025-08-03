# Implements a suite of advanced optimizer bug detection techniques, including
# Differential Query Plans (DQP), Cardinality Estimation Restriction
# Testing (CERT), and Constant Optimization Driven Testing (CODDTest).
# This version also contributes to Corpus Evolution.

import logging
import re
import time
import hashlib
import os
from typing import Union, Optional
from .base_oracle import BaseOracle
from core.generator import SQLNode

class QPGOracle(BaseOracle):
    """
    Detects optimizer bugs by analyzing and comparing query plans and contributes
    to corpus evolution by finding queries with unique execution plans.
    """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.logger = logging.getLogger(self.name)
        self.oracle_config = self.config.get('oracles', {}).get(self.name, {})
        
        # --- State for Corpus Evolution ---
        self.seen_plan_structures = set()
        self.evo_config = self.config.get('corpus_evolution', {})
        self.evo_dir = self.evo_config.get('directory')

    def can_check(self, sql_or_ast: Union[str, 'SQLNode'], exception: Optional[Exception]) -> bool:
        """
        This oracle is only interested in successful SELECT queries, as it
        needs a valid query plan to analyze.
        """
        if exception:
            return False
        
        sql_query = sql_or_ast if isinstance(sql_or_ast, str) else sql_or_ast.to_sql()
        return sql_query.strip().upper().startswith("SELECT")

    def check(self, sql_or_ast: Union[str, 'SQLNode'], result: Optional[list], exception: Optional[Exception]):
        """
        Orchestrates the various optimizer checks.
        """
        sql_query = sql_or_ast if isinstance(sql_or_ast, str) else sql_or_ast.to_sql()

        # Get the initial, detailed plan for analysis
        explain_query = f"EXPLAIN (ANALYZE, VERBOSE, COSTS) {sql_query}"
        plan_result, plan_exception = self.executor.execute_query(explain_query)
        if plan_exception or not plan_result:
            self.logger.warning(f"Could not retrieve EXPLAIN ANALYZE plan for query: {sql_query[:100]}...")
            return
        
        plan_text = "\n".join(str(row[0]) for row in plan_result)
        
        # --- Corpus Evolution Check ---
        self._check_for_new_plan_structure(sql_query, plan_text)

        # Run Cardinality Estimation check
        if self.oracle_config.get('enable_cert', False):
            self.logger.debug("Running CERT check...")
            self._run_cert_check(sql_query, plan_text)
            
        # Run Differential Query Plan check
        if self.oracle_config.get('enable_dqp', False):
            self.logger.debug("Running DQP check...")
            self._run_dqp_check(sql_query)

        # Run Constant Optimization check
        if self.oracle_config.get('enable_coddtest', False):
            self.logger.debug("Running CODDTest check...")
            self._run_codd_check(sql_query)

    def _normalize_plan(self, plan_text: str) -> str:
        """
        Normalizes a query plan by removing volatile details like costs,
        times, and memory usage, leaving only the structural information.
        """
        plan_text = re.sub(r'cost=[\d\.]+\.\.[\d\.]+', '', plan_text)
        plan_text = re.sub(r'rows=\d+', '', plan_text)
        plan_text = re.sub(r'width=\d+', '', plan_text)
        plan_text = re.sub(r'actual time=[\d\.]+\.\.[\d\.]+', '', plan_text)
        plan_text = re.sub(r'Memory: \w+', '', plan_text)
        plan_text = re.sub(r'Buckets: \d+', '', plan_text)
        plan_text = re.sub(r'fuzz_table_\d+_\d+', 'fuzz_table', plan_text)
        return " ".join(plan_text.split())

    def _save_to_evolved_corpus(self, sql_query: str, reason: str):
        """Saves an interesting query to the evolved corpus directory."""
        if not self.evo_config.get('enabled', False) or not self.evo_dir:
            return
        
        try:
            query_hash = hashlib.sha256(sql_query.encode()).hexdigest()
            filepath = os.path.join(self.evo_dir, f"{query_hash}.sql")
            
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write(f"-- Reason: {reason}\n")
                    f.write(sql_query)
                self.logger.info(f"Saved new interesting query to corpus: {reason}")
        except Exception as e:
            self.logger.error(f"Failed to save query to evolved corpus: {e}")

    def _check_for_new_plan_structure(self, sql_query: str, plan_text: str):
        """Checks if the query produced a previously unseen plan structure."""
        normalized_plan = self._normalize_plan(plan_text)
        if normalized_plan not in self.seen_plan_structures:
            self.seen_plan_structures.add(normalized_plan)
            self._save_to_evolved_corpus(sql_query, "Discovered new query plan structure")

    def _parse_plan_for_rows(self, plan_text: str) -> list[tuple[int, int]]:
        """Parses EXPLAIN ANALYZE output for estimated vs actual rows."""
        row_estimates = []
        for line in plan_text.split('\n'):
            match = re.search(r'rows=(\d+).*actual.*rows=(\d+)', line)
            if match:
                estimated = int(match.group(1))
                actual = int(match.group(2))
                row_estimates.append((estimated, actual))
        return row_estimates

    def _run_cert_check(self, sql_query: str, plan_text: str):
        """Cardinality Estimation Restriction Testing (CERT)."""
        row_estimates = self._parse_plan_for_rows(plan_text)
        threshold = self.oracle_config.get('cert_threshold', 100)

        for estimated, actual in row_estimates:
            if actual > 0 and estimated > 0 and ((estimated / actual > threshold) or (actual / estimated > threshold)):
                self.reporter.report_bug(
                    oracle_name=self.name,
                    bug_type="CERT - Cardinality Misestimation",
                    description=f"Optimizer misestimated row count by more than {threshold}x.",
                    original_query=sql_query,
                    estimated_rows=estimated,
                    actual_rows=actual,
                    full_plan=plan_text
                )
                break

    def _run_dqp_check(self, sql_query: str):
        """Differential Query Plans (DQP) by creating a temporary index."""
        match = re.search(r'WHERE\s+"([^"]+)"\s*=', sql_query, re.IGNORECASE)
        if not match: return
        
        column_to_index = match.group(1)
        table_match = re.search(r'FROM\s+([^\s]+)', sql_query, re.IGNORECASE)
        if not table_match: return
        table_name_with_schema = table_match.group(1)
        
        index_name = f"ybfuzz_temp_idx_{int(time.time())}"

        original_plan_res, _ = self.executor.execute_query(f"EXPLAIN {sql_query}")
        if not original_plan_res: return
        original_plan = "\n".join(row[0] for row in original_plan_res)

        setup_sqls = [f"CREATE INDEX {index_name} ON {table_name_with_schema} (\"{column_to_index}\");"]
        teardown_sqls = [f"DROP INDEX IF EXISTS {index_name};"]
        new_plan_res, exc = self.executor.execute_query_with_setup(setup_sqls, f"EXPLAIN {sql_query}", teardown_sqls)
        if exc or not new_plan_res: return
        
        new_plan = "\n".join(row[0] for row in new_plan_res)

        if "Index Scan" not in new_plan and "Seq Scan" in original_plan:
            self.reporter.report_bug(
                oracle_name=self.name,
                bug_type="DQP - No Plan Change",
                description=f"Optimizer did not use a newly created, relevant index on column '{column_to_index}'.",
                original_query=sql_query,
                original_plan=original_plan,
                new_plan_after_index=new_plan
            )

    def _run_codd_check(self, sql_query: str):
        """Constant Optimization Driven Testing (CODDTest)."""
        match = re.search(r'(WHERE\s+.*[=\s><])(\d+\.?\d*)', sql_query, re.IGNORECASE)
        if not match: return

        prefix = match.group(1)
        original_literal = match.group(2)
        
        new_literal = str(float(original_literal) + random.uniform(1, 10))
        variant_query = sql_query.replace(f"{prefix}{original_literal}", f"{prefix}{new_literal}", 1)

        original_plan_res, _ = self.executor.execute_query(f"EXPLAIN {sql_query}")
        variant_plan_res, _ = self.executor.execute_query(f"EXPLAIN {variant_query}")
        if not original_plan_res or not variant_plan_res: return

        normalize = lambda plan: [re.sub(r'\(cost=.*\)', '', line) for line in plan]
        original_plan_structure = normalize([row[0] for row in original_plan_res])
        variant_plan_structure = normalize([row[0] for row in variant_plan_res])

        if original_plan_structure != variant_plan_structure:
            self.reporter.report_bug(
                oracle_name=self.name,
                bug_type="CODDTest - Unstable Plan",
                description="Query plan structure changed unexpectedly for a minor change in a literal constant.",
                original_query=sql_query,
                variant_query=variant_query,
                original_plan="\n".join(row[0] for row in original_plan_res),
                variant_plan="\n".join(row[0] for row in variant_plan_res)
            )
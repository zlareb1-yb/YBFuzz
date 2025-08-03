# This is the definitive, complete, and optimized version of the fuzzer engine.
# It is re-architected to support stateful fuzzing sessions and correctly
# integrates the hybrid generative/mutational engine for all phases of testing.

import logging
import random
import time
import os
from config import FuzzerConfig
from core.grammar import Grammar
from core.generator import GrammarGenerator, SQLNode
from core.mutator import Mutator
from utils.db_executor import DBExecutor
from utils.bug_reporter import BugReporter
from oracles.base_oracle import BaseOracle
from oracles.tlp_oracle import TLOracle
from oracles.qpg_oracle import QPGOracle

class FuzzerEngine:
    """The main stateful fuzzing engine."""

    def __init__(self, config: FuzzerConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        random.seed(self.config.get('random_seed'))

        self.bug_reporter = BugReporter(config)
        self.db_executor = DBExecutor(config.get_db_config(), self.bug_reporter, config)
        self.bug_reporter.set_db_executor(self.db_executor)
        
        self.grammar = Grammar(config.get('grammar_file'))
        self.generator = GrammarGenerator(self.grammar.get_rules(), config, self.db_executor.catalog)
        self.mutator = Mutator(config, self.db_executor.catalog)
        
        self.oracles: list[BaseOracle] = self._load_oracles()
        self.logger.info(f"Registered {len(self.oracles)} active oracles: {[o.__class__.__name__ for o in self.oracles]}")

        # Setup for Corpus Evolution
        self._setup_corpus_evolution()

    def _load_oracles(self) -> list[BaseOracle]:
        """Instantiates and registers all bug-finding oracles based on config."""
        oracles = []
        oracle_configs = self.config.get('oracles', {})
        available_oracles = {"TLOracle": TLOracle, "QPGOracle": QPGOracle}
        for name, oracle_class in available_oracles.items():
            if oracle_configs.get(name, {}).get('enabled', False):
                oracles.append(oracle_class(self.db_executor, self.bug_reporter, self.config))
        return oracles

    def _setup_corpus_evolution(self):
        """Creates the directory for the evolved corpus if enabled."""
        evo_config = self.config.get('corpus_evolution', {})
        if evo_config.get('enabled', False):
            directory = evo_config.get('directory')
            if directory:
                os.makedirs(directory, exist_ok=True)
                self.logger.info(f"Corpus Evolution enabled. Interesting queries will be saved to '{directory}'.")

    def run(self):
        """The main fuzzing loop, now structured around sessions."""
        start_time = time.time()
        session_count = 0
        max_sessions = self.config.get('max_sessions')
        duration = self.config.get('duration')

        while True:
            if time.time() - start_time > duration:
                self.logger.info("Duration limit reached.")
                break
            if session_count >= max_sessions:
                self.logger.info("Session limit reached.")
                break
            
            session_count += 1
            self.logger.info(f"========== Starting Fuzzing Session #{session_count} ==========")
            self._setup_database() # Reset DB for each session for isolation

            # --- Execute Stateful Session ---
            self._run_session_phase('ddl_statements', 'ddl_statement')
            self._run_session_phase('dml_statements', 'dml_statement')
            
            # --- Final Validation Phase ---
            self.logger.info("--- Session Phase: Final Validation SELECT ---")
            
            # Use the hybrid engine for the final SELECT as well
            final_sql, final_ast_node = self._get_next_query('select_stmt')

            if not final_sql:
                self.logger.warning("Failed to produce a final SELECT statement for validation.")
                continue

            result, exception = self.db_executor.execute_query(final_sql)

            for oracle in self.oracles:
                try:
                    # Pass the AST node if we have it, otherwise the raw SQL
                    if oracle.can_check(final_ast_node if final_ast_node else final_sql, exception):
                        oracle.check(final_ast_node if final_ast_node else final_sql, result, exception)
                except Exception as e:
                    self.logger.error(f"Oracle '{oracle.__class__.__name__}' crashed: {e}", exc_info=True)

        self.db_executor.close()

    def _get_next_query(self, grammar_rule: str) -> tuple[str | None, SQLNode | None]:
        """
        Uses the hybrid engine to get the next query, either by generation
        or mutation. Returns the SQL string and the AST node (if available).
        """
        mutation_prob = self.config.get('engine_strategy', {}).get('mutation_probability', 0.5)
        
        if random.random() < mutation_prob and self.mutator.has_corpus():
            self.logger.debug(f"Strategy: Mutation for '{grammar_rule}'")
            # The mutator returns a raw SQL string, so no AST node.
            return self.mutator.mutate(), None
        else:
            self.logger.debug(f"Strategy: Generation for '{grammar_rule}'")
            stmt_node = self.generator.generate_statement_of_type(grammar_rule)
            if stmt_node:
                return stmt_node.to_sql(), stmt_node
        
        return None, None

    def _run_session_phase(self, config_key: str, grammar_rule: str):
        """Runs a phase of the session (e.g., DDL, DML) using the hybrid engine."""
        session_config = self.config.get('session_strategy', {})
        min_stmts, max_stmts = session_config.get(config_key, [0, 0])
        num_stmts = random.randint(min_stmts, max_stmts)
        
        self.logger.info(f"--- Session Phase: {grammar_rule} (Target: {num_stmts} statements) ---")
        for i in range(num_stmts):
            sql_query, _ = self._get_next_query(grammar_rule)
            
            if sql_query:
                self.db_executor.execute_query(sql_query)
                # Refresh catalog after every DDL change to stay aware of the new state
                if grammar_rule == 'ddl_statement':
                    self.db_executor.catalog.refresh()
            else:
                self.logger.warning(f"Failed to produce a '{grammar_rule}' statement for this step.")

    def _setup_database(self):
        """Prepares the database schema for a fuzzing run."""
        schema_name = self.config.get('database')['schema_name']
        self.db_executor.execute_admin(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE;")
        self.db_executor.execute_admin(f"CREATE SCHEMA {schema_name};")
        initial_setup_sqls = self.config.get('initial_db_setup_sqls', [])
        for sql in initial_setup_sqls:
            self.db_executor.execute_admin(sql.replace('$$schema$$', schema_name))
        self.db_executor.catalog.refresh()
# This is the definitive, complete, and optimized version of the fuzzer engine.
# It includes robust statistics reporting, graceful shutdown handling, and
# dynamic oracle loading for a world-class operator experience.

import logging
import random
import time
import os
import sys
import signal
import pkgutil
import inspect
from config import FuzzerConfig
from core.grammar import Grammar
from core.generator import GrammarGenerator, SQLNode
from core.mutator import Mutator
from utils.db_executor import DBExecutor
from utils.bug_reporter import BugReporter
from oracles.base_oracle import BaseOracle

class FuzzerEngine:
    """The main stateful fuzzing engine."""

    def __init__(self, config: FuzzerConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        random.seed(self.config.get('random_seed'))

        # --- Core Components ---
        self.bug_reporter = BugReporter(config)
        self.db_executor = DBExecutor(config.get_db_config(), self.bug_reporter, config)
        
        self.grammar = Grammar(config.get('grammar_file'))
        self.generator = GrammarGenerator(self.grammar.get_rules(), config, self.db_executor.catalog)
        self.mutator = Mutator(config, self.db_executor.catalog)
        
        # --- State Management ---
        self.stats = {"sessions": 0, "queries": 0, "bugs": 0, "start_time": time.time()}
        self.shutdown_requested = False
        
        # --- Dynamic Loading and Setup ---
        self.oracles: list[BaseOracle] = self._load_oracles()
        self.logger.info(f"Registered {len(self.oracles)} active oracles: {[o.__class__.__name__ for o in self.oracles]}")
        self._setup_output_dirs()

    def _load_oracles(self) -> list[BaseOracle]:
        """Dynamically discovers and instantiates all oracle classes from the oracles package."""
        self.logger.debug("Dynamically loading oracles...")
        oracle_list = []
        oracle_configs = self.config.get('oracles', {})
        
        # Dynamically import all modules in the 'oracles' package
        import oracles
        for _, modname, _ in pkgutil.iter_modules(oracles.__path__):
            module = __import__(f"oracles.{modname}", fromlist="dummy")
            for name, obj in inspect.getmembers(module, inspect.isclass):
                # Add any class that inherits from BaseOracle but is not BaseOracle itself
                if issubclass(obj, BaseOracle) and obj is not BaseOracle:
                    if oracle_configs.get(name, {}).get('enabled', False):
                        oracle_list.append(obj(self.db_executor, self.bug_reporter, self.config))
                        self.logger.info(f"Oracle '{name}' is ENABLED.")
                    else:
                        self.logger.info(f"Oracle '{name}' is DISABLED.")
        return oracle_list

    def _setup_output_dirs(self):
        """Creates directories for corpus evolution and bug reproductions."""
        evo_config = self.config.get('corpus_evolution', {});
        if evo_config.get('enabled', False):
            directory = evo_config.get('directory')
            if directory: os.makedirs(directory, exist_ok=True)
        
        # Create bug reproductions directory
        bug_config = self.config.get('bug_reporting', {})
        if bug_config.get('enabled', False):
            repro_dir = bug_config.get('reproduction_dir', 'bug_reproductions')
            os.makedirs(repro_dir, exist_ok=True)

    def _handle_shutdown_signal(self, signum, frame):
        """Catches Ctrl+C and requests a graceful shutdown."""
        if not self.shutdown_requested:
            self.logger.warning("\nShutdown signal received. Finishing current session, then exiting.")
            self.shutdown_requested = True

    def run(self):
        """The main fuzzing loop with improved logic and state management."""
        signal.signal(signal.SIGINT, self._handle_shutdown_signal)
        
        try:
            self._setup_database()
            start_time = time.time()
            max_sessions = self.config.get('max_sessions')
            duration = self.config.get('duration')

            while not self.shutdown_requested:
                if time.time() - start_time > duration: self.logger.info("Duration limit reached."); break
                if self.stats["sessions"] >= max_sessions: self.logger.info("Session limit reached."); break
                
                self.stats["sessions"] += 1
                self.logger.info(f"========== Starting Fuzzing Session #{self.stats['sessions']} ==========")
                
                self._run_session_phase('ddl_statements', 'ddl_statement')
                self._run_session_phase('dml_statements', 'dml_statement')
                self._run_validation_phase()

                if self.stats["sessions"] % 10 == 0:
                    self._log_progress_stats()

        except Exception as e:
            self.logger.critical(f"A critical error forced the engine to stop: {e}", exc_info=True)
        finally:
            self._report_final_stats()
            self.db_executor.close()

    def _run_validation_phase(self):
        """Generates and validates the final SELECT statement of a session."""
        self.logger.info("--- Session Phase: Final Validation SELECT ---")
        final_sql, final_ast_node = self._get_next_query('select_stmt')
        if not final_sql: self.logger.warning("Failed to produce a final SELECT statement."); return

        result, exception = self.db_executor.execute_query(final_sql)
        self.stats["queries"] += 1

        for oracle in self.oracles:
            try:
                if oracle.can_check(final_ast_node or final_sql, exception):
                    oracle.check(final_ast_node or final_sql, result, exception)
            except Exception as e:
                self.logger.error(f"Oracle '{oracle.__class__.__name__}' crashed: {e}", exc_info=True)

    def _get_next_query(self, grammar_rule: str) -> tuple[str | None, SQLNode | None]:
        mutation_prob = self.config.get('engine_strategy', {}).get('mutation_probability', 0.5)
        if random.random() < mutation_prob and self.mutator.has_corpus():
            self.logger.debug(f"Strategy: Mutation for '{grammar_rule}'")
            return self.mutator.mutate(), None
        else:
            self.logger.debug(f"Strategy: Generation for '{grammar_rule}'")
            stmt_node = self.generator.generate_statement_of_type(grammar_rule)
            if stmt_node: return stmt_node.to_sql(), stmt_node
        return None, None

    def _run_session_phase(self, config_key: str, grammar_rule: str):
        session_config = self.config.get('session_strategy', {}); min_stmts, max_stmts = session_config.get(config_key, [0, 0]); num_stmts = random.randint(min_stmts, max_stmts)
        self.logger.info(f"--- Session Phase: {grammar_rule} (Target: {num_stmts} statements) ---")
        for i in range(num_stmts):
            if self.shutdown_requested: break
            sql_query, _ = self._get_next_query(grammar_rule)
            if sql_query:
                self.db_executor.execute_query(sql_query); self.stats["queries"] += 1
                if grammar_rule == 'ddl_statement': self.db_executor.catalog.refresh()
            else: self.logger.warning(f"Failed to produce a '{grammar_rule}' statement.")

    def _setup_database(self):
        """Sets up the initial database schema and tables for fuzzing."""
        self.logger.info("Setting up database schema and initial tables...")
        schema_name = self.config.get_db_config()['schema_name']
        
        # Drop and recreate the schema
        self.db_executor.execute_admin(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE;")
        self.db_executor.execute_admin(f"CREATE SCHEMA {schema_name};")
        
        # Execute initial setup SQL commands
        initial_setup_sqls = self.config.get('initial_db_setup_sqls', [])
        for sql in initial_setup_sqls:
            sql_with_schema = sql.replace('$$schema$$', schema_name)
            self.db_executor.execute_admin(sql_with_schema)
        
        # Refresh the catalog to discover the new schema
        self.db_executor.catalog.refresh()
        self.logger.info(f"Database setup complete. Schema '{schema_name}' ready for fuzzing.")

    def _log_progress_stats(self):
        """Logs a periodic summary of the fuzzer's progress."""
        elapsed_time = time.time() - self.stats["start_time"]
        qps = self.stats["queries"] / elapsed_time if elapsed_time > 0 else 0
        bug_summary = self.bug_reporter.get_bug_summary()
        self.stats["bugs"] = bug_summary.get('total_bugs', 0)
        self.logger.info(
            f"Progress: {self.stats['sessions']} sessions | "
            f"{self.stats['queries']} queries ({qps:.2f} q/s) | "
            f"{self.stats['bugs']} unique bugs found."
        )

    def _report_final_stats(self):
        """Logs a final summary at the end of the fuzzing run."""
        self.logger.info("========== Fuzzing Run Summary ==========")
        
        # Get bug summary from bug reporter
        bug_summary = self.bug_reporter.get_bug_summary()
        total_bugs = bug_summary.get('total_bugs', 0)
        
        self.logger.info(f"Progress: {self.stats['sessions']} sessions | {self.stats['queries']} queries ({self.stats['queries'] / max(1, time.time() - self.stats['start_time']):.2f} q/s) | {total_bugs} unique bugs found.")
        
        if total_bugs > 0:
            self.logger.info(f"Bug Types: {', '.join([f'{k} ({v})' for k, v in bug_summary.get('bug_types', {}).items()])}")
            self.logger.info(f"Detailed reproduction files: {bug_summary.get('reproduction_dir', 'bug_reproductions')}/")
            
            # Create bug summary report
            self.bug_reporter.create_bug_report_summary()
        
        self.logger.info("=========================================")
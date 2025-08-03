# This is the central orchestrator of the fuzzing process. This optimized
# version includes more robust initialization, graceful shutdown logic,
# dynamic oracle loading, and a clearer, more insightful main fuzzing loop.

import logging
import random
import time
import sys
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
    """
    The main fuzzing engine. It orchestrates the entire fuzzing lifecycle,
    from setup and query generation to execution and validation by oracles.
    """

    def __init__(self, config: FuzzerConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        random.seed(self.config.get('random_seed'))

        # --- Robust Initialization and Dependency Injection ---
        self.bug_reporter = BugReporter(config)
        self.db_executor = DBExecutor(config.get_db_config(), self.bug_reporter)
        
        # Post-initialization dependency wiring to avoid circular imports
        # The BugReporter needs the DBExecutor to access query history.
        self.bug_reporter.set_db_executor(self.db_executor)
        
        # Setup grammar and the two main fuzzing engines
        self.grammar = Grammar(self.config.get('grammar_file'))
        self.generator = GrammarGenerator(self.grammar.get_rules(), self.config, self.db_executor.catalog)
        self.mutator = Mutator(self.config, self.db_executor.catalog)
        
        # Dynamically load oracles based on configuration
        self.oracles: list[BaseOracle] = self._load_oracles()
        self.logger.info(f"Registered {len(self.oracles)} active oracles: {[o.__class__.__name__ for o in self.oracles]}")


    def _load_oracles(self) -> list[BaseOracle]:
        """Instantiates and registers all bug-finding oracles based on config."""
        self.logger.debug("Dynamically loading oracles based on configuration...")
        oracles = []
        oracle_configs = self.config.get('oracles', {})
        
        # A map of oracle names to their classes for easy extension
        available_oracles = {
            "TLOracle": TLOracle,
            "QPGOracle": QPGOracle
        }

        for name, oracle_class in available_oracles.items():
            if oracle_configs.get(name, {}).get('enabled', False):
                oracles.append(oracle_class(self.db_executor, self.bug_reporter, self.config))
                self.logger.info(f"Oracle '{name}' is ENABLED.")
            else:
                self.logger.info(f"Oracle '{name}' is DISABLED.")
            
        return oracles

    def _setup_database(self):
        """Prepares the database schema for a fuzzing run."""
        self.logger.info("Setting up database schema for fuzzing run...")
        schema_name = self.config.get('database')['schema_name']
        self.db_executor.execute_admin(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE;")
        self.db_executor.execute_admin(f"CREATE SCHEMA {schema_name};")
        
        # Create and populate initial tables
        initial_setup_sqls = self.config.get('initial_db_setup_sqls', [])
        for sql in initial_setup_sqls:
             self.db_executor.execute_admin(sql.replace('$$schema$$', schema_name))
        
        self.db_executor.catalog.refresh()
        self.logger.info("Database setup complete.")

    def run(self):
        """The main fuzzing loop with improved logic and state management."""
        self._setup_database()
        
        start_time = time.time()
        query_count = 0
        max_queries = self.config.get('max_queries')
        duration = self.config.get('duration')
        dry_run = self.config.get('dry_run', False)

        try:
            while True:
                # Check exit conditions
                if time.time() - start_time > duration:
                    self.logger.info("Fuzzing run finished: duration limit reached."); break
                if query_count >= max_queries:
                    self.logger.info("Fuzzing run finished: query limit reached."); break
                
                query_count += 1
                sql_query = None
                
                # --- Hybrid Engine Strategy ---
                mutation_prob = self.config.get('engine_strategy', {}).get('mutation_probability', 0.5)
                if random.random() < mutation_prob and self.mutator.has_corpus():
                    self.logger.info(f"--- Iteration #{query_count} (Strategy: Mutation) ---")
                    sql_query = self.mutator.mutate()
                else:
                    self.logger.info(f"--- Iteration #{query_count} (Strategy: Generation) ---")
                    statement_node = self.generator.generate_statement()
                    if statement_node:
                        sql_query = statement_node.to_sql()

                if not sql_query:
                    self.logger.warning("Failed to produce a query for this iteration.")
                    continue
                
                if dry_run:
                    print(f"\n[DRY RUN] Generated Query:\n{sql_query}\n")
                    continue

                # --- Execution and Validation ---
                result, exception = self.db_executor.execute_query(sql_query)

                # Pass the raw SQL string to oracles, as we may not have an AST for mutated queries
                for oracle in self.oracles:
                    try:
                        # Oracles can handle either raw SQL or an AST node if available
                        oracle.check(statement_node if 'statement_node' in locals() else sql_query, result, exception)
                    except Exception as e:
                        self.logger.error(f"Oracle '{oracle.__class__.__name__}' crashed: {e}", exc_info=True)

                # Periodically refresh the catalog to learn about DDL changes
                if query_count % self.config.get('catalog_refresh_interval', 20) == 0:
                    self.db_executor.catalog.refresh()
        
        finally:
            # --- Graceful Shutdown ---
            self.logger.info("Fuzzing loop concluded. Shutting down resources.")
            self.db_executor.close()
# A centralized module for formatting and logging detected bugs.
# This optimized version provides structured JSON output, automatic
# bug deduplication, and captures rich historical context to make
# bug reproduction and analysis trivial. It also integrates with the
# DeltaReducer to automatically minimize failing test cases.

import logging
import json
import os
import hashlib
from config import FuzzerConfig
# We use a forward declaration for type hinting to avoid circular imports
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .db_executor import DBExecutor
    from reducer.delta_reducer import DeltaReducer


class BugReporter:
    """
    Handles the formatting, deduplication, and logging of discovered bugs,
    and contributes bug-triggering queries to the evolved corpus.
    """

    def __init__(self, config: FuzzerConfig):
        self.config = config
        self.bug_log_file = config.get('bug_report_file')
        self.seed = config.get('random_seed')
        self.db_executor = None # Will be set post-initialization
        
        # --- State for Optimizations ---
        self._reported_bugs = set() # For bug deduplication
        self._setup_bug_logger()
        
        # --- Config for Corpus Evolution ---
        self.evo_config = self.config.get('corpus_evolution', {})
        self.evo_dir = self.evo_config.get('directory')
        
        # --- Reducer instance and config ---
        self.reducer: 'DeltaReducer' | None = None
        self.reducer_enabled = self.config.get('reducer', {}).get('enabled', False)

    def set_db_executor(self, executor: 'DBExecutor'):
        """
        Sets the DBExecutor instance and initializes the reducer which depends on it.
        This is called after all core components are initialized to prevent
        circular dependencies.
        """
        self.db_executor = executor
        if self.reducer_enabled:
            # Late import to prevent circular dependency
            from reducer.delta_reducer import DeltaReducer
            self.reducer = DeltaReducer(self.db_executor, self)

    def _setup_bug_logger(self):
        """Sets up a dedicated logger for structured bug reports."""
        self.bug_logger = logging.getLogger('BugReporter')
        self.bug_logger.setLevel(logging.ERROR)
        self.bug_logger.propagate = False
        
        if not self.bug_logger.handlers:
            handler = logging.FileHandler(self.bug_log_file, mode='w') # Start fresh for each run
            # Use a formatter that only outputs the message, as we are logging pre-formatted JSON
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            self.bug_logger.addHandler(handler)

    def _get_bug_signature(self, bug_type: str, exception: Exception | None) -> str:
        """
        Creates a unique signature for a bug to enable deduplication.
        A simple signature is based on the bug type and the exception message,
        ignoring specific object IDs or memory addresses.
        """
        # Take only the first line of the exception to avoid noise from stack traces
        error_message = str(exception).splitlines()[0] if exception else "N/A"
        return f"{bug_type}|{error_message}"

    def _save_to_evolved_corpus(self, sql_query: str, reason: str):
        """Saves an interesting query to the evolved corpus directory."""
        if not self.evo_config.get('enabled', False) or not self.evo_dir:
            return
        
        try:
            # Use a hash of the query as the filename to avoid duplicates
            query_hash = hashlib.sha256(sql_query.encode()).hexdigest()
            filepath = os.path.join(self.evo_dir, f"{query_hash}.sql")
            
            if not os.path.exists(filepath):
                with open(filepath, 'w') as f:
                    f.write(f"-- Reason: {reason}\n")
                    f.write(sql_query)
                logging.getLogger(self.__class__.__name__).info(f"Saved interesting query to corpus: {reason}")
        except Exception as e:
            logging.getLogger(self.__class__.__name__).error(f"Failed to save query to evolved corpus: {e}")

    def report_bug(self, oracle_name: str, bug_type: str, description: str, **kwargs):
        """
        Formats and logs a detailed bug report. If enabled, it will first
        attempt to minimize the failing query.
        """
        exception = kwargs.get('exception')
        signature = self._get_bug_signature(bug_type, exception)

        if signature in self._reported_bugs:
            logging.getLogger(self.__class__.__name__).debug(f"Duplicate bug found and ignored: {signature}")
            return # This is a duplicate, so we don't log it again.

        # This is a new bug, so we add it to our set and log it.
        self._reported_bugs.add(signature)
        
        triggering_query = kwargs.get('original_query') or kwargs.get('query')
        
        # --- Run the reducer before reporting ---
        minimized_query = None
        if self.reducer and triggering_query and exception:
            minimized_query = self.reducer.reduce(triggering_query, signature)
            kwargs['minimized_query'] = minimized_query
            # Save the minimized query to the corpus for future mutations
            self._save_to_evolved_corpus(minimized_query, f"Triggered and minimized bug: {bug_type}")
        elif triggering_query:
            # If reducer is not active, still save the original bug-triggering query
            self._save_to_evolved_corpus(triggering_query, f"Triggered bug: {bug_type}")
        
        # --- Build Rich Context for the Report ---
        
        # Safely convert exception and other non-serializable objects to strings
        for key, value in kwargs.items():
            if isinstance(value, Exception):
                kwargs[key] = str(value)
        
        # Get recent query history for context
        query_history = []
        if self.db_executor and hasattr(self.db_executor, 'query_history'):
            # Safely slice the last 10 queries, excluding the current one
            history_slice = self.db_executor.query_history[-11:-1] if len(self.db_executor.query_history) > 1 else []
            query_history = history_slice

        bug_report = {
            "oracle": oracle_name,
            "bug_type": bug_type,
            "seed": self.seed,
            "description": description,
            "context": kwargs,
            "query_history": query_history
        }

        # Log the structured report as a single line of JSON
        try:
            json_report = json.dumps(bug_report, indent=None) # indent=None for single line
            self.bug_logger.error(json_report)
        except TypeError as e:
            # Fallback for unserializable objects
            logging.getLogger(self.__class__.__name__).error(f"Failed to serialize bug report to JSON: {e}. Logging as string.")
            self.bug_logger.error(str(bug_report))

        # Also log a notification to the main console/log
        logging.error(f"!!! NEW BUG FOUND by {oracle_name}! Type: {bug_type}. See {self.bug_log_file} for details. !!!")

# A centralized module for formatting and logging detected bugs.
# This optimized version provides structured JSON output, automatic
# bug deduplication, and captures rich historical context to make
# bug reproduction and analysis trivial.

import logging
import json
from config import FuzzerConfig
# We use a forward declaration for type hinting to avoid circular imports
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .db_executor import DBExecutor


class BugReporter:
    """
    Handles the formatting, deduplication, and logging of discovered bugs.
    """

    def __init__(self, config: FuzzerConfig):
        self.config = config
        self.bug_log_file = config.get('bug_report_file')
        self.seed = config.get('random_seed')
        self.db_executor = None # Will be set post-initialization
        
        # --- Optimizations ---
        self._reported_bugs = set() # For bug deduplication
        self._setup_bug_logger()

    def set_db_executor(self, executor: 'DBExecutor'):
        """
        Sets the DBExecutor instance to allow access to query history.
        This is called after all core components are initialized to prevent
        circular dependencies.
        """
        self.db_executor = executor

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
        error_message = str(exception).split('\n')[0] if exception else "N/A"
        return f"{bug_type}|{error_message}"

    def report_bug(self, oracle_name: str, bug_type: str, description: str, **kwargs):
        """
        Formats and logs a detailed bug report if it hasn't been seen before.

        Args:
            oracle_name: The name of the oracle that found the bug.
            bug_type: A specific type for the bug (e.g., "NoREC - Inconsistent Results").
            description: A human-readable description of the bug.
            **kwargs: Any additional context (original_query, variant_query, etc.).
        """
        exception = kwargs.get('exception')
        signature = self._get_bug_signature(bug_type, exception)

        if signature in self._reported_bugs:
            logging.getLogger(self.__class__.__name__).debug(f"Duplicate bug found and ignored: {signature}")
            return # This is a duplicate, so we don't log it again.

        # This is a new bug, so we add it to our set and log it.
        self._reported_bugs.add(signature)
        
        # --- Build Rich Context for the Report ---
        
        # Safely convert exception to string
        kwargs['exception'] = str(exception) if exception else None
        
        # Get recent query history for context
        query_history = []
        if self.db_executor:
            # Get the last 10 queries, excluding the current one if it's in kwargs
            history_slice = self.db_executor.query_history[-11:-1] if self.db_executor.query_history else []
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
            self.logger.error(f"Failed to serialize bug report to JSON: {e}")

        # Also log a notification to the main console/log
        logging.error(f"!!! NEW BUG FOUND by {oracle_name}! Type: {bug_type}. See {self.bug_log_file} for details. !!!")

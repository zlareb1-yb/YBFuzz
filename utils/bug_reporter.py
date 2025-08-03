# A centralized module for formatting and logging detected bugs.
# This definitive version provides structured JSON output, automatic
# bug deduplication, test case reduction, sanitizer awareness, and
# generates SQLLogicTest regression tests for every bug.

import logging
import json
import os
import re
import hashlib
from config import FuzzerConfig
# We use a forward declaration for type hinting to avoid circular imports
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from .db_executor import DBExecutor
    from reducer.delta_reducer import DeltaReducer
from .sqllogictest_formatter import SQLLogicTestFormatter


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

        # --- Sanitizer Configuration ---
        self.sanitizer_config = self.config.get('sanitizer', {})
        self.sanitizer_type = self.sanitizer_config.get('type')
        self.sanitizer_log_path = self.sanitizer_config.get('log_file_path')
        self.logger = logging.getLogger(self.__class__.__name__)

        # --- SQLLogicTest Formatter ---
        self.sqllogic_config = self.config.get('sqllogictest_formatter', {})
        self.sqllogic_formatter = None
        if self.sqllogic_config.get('enabled', False):
            self.sqllogic_formatter = SQLLogicTestFormatter(self.config)


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
        """
        # Take only the first line of the exception to avoid noise from stack traces
        error_message = str(exception).splitlines()[0] if exception else "N/A"
        return f"{bug_type}|{error_message}"

    def _scan_log_for_sanitizer_error(self) -> str | None:
        """Scans the DB log file for sanitizer error messages."""
        if not self.sanitizer_type or not self.sanitizer_log_path:
            return None
        
        try:
            with open(self.sanitizer_log_path, 'r') as f:
                content = f.read()
            
            # Look for common sanitizer error patterns
            asan_match = re.search(r'==\d+==ERROR: AddressSanitizer: ([\w-]+)', content)
            if asan_match:
                return f"{self.sanitizer_type} - {asan_match.group(1)}"
            
            # Add patterns for TSan, UBSan, etc. here
            
        except FileNotFoundError:
            self.logger.warning(f"Sanitizer log file not found at '{self.sanitizer_log_path}'.")
        except Exception as e:
            self.logger.error(f"Error reading sanitizer log file: {e}")
            
        return None

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
                self.logger.info(f"Saved interesting query to corpus: {reason}")
        except Exception as e:
            self.logger.error(f"Failed to save query to evolved corpus: {e}")

    def _save_sqllogic_test(self, test_content: str, signature: str):
        """Saves a generated SQLLogicTest file."""
        if not self.sqllogic_formatter:
            return
            
        output_dir = self.sqllogic_config.get('output_directory')
        if not output_dir:
            self.logger.warning("SQLLogicTest formatter is enabled, but no output_directory is configured.")
            return

        try:
            # Use a hash of the signature for a stable filename
            signature_hash = hashlib.sha256(signature.encode()).hexdigest()[:16]
            filename = f"bug_{signature_hash}.test"
            filepath = os.path.join(output_dir, filename)
            
            with open(filepath, 'w') as f:
                f.write(test_content)
            self.logger.info(f"Generated SQLLogicTest regression test: {filepath}")
        except Exception as e:
            self.logger.error(f"Failed to save SQLLogicTest file: {e}")

    def report_bug(self, oracle_name: str, bug_type: str, description: str, **kwargs):
        """
        Formats and logs a detailed bug report. If a crash occurs, it will
        check for sanitizer output to enrich the report.
        """
        exception = kwargs.get('exception')
        
        # Check for Sanitizer Errors on Critical Failures
        is_crash = "Critical Database Error" in bug_type
        if is_crash:
            sanitizer_bug_type = self._scan_log_for_sanitizer_error()
            if sanitizer_bug_type:
                bug_type = sanitizer_bug_type
                description = f"A critical crash was detected and sanitizer output was found. {description}"

        signature = self._get_bug_signature(bug_type, exception)

        if signature in self._reported_bugs:
            self.logger.debug(f"Duplicate bug found and ignored: {signature}")
            return

        self._reported_bugs.add(signature)
        
        triggering_query = kwargs.get('original_query') or kwargs.get('query')
        
        # Run the reducer before reporting
        minimized_query = None
        if self.reducer and triggering_query and exception:
            minimized_query = self.reducer.reduce(triggering_query, signature)
            kwargs['minimized_query'] = minimized_query
            self._save_to_evolved_corpus(minimized_query, f"Triggered and minimized bug: {bug_type}")
        elif triggering_query:
            self._save_to_evolved_corpus(triggering_query, f"Triggered bug: {bug_type}")
        
        # Generate SQLLogicTest file
        query_for_test = minimized_query or triggering_query
        if self.sqllogic_formatter and query_for_test and exception:
            test_content = self.sqllogic_formatter.format_error_test(query_for_test, exception)
            self._save_sqllogic_test(test_content, signature)
        
        # Build Rich Context for the Report
        kwargs['exception'] = str(exception) if exception else None
        query_history = self.db_executor.query_history[-11:-1] if self.db_executor else []
        
        bug_report = {
            "oracle": oracle_name,
            "bug_type": bug_type,
            "seed": self.seed,
            "description": description,
            "context": kwargs,
            "query_history": query_history,
            "sanitizer_used": self.sanitizer_type
        }

        try:
            self.bug_logger.error(json.dumps(bug_report))
        except TypeError as e:
            self.logger.error(f"Failed to serialize bug report to JSON: {e}")
            self.bug_logger.error(str(bug_report))

        logging.error(f"!!! NEW BUG FOUND by {oracle_name}! Type: {bug_type}. See {self.bug_log_file} for details. !!!")

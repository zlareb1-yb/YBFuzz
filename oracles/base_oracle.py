# Defines the abstract base class for all bug-finding oracles.
# This optimized version provides a more robust and flexible contract
# for creating new oracles, including pre-check filtering and a
# more powerful check method signature.

from abc import ABC, abstractmethod
from typing import Union, Any, Optional
from utils.db_executor import DBExecutor
from utils.bug_reporter import BugReporter
from config import FuzzerConfig
# Use a forward declaration for type hinting to avoid circular imports
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from core.generator import SQLNode


class BaseOracle(ABC):
    """
    Abstract Base Class for a bug-finding oracle.

    An oracle is a self-contained module that knows how to detect a specific
    class of bugs (e.g., logic bugs, performance regressions).
    """

    def __init__(self, executor: DBExecutor, reporter: BugReporter, config: FuzzerConfig):
        """
        Initializes the oracle.

        Args:
            executor: The database executor to run additional queries.
            reporter: The bug reporter to log any findings.
            config: The global fuzzer configuration.
        """
        self.executor = executor
        self.reporter = reporter
        self.config = config
        self.name = self.__class__.__name__

    def can_check(self, sql_or_ast: Union[str, 'SQLNode'], exception: Optional[Exception]) -> bool:
        """
        An optional pre-check to determine if this oracle should run for the
        given query outcome. This allows the engine to efficiently skip oracles
        that are not applicable.

        By default, it returns True, meaning the oracle will always run.
        Concrete oracle implementations should override this for efficiency.

        For example, an optimizer oracle might return False if the query
        resulted in an exception or was not a SELECT statement.

        Args:
            sql_or_ast: The SQL query string or the generated AST node.
            exception: The exception object if the query failed, otherwise None.

        Returns:
            True if the `check` method should be called, False otherwise.
        """
        return True

    @abstractmethod
    def check(self, sql_or_ast: Union[str, 'SQLNode'], result: Optional[list], exception: Optional[Exception]):
        """
        Performs the main check on the outcome of a query. If a bug is found,
        it should be logged via the BugReporter.

        Args:
            sql_or_ast: The SQL query string (from the mutator) or the structured
                        AST node (from the generator). Oracles should be prepared
                        to handle either.
            result: The result from the database (e.g., fetched rows), or None
                    if an exception occurred.
            exception: The exception object if the query failed, otherwise None.
        """
        pass

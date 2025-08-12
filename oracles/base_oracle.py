# Defines the abstract base class for all bug-finding oracles.
# Each oracle implements a specific technique for finding different types of bugs.

import logging
from abc import ABC, abstractmethod
from typing import Tuple, Optional, Any

class BaseOracle(ABC):
    """
    Abstract Base Class for a bug-finding oracle.
    
    An oracle is a component that implements a specific technique for finding
    different types of bugs in the database system. Each oracle focuses on
    a particular class of bugs and uses specific methodologies to detect them.
    
    Examples of oracles include:
    - TLP Oracle: Detects logic bugs using Ternary Logic Partitioning
    - QPG Oracle: Detects optimization bugs using Query Plan Guidance
    - NoREC Oracle: Detects optimization bugs using Non-optimizing Reference Engine Construction
    """
    
    def __init__(self, db_executor):
        """
        Initialize the oracle with a database executor.
        
        Args:
            db_executor: Database executor for running queries
        """
        self.db_executor = db_executor
        self.logger = logging.getLogger(self.__class__.__name__)
        self.name = self.__class__.__name__
    
    @abstractmethod
    def check(self, sql_query: str) -> Tuple[bool, Optional[str], Optional[str]]:
        """
        Check for bugs using the oracle's specific technique.
        
        Args:
            sql_query: The SQL query to test
            
        Returns:
            Tuple of (bug_found, bug_description, reproduction_query)
            - bug_found: True if a bug was detected, False otherwise
            - bug_description: Description of the bug if found, None otherwise
            - reproduction_query: SQL query to reproduce the bug if found, None otherwise
        """
        pass
    
    def can_check(self, sql_query: str) -> bool:
        """
        Check if this oracle can process the given query.
        
        Args:
            sql_query: The SQL query to check
            
        Returns:
            True if the oracle can process this query, False otherwise
        """
        # Default implementation - can check any query
        return True
    
    def get_oracle_name(self) -> str:
        """
        Get the name of this oracle.
        
        Returns:
            The oracle's name
        """
        return self.name
    
    def get_oracle_description(self) -> str:
        """
        Get a description of what this oracle does.
        
        Returns:
            Description of the oracle's functionality
        """
        return f"{self.name} - {self.__class__.__doc__ or 'No description available'}"

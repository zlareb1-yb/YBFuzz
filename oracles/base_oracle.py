# Defines the abstract base class for all bug-finding oracles.
# Each oracle implements a specific technique for finding different types of bugs.

import logging
from abc import ABC, abstractmethod
from typing import Dict, Any, Optional

class BaseOracle(ABC):
    """Base class for all oracles."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize oracle with configuration."""
        self.config = config
        self.db_executor = None  # Will be set by the engine
        
    def set_db_executor(self, db_executor):
        """Set the database executor for this oracle."""
        self.db_executor = db_executor
    
    @abstractmethod
    def check_for_bugs(self, sql_query: str) -> Optional[Dict[str, Any]]:
        """
        Check for bugs in the given SQL query.
        
        Args:
            sql_query: The SQL query to test
            
        Returns:
            Bug report dictionary if bug found, None otherwise
        """
        pass
    
    def can_check(self, sql_query: str) -> bool:
        """Check if this oracle can test the given query."""
        return True
    
    def get_oracle_name(self) -> str:
        """
        Get the name of this oracle.
        
        Returns:
            The oracle's name
        """
        return self.__class__.__name__
    
    def get_oracle_description(self) -> str:
        """
        Get a description of what this oracle does.
        
        Returns:
            Description of the oracle's functionality
        """
        return f"{self.get_oracle_name()} - {self.__class__.__doc__ or 'No description available'}"

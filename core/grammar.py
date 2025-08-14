# This optimized version is now a lean and robust loader and validator.
# Its sole responsibility is to load the grammar definition from an
# external YAML file and ensure it is well-formed before the fuzzer uses it.

import logging
import yaml
import sys

class Grammar:
    """Loads and provides access to the SQL grammar definition from a YAML file."""

    def __init__(self, grammar_file_path: str):
        """
        Initializes the Grammar object by loading and validating the grammar.
        
        Args:
            grammar_file_path: The path to the YAML file defining the grammar.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        self.logger.info(f"Loading grammar from '{grammar_file_path}'.")
        self._rules = self._load_from_yaml(grammar_file_path)
        self._validate_grammar()

    def _load_from_yaml(self, path: str) -> dict:
        """Loads the grammar definition from a YAML file."""
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            self.logger.critical(f"Grammar file not found at '{path}'. Please check the 'grammar_file' path in your config.yaml.")
            sys.exit(1)
        except yaml.YAMLError as e:
            self.logger.critical(f"Error parsing YAML grammar file '{path}': {e}")
            sys.exit(1)

    def _validate_grammar(self):
        """
        Performs sanity checks on the loaded grammar to catch common errors early.
        For example, it ensures that all non-terminal rules actually exist.
        """
        self.logger.debug("Validating grammar integrity...")
        all_rule_names = set(self._rules.keys())
        
        # Define SQL keywords that are valid terminals
        sql_keywords = {"SUM", "AVG", "MIN", "MAX", "COUNT", "CREATE", "TABLE", "VIEW", "INDEX", "INSERT", "UPDATE", "DELETE", "SELECT", "FROM", "WHERE", "GROUP", "BY", "LIMIT", "AS", "ON", "INTO", "VALUES", "SET", "AND", "OR", "=", "<>", "<", "<=", ">", ">=", "+", "-", "*", "/", "STAR", "LPAREN", "RPAREN", "COMMA", "DOT", "EQ", "NE", "LT", "LTE", "GT", "GTE", "ASC", "DESC", "INT", "TEXT", "VARCHAR", "BOOLEAN", "TIMESTAMP", "NUMERIC", "PRIMARY_KEY", "NOT_NULL", "UNIQUE"}

        for rule_name, rule_def in self._rules.items():
            # Skip terminal rules (those that are just strings)
            if isinstance(rule_def, str):
                continue
                
            if rule_def.get("type") == "choice":
                for option in rule_def.get("options", []):
                    # Choice options can be either rule names or string literals
                    # String literals like "SUM", "AVG" are valid and don't need validation
                    # Only validate if the option is a rule name (not a string literal)
                    if isinstance(option, str) and option not in all_rule_names:
                        # Check if this looks like a string literal (all caps, common SQL keywords)
                        if option not in sql_keywords:
                            self._fail_validation(f"Rule '{rule_name}' refers to an undefined choice option: '{option}'")
            
            elif rule_def.get("type") == "sequence":
                for element in rule_def.get("elements", []):
                    # Handle both string elements and object elements
                    if isinstance(element, str):
                        # String element - validate it's a defined rule or terminal
                        if element not in all_rule_names and element not in sql_keywords:
                            self._fail_validation(f"Rule '{rule_name}' refers to an undefined element: '{element}'")
                    elif isinstance(element, dict) and element.get("type") == "non_terminal":
                        if element["rule"] not in all_rule_names:
                            self._fail_validation(f"Rule '{rule_name}' refers to an undefined non-terminal: '{element['rule']}'")
        
        self.logger.info("Grammar validation passed successfully.")

    def _fail_validation(self, message: str):
        """Logs a critical error and exits if validation fails."""
        self.logger.critical(f"Grammar validation failed: {message}")
        sys.exit(1)

    def get_rules(self) -> dict:
        """Returns the entire grammar definition."""
        return self._rules

    def get_rule(self, rule_name: str) -> dict | None:
        """Returns the definition for a specific grammar rule."""
        return self._rules.get(rule_name)
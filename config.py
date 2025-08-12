# Manages all configuration for the fuzzer, providing a single source of truth.
# This optimized version includes robust validation, clearer merging logic,
# and dynamic handling of CLI overrides for a production-ready experience.

import yaml
import random
import time
import logging
import sys
from argparse import Namespace

class FuzzerConfig:
    """
    A centralized class to manage fuzzer configuration. It loads settings
    from a YAML file, intelligently merges them with command-line arguments,
    and performs validation to ensure a sane configuration state.
    """

    def __init__(self, config_path: str, cli_args: Namespace):
        """
        Initializes the configuration.

        Args:
            config_path: Path to the main YAML configuration file.
            cli_args: The parsed arguments object from argparse.
        """
        self.logger = logging.getLogger(self.__class__.__name__)
        
        self._config = self._load_from_yaml(config_path)
        self._override_with_cli_args(cli_args)
        self._apply_cli_oracle_overrides(cli_args)
        self._set_defaults()
        self._validate_config()

    def _load_from_yaml(self, path: str) -> dict:
        """Loads the base configuration from a YAML file."""
        self.logger.debug(f"Loading configuration from YAML file: {path}")
        try:
            with open(path, 'r') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            # This is a critical error, as the config file is required.
            self.logger.critical(f"Configuration file not found at '{path}'. Please provide a valid path via the --config argument.")
            sys.exit(1)
        except yaml.YAMLError as e:
            self.logger.critical(f"Error parsing YAML configuration file '{path}': {e}")
            sys.exit(1)

    def _override_with_cli_args(self, args: Namespace):
        """Overrides YAML settings with command-line arguments if they were provided."""
        self.logger.debug("Overriding configuration with command-line arguments.")
        cli_config = vars(args)

        for key, value in cli_config.items():
            # Only override if the CLI argument was actually provided by the user
            if value is not None:
                # Special handling for keys that don't map directly
                if key in ['config', 'enable_oracle', 'disable_oracle']:
                    continue
                
                # Handle nested database config
                if key.startswith('db_'):
                    db_key = key.split('_', 1)[1]
                    self._config.setdefault('database', {})[db_key] = value
                else:
                    self._config[key] = value

    def _apply_cli_oracle_overrides(self, args: Namespace):
        """Applies the --enable-oracle and --disable-oracle flags."""
        self.logger.debug("Applying CLI oracle enable/disable overrides.")
        oracles_config = self._config.setdefault('oracles', {})

        # Disable oracles specified by the user
        if args.disable_oracle:
            for oracle_name in args.disable_oracle:
                oracles_config.setdefault(oracle_name, {})['enabled'] = False
                self.logger.info(f"Oracle '{oracle_name}' disabled via command line.")

        # Enable oracles specified by the user
        if args.enable_oracle:
            for oracle_name in args.enable_oracle:
                oracles_config.setdefault(oracle_name, {})['enabled'] = True
                self.logger.info(f"Oracle '{oracle_name}' enabled via command line.")

    def _set_defaults(self):
        """Sets essential defaults if they are not provided elsewhere."""
        self.logger.debug("Setting default configuration values.")
        # Ensure a random seed is always set for reproducibility
        if 'random_seed' not in self._config:
            self._config['random_seed'] = int(time.time())
        
        # Set default file paths
        self._config.setdefault('log_file', 'ybfuzz.log')
        self._config.setdefault('bug_report_file', 'bugs.log')
        self._config.setdefault('sql_log_file', 'executed_queries.sql') # Added default for robustness
        
        # Ensure database config structure exists
        self._config.setdefault('database', {})
        self._config['database'].setdefault('schema_name', 'ybfuzz_schema')

    def _validate_config(self):
        """Performs sanity checks on the final configuration."""
        self.logger.debug("Validating final configuration.")
        # Example validation: ensure mutation probability is within a valid range
        prob = self.get('engine_strategy', {}).get('mutation_probability')
        if prob is not None and not (0.0 <= prob <= 1.0):
            self.logger.critical(f"Invalid 'mutation_probability': {prob}. Must be between 0.0 and 1.0.")
            sys.exit(1)

        # Example validation: ensure database host is specified
        if not self.get_db_config().get('host'):
            self.logger.critical("Database host is not specified in config file or via --db-host argument.")
            sys.exit(1)

    def get(self, key: str, default=None):
        """
        Retrieves a configuration value.

        Args:
            key: The configuration key to retrieve.
            default: A default value to return if the key is not found.

        Returns:
            The configuration value or the default.
        """
        return self._config.get(key, default)

    def get_db_config(self) -> dict:
        """Returns the database connection dictionary."""
        db_config = self.get('database', {})
        
        # Map config keys to expected DB executor keys
        mapped_config = {}
        if 'host' in db_config:
            mapped_config['host'] = db_config['host']
        if 'port' in db_config:
            mapped_config['port'] = db_config['port']
        if 'user' in db_config:
            mapped_config['user'] = db_config['user']
        if 'password' in db_config:
            mapped_config['password'] = db_config['password']
        if 'database' in db_config:
            mapped_config['dbname'] = db_config['database']  # Map 'database' to 'dbname'
        if 'schema_name' in db_config:
            mapped_config['schema_name'] = db_config['schema_name']
            
        return mapped_config

    def __getitem__(self, key):
        """Allows dictionary-style access to the configuration."""
        return self._config[key]

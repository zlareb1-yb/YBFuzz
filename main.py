# The main entry point for the YBFuzz Framework.
# This file is responsible for parsing command-line arguments,
# loading configuration, and kicking off the fuzzing engine.
# It is designed to be as powerful and flexible as established
# fuzzers like SQLancer and SQLsmith.

import argparse
import logging
import sys
from config import FuzzerConfig
from core.engine import FuzzerEngine

def main():
    """Parses arguments, sets up logging, and starts the fuzzer."""
    # Use a formatter that shows default values in help text
    parser = argparse.ArgumentParser(
        description="YBFuzz: A Professional Hybrid Fuzzing Framework for YugabyteDB",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # --- Argument Groups for Clarity ---
    
    run_group = parser.add_argument_group('Run Control')
    run_group.add_argument("-c", "--config", required=True, help="Path to the main YAML configuration file.")
    run_group.add_argument("-d", "--duration", type=int, help="Fuzzing duration in seconds. Overrides config file.")
    run_group.add_argument("-q", "--max-queries", type=int, help="Maximum number of queries to generate. Overrides config file.")
    run_group.add_argument("--num-threads", type=int, default=1, help="Number of concurrent fuzzing threads (architectural hook).")

    debug_group = parser.add_argument_group('Reproducibility & Debugging')
    debug_group.add_argument("-s", "--seed", type=int, help="Random seed for reproducible runs. Overrides config file.")
    debug_group.add_argument("-l", "--log-level", choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], help="Logging level. Overrides config file.")
    debug_group.add_argument("--dry-run", action='store_true', help="Generate and print queries without executing them.")

    db_group = parser.add_argument_group('Database Connection Overrides')
    db_group.add_argument("--db-host", help="Database host.")
    db_group.add_argument("--db-port", type=int, help="Database port.")
    db_group.add_argument("--db-user", help="Database user.")
    db_group.add_argument("--db-password", help="Database password.")
    db_group.add_argument("--db-name", help="Database name.")

    strategy_group = parser.add_argument_group('Fuzzer Strategy')
    strategy_group.add_argument("--mutation-probability", type=float, help="Probability (0.0-1.0) of using the mutational engine. Overrides config.")
    strategy_group.add_argument("--enable-oracle", action='append', help="Enable a specific oracle (e.g., TLOracle). Can be used multiple times.")
    strategy_group.add_argument("--disable-oracle", action='append', help="Disable a specific oracle (e.g., QPGOracle). Can be used multiple times.")


    args = parser.parse_args()

    # Load configuration from file and merge with CLI arguments
    try:
        config = FuzzerConfig(args.config, args)
    except Exception as e:
        # Exit gracefully if config fails to load
        logging.basicConfig(level=logging.CRITICAL, format='%(asctime)s - %(levelname)s - %(message)s')
        logging.critical(f"Failed to initialize configuration: {e}")
        sys.exit(1)
    
    # Setup logging based on the final configuration
    log_level = getattr(logging, config.get('log_level', 'INFO').upper())
    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
        handlers=[
            logging.FileHandler(config.get('log_file'), mode='w'),
            logging.StreamHandler(sys.stdout)
        ]
    )

    logging.info("YBFuzz Framework Initializing...")
    logging.info(f"Configuration loaded from '{args.config}'")
    logging.info(f"Random seed for this run: {config.get('random_seed')}")
    if config.get('dry_run'):
        logging.warning("DRY RUN mode enabled. Queries will be printed but not executed.")

    # Main execution block
    try:
        engine = FuzzerEngine(config)
        engine.run()
    except KeyboardInterrupt:
        logging.info("\nFuzzing run interrupted by user.")
    except Exception as e:
        logging.critical(f"A critical, unhandled error occurred in the fuzzer engine: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logging.info("YBFuzz Framework Shutting Down.")


if __name__ == "__main__":
    main()
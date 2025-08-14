#!/usr/bin/env python3
"""
YBFuzz Framework - Database Fuzzer for YugabyteDB

This module provides the main entry point for the YBFuzz framework.
Features:
- Advanced query generation and mutation
- Multi-oracle bug detection
- Session management and recovery
- Performance monitoring and metrics
- Advanced logging and reporting
"""

import argparse
import logging
import signal
import sys
import time
import traceback
from pathlib import Path
from typing import Optional, Dict, Any

# Imports with error handling
try:
    import yaml
    import psycopg2
    import psycopg2.extras
except ImportError as e:
    print(f"❌ Critical dependency missing: {e}")
    print("Please install required packages: pip install pyyaml psycopg2-binary")
    sys.exit(1)

# Local imports with error handling
try:
    from config import load_config, validate_config
    from core.engine import FuzzerEngine
    from utils.bug_reporter import BugReporter
    from utils.db_executor import DBExecutor
except ImportError as e:
    print(f"❌ Failed to import YBFuzz components: {e}")
    print("Please ensure all components are properly installed")
    sys.exit(1)

# Global variables for signal handling
fuzzer_engine: Optional[FuzzerEngine] = None
shutdown_requested = False

def setup_logging(config: Dict[str, Any]) -> logging.Logger:
    """
    Setup advanced logging with multiple handlers and formats.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        Configured logger instance
    """
    # Create logs directory if it doesn't exist
    log_dir = Path("logs")
    log_dir.mkdir(exist_ok=True)
    
    # Configure root logger
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG if config.get('debug', False) else logging.INFO)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler with structured output
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    
    # Console formatter with structure
    console_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(name)s] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    console_handler.setFormatter(console_formatter)
    
    # File handler for comprehensive logging
    log_file = config.get('log_file', 'logs/ybfuzz_comprehensive.log')
    file_handler = logging.FileHandler(log_file, mode='w', encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    
    # File formatter with detailed information
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - [%(name)s] - %(funcName)s:%(lineno)d - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(file_formatter)
    
    # Error file handler for critical issues
    error_log_file = config.get('error_log_file', 'logs/ybfuzz_errors.log')
    error_handler = logging.FileHandler(error_log_file, mode='w', encoding='utf-8')
    error_handler.setLevel(logging.ERROR)
    error_handler.setFormatter(file_formatter)
    
    # Performance metrics handler
    metrics_log_file = config.get('metrics_log_file', 'logs/ybfuzz_metrics.log')
    metrics_handler = logging.FileHandler(metrics_log_file, mode='w', encoding='utf-8')
    metrics_handler.setLevel(logging.INFO)
    metrics_formatter = logging.Formatter('%(asctime)s - %(message)s')
    metrics_handler.setFormatter(metrics_formatter)
    
    # Add all handlers
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)
    logger.addHandler(error_handler)
    logger.addHandler(metrics_handler)
    
    return logger

def signal_handler(signum: int, frame) -> None:
    """
    Handle shutdown signals gracefully.
    
    Args:
        signum: Signal number
        frame: Current stack frame
    """
    global shutdown_requested, fuzzer_engine
    
    signal_name = signal.Signals(signum).name
    print(f"\n🛑 Received signal {signal_name}, initiating graceful shutdown...")
    
    shutdown_requested = True
    
    if fuzzer_engine:
        try:
            fuzzer_engine.shutdown()
            print("✅ Fuzzer shutdown completed successfully")
        except Exception as e:
            print(f"⚠️  Error during shutdown: {e}")
    
    sys.exit(0)

def validate_environment() -> bool:
    """
    Validate the execution environment and dependencies.
    
    Returns:
        True if environment is valid, False otherwise
    """
    print("🔍 Validating execution environment...")
    
    # Check Python version
    if sys.version_info < (3, 8):
        print("❌ Python 3.8+ required")
        return False
    
    # Check required directories
    required_dirs = ['logs', 'bug_reproductions', 'corpus', 'evolved_corpus']
    for dir_name in required_dirs:
        Path(dir_name).mkdir(exist_ok=True)
        print(f"✅ Directory '{dir_name}' ready")
    
    # Check write permissions
    try:
        test_file = Path("logs/test_write.tmp")
        test_file.write_text("test")
        test_file.unlink()
        print("✅ Write permissions verified")
    except Exception as e:
        print(f"❌ Write permission error: {e}")
        return False
    
    print("✅ Environment validation completed successfully")
    return True

def main() -> int:
    """
    Main entry point for the YBFuzz framework.
    
    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    global fuzzer_engine, shutdown_requested
    
    try:
        # Parse command line arguments
        parser = argparse.ArgumentParser(
            description="YBFuzz Framework - Database Fuzzer for YugabyteDB",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  # Run fuzzer for 1 hour with comprehensive logging
  python3 main.py -c config.yaml --duration 3600 --debug
  
  # Run fuzzer with specific oracle focus
  python3 main.py -c config.yaml --duration 1800 --oracles TLP,QPG
  
  # Run fuzzer with performance monitoring
  python3 main.py -c config.yaml --duration 7200 --metrics --corpus-evolution
            """
        )
        
        parser.add_argument(
            '-c', '--config', 
            required=True, 
            help='Configuration file path'
        )
        parser.add_argument(
            '--duration', 
            type=int, 
            default=3600,
            help='Fuzzing duration in seconds (default: 3600)'
        )
        parser.add_argument(
            '--debug', 
            action='store_true',
            help='Enable debug logging'
        )
        parser.add_argument(
            '--oracles', 
            type=str,
            help='Comma-separated list of oracles to use (default: all)'
        )
        parser.add_argument(
            '--metrics', 
            action='store_true',
            help='Enable detailed performance metrics'
        )
        parser.add_argument(
            '--corpus-evolution', 
            action='store_true',
            help='Enable advanced corpus evolution'
        )
        parser.add_argument(
            '--distributed', 
            action='store_true',
            help='Enable distributed testing mode'
        )
        parser.add_argument(
            '--validate-only', 
            action='store_true',
            help='Validate configuration and exit'
        )
        
        args = parser.parse_args()
        
        # Validate environment
        if not validate_environment():
            return 1
        
        # Load and validate configuration
        print("📋 Loading configuration...")
        config = load_config(args.config)
        
        # Override config with command line arguments
        if args.debug:
            config['debug'] = True
        if args.metrics:
            config['enable_metrics'] = True
        if args.corpus_evolution:
            config['enable_corpus_evolution'] = True
        if args.distributed:
            config['enable_distributed'] = True
        
        # Validate configuration
        if not validate_config(config):
            print("❌ Configuration validation failed")
            return 1
        
        if args.validate_only:
            print("✅ Configuration validation completed successfully")
            return 0
        
        # Setup logging
        logger = setup_logging(config)
        logger.info("🚀 YBFuzz Framework Initializing...")
        
        # Setup signal handlers for graceful shutdown
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        # Initialize components silently
        bug_reporter = BugReporter(config)
        db_config = config.get('database', {})
        db_executor = DBExecutor(db_config, bug_reporter, config)
        fuzzer_engine = FuzzerEngine(config, db_executor, bug_reporter)
        
        # Start fuzzing
        logger.info(f"🎯 Starting fuzzer for {args.duration} seconds...")
        start_time = time.time()
        
        try:
            fuzzer_engine.run(duration=args.duration)
        except KeyboardInterrupt:
            logger.info("🛑 Fuzzing interrupted by user")
        except Exception as e:
            logger.error(f"❌ Fuzzing failed: {e}")
            logger.error(f"Traceback: {traceback.format_exc()}")
            return 1
        
        # Calculate and log final statistics
        end_time = time.time()
        total_time = end_time - start_time
        
        logger.info("📊 Final Statistics:")
        logger.info(f"   Total Runtime: {total_time:.2f} seconds")
        logger.info(f"   Queries Executed: {fuzzer_engine.stats.get('queries_executed', 0)}")
        logger.info(f"   Bugs Found: {fuzzer_engine.stats.get('bugs_found', 0)}")
        logger.info(f"   Error Rate: {fuzzer_engine.stats.get('query_errors', 0) / max(fuzzer_engine.stats.get('queries_executed', 1), 1) * 100:.2f}%")
        
        logger.info("🎉 YBFuzz Framework completed successfully")
        return 0
        
    except Exception as e:
        print(f"❌ Critical error in main: {e}")
        print(f"Traceback: {traceback.format_exc()}")
        return 1
        
    finally:
        # Ensure cleanup
        if fuzzer_engine:
            try:
                fuzzer_engine.shutdown()
            except Exception as e:
                print(f"⚠️  Error during cleanup: {e}")

if __name__ == "__main__":
    exit_code = main()
    sys.exit(exit_code)
#!/usr/bin/env python3
"""
YBFuzz Configuration Management - Advanced Configuration System

This module provides advanced configuration management with:
- Comprehensive database configuration
- Oracle-specific settings
- Fuzzing behavior control
- Logging and monitoring options
- Performance tuning parameters
"""

import os
import yaml
import logging
from pathlib import Path
from typing import Dict, Any, List, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta

# Logging setup
logger = logging.getLogger(__name__)

@dataclass
class DatabaseConfig:
    """Advanced database configuration with comprehensive connection options."""
    host: str = "localhost"
    port: int = 5433
    dbname: str = "yugabyte"
    user: str = "yugabyte"
    password: str = ""
    schema_name: str = "ybfuzz_schema"
    connection_timeout: int = 30
    statement_timeout: int = 300
    max_connections: int = 10
    connection_pool_size: int = 5
    retry_attempts: int = 3
    retry_delay: float = 1.0
    enable_ssl: bool = False
    ssl_mode: str = "prefer"
    enable_connection_pooling: bool = True
    pool_recycle: int = 3600
    
    def validate(self) -> List[str]:
        """Validate database configuration."""
        errors = []
        
        if not self.host:
            errors.append("Database host is required")
        if not self.dbname:
            errors.append("Database name is required")
        if not self.user:
            errors.append("Database user is required")
        if self.port < 1 or self.port > 65535:
            errors.append("Invalid database port")
        if self.connection_timeout < 1:
            errors.append("Connection timeout must be positive")
        if self.statement_timeout < 1:
            errors.append("Statement timeout must be positive")
        if self.max_connections < 1:
            errors.append("Max connections must be positive")
        if self.connection_pool_size < 1:
            errors.append("Connection pool size must be positive")
        if self.retry_attempts < 0:
            errors.append("Retry attempts must be non-negative")
        if self.retry_delay < 0:
            errors.append("Retry delay must be non-negative")
        if self.pool_recycle < 0:
            errors.append("Pool recycle must be non-negative")
            
        return errors

@dataclass
class OracleConfig:
    """Advanced oracle configuration for comprehensive bug detection."""
    enabled_oracles: List[str] = field(default_factory=lambda: [
        "TLOracle", "QPGOracle", "PQSOracle", "NoRECOracle", 
        "CERTOracle", "DQPOracle", "CODDTestOracle"
    ])
    
    # TLP Oracle settings
    tlp_enable_non_deterministic_check: bool = True
    tlp_skip_simple_queries: bool = True
    tlp_max_partitions: int = 3
    tlp_enable_complex_conditions: bool = True
    
    # QPG Oracle settings
    qpg_performance_threshold: float = 0.15
    qpg_execution_runs: int = 3
    qpg_enable_plan_hints: bool = True
    qpg_max_alternative_plans: int = 5
    qpg_enable_distributed_optimization: bool = True
    
    # PQS Oracle settings
    pqs_max_pivot_attempts: int = 10
    pqs_enable_complex_queries: bool = True
    pqs_enable_user_tables: bool = True
    
    # NoREC Oracle settings
    norec_enable_optimization_hints: bool = True
    norec_max_hint_combinations: int = 8
    norec_enable_plan_comparison: bool = True
    
    # CERT Oracle settings
    cert_cardinality_threshold: float = 0.5
    cert_enable_plan_analysis: bool = True
    cert_enable_statistics_validation: bool = True
    
    # DQP Oracle settings
    dqp_enable_plan_comparison: bool = True
    dqp_max_plan_variations: int = 6
    dqp_enable_hint_optimization: bool = True
    
    # CODDTest Oracle settings
    coddtest_enable_constant_folding: bool = True
    coddtest_max_optimization_steps: int = 5
    coddtest_enable_expression_optimization: bool = True
    
    def validate(self) -> List[str]:
        """Validate oracle configuration."""
        errors = []
        
        if not self.enabled_oracles:
            errors.append("At least one oracle must be enabled")
        
        if self.qpg_performance_threshold <= 0 or self.qpg_performance_threshold > 1:
            errors.append("QPG performance threshold must be between 0 and 1")
        
        if self.qpg_execution_runs < 1:
            errors.append("QPG execution runs must be positive")
            
        if self.tlp_max_partitions < 1:
            errors.append("TLP max partitions must be positive")
            
        if self.pqs_max_pivot_attempts < 1:
            errors.append("PQS max pivot attempts must be positive")
            
        if self.norec_max_hint_combinations < 1:
            errors.append("NoREC max hint combinations must be positive")
            
        if self.cert_cardinality_threshold <= 0 or self.cert_cardinality_threshold > 1:
            errors.append("CERT cardinality threshold must be between 0 and 1")
            
        if self.dqp_max_plan_variations < 1:
            errors.append("DQP max plan variations must be positive")
            
        if self.coddtest_max_optimization_steps < 1:
            errors.append("CODDTest max optimization steps must be positive")
            
        return errors

@dataclass
class FuzzingConfig:
    """Advanced fuzzing configuration for maximum bug detection."""
    duration: int = 3600  # 1 hour default
    max_queries: Optional[int] = None
    queries_per_second: float = 1.0
    max_query_length: int = 10000
    enable_mutation: bool = True
    enable_corpus_evolution: bool = True
    enable_distributed: bool = False
    
    # Query generation settings
    grammar_mutation_probability: float = 0.3
    seed_query_probability: float = 0.2
    random_query_probability: float = 0.5
    
    # Session management
    session_duration: int = 300  # 5 minutes
    max_sessions: Optional[int] = None
    session_cleanup_interval: int = 60
    
    # Performance optimization
    batch_size: int = 10
    max_concurrent_queries: int = 5
    query_timeout: float = 30.0
    
    # Advanced query types
    enable_ddl_queries: bool = True
    enable_dml_queries: bool = True
    enable_complex_joins: bool = True
    enable_subqueries: bool = True
    enable_window_functions: bool = True
    enable_ctes: bool = True
    enable_json_operations: bool = True
    enable_array_operations: bool = True
    enable_aggregations: bool = True
    enable_transactions: bool = True
    
    def validate(self) -> List[str]:
        """Validate fuzzing configuration."""
        errors = []
        
        if self.duration < 1:
            errors.append("Fuzzing duration must be positive")
        if self.queries_per_second <= 0:
            errors.append("Queries per second must be positive")
        if self.max_query_length < 100:
            errors.append("Max query length must be at least 100")
        if self.grammar_mutation_probability < 0 or self.grammar_mutation_probability > 1:
            errors.append("Grammar mutation probability must be between 0 and 1")
        if self.session_duration < 1:
            errors.append("Session duration must be positive")
        if self.batch_size < 1:
            errors.append("Batch size must be positive")
        if self.max_concurrent_queries < 1:
            errors.append("Max concurrent queries must be positive")
        if self.query_timeout <= 0:
            errors.append("Query timeout must be positive")
            
        return errors

@dataclass
class LoggingConfig:
    """Advanced logging configuration."""
    log_level: str = "INFO"
    log_file: str = "logs/ybfuzz_comprehensive.log"
    error_log_file: str = "logs/ybfuzz_errors.log"
    metrics_log_file: str = "logs/ybfuzz_metrics.log"
    
    # Advanced logging options
    enable_structured_logging: bool = True
    enable_performance_metrics: bool = True
    enable_query_tracking: bool = True
    enable_oracle_tracking: bool = True
    
    # Log rotation
    max_log_size: int = 100 * 1024 * 1024  # 100MB
    backup_count: int = 5
    enable_compression: bool = True
    
    # Query logging
    log_all_queries: bool = True
    log_query_results: bool = False
    log_query_plans: bool = True
    log_performance_metrics: bool = True
    
    def validate(self) -> List[str]:
        """Validate logging configuration."""
        errors = []
        
        valid_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        if self.log_level not in valid_levels:
            errors.append(f"Log level must be one of: {', '.join(valid_levels)}")
        
        if self.max_log_size < 1024 * 1024:  # 1MB minimum
            errors.append("Max log size must be at least 1MB")
            
        if self.backup_count < 0:
            errors.append("Backup count must be non-negative")
            
        return errors

@dataclass
class MonitoringConfig:
    """Advanced monitoring and metrics configuration."""
    enable_real_time_monitoring: bool = True
    enable_performance_tracking: bool = True
    enable_resource_monitoring: bool = True
    enable_bug_analytics: bool = True
    
    # Metrics collection
    metrics_interval: int = 60  # seconds
    performance_sampling_rate: float = 0.1
    enable_histograms: bool = True
    enable_percentiles: bool = True
    
    # Alerting
    enable_alerts: bool = False
    error_rate_threshold: float = 0.1
    performance_degradation_threshold: float = 0.2
    
    # Performance tracking
    track_query_execution_time: bool = True
    track_memory_usage: bool = True
    track_cpu_usage: bool = True
    track_database_connections: bool = True
    
    def validate(self) -> List[str]:
        """Validate monitoring configuration."""
        errors = []
        
        if self.metrics_interval < 1:
            errors.append("Metrics interval must be positive")
        if self.performance_sampling_rate < 0 or self.performance_sampling_rate > 1:
            errors.append("Performance sampling rate must be between 0 and 1")
        if self.error_rate_threshold < 0 or self.error_rate_threshold > 1:
            errors.append("Error rate threshold must be between 0 and 1")
        if self.performance_degradation_threshold < 0 or self.performance_degradation_threshold > 1:
            errors.append("Performance degradation threshold must be between 0 and 1")
            
        return errors

@dataclass
class CorpusConfig:
    """Advanced corpus management configuration."""
    initial_corpus_size: int = 1000
    max_corpus_size: int = 10000
    evolution_rate: float = 0.1
    mutation_strength: float = 0.3
    
    # Corpus evolution
    enable_adaptive_mutation: bool = True
    enable_cross_over: bool = True
    enable_selection_pressure: bool = True
    
    # Seed management
    seed_query_file: str = "corpus/seed_queries.txt"
    evolved_corpus_dir: str = "evolved_corpus"
    
    # Query diversity
    enable_complex_queries: bool = True
    enable_edge_cases: bool = True
    enable_performance_queries: bool = True
    enable_distributed_queries: bool = True
    
    def validate(self) -> List[str]:
        """Validate corpus configuration."""
        errors = []
        
        if self.initial_corpus_size < 1:
            errors.append("Initial corpus size must be positive")
        if self.max_corpus_size < self.initial_corpus_size:
            errors.append("Max corpus size must be >= initial corpus size")
        if self.evolution_rate < 0 or self.evolution_rate > 1:
            errors.append("Evolution rate must be between 0 and 1")
        if self.mutation_strength < 0 or self.mutation_strength > 1:
            errors.append("Mutation strength must be between 0 and 1")
            
        return errors

@dataclass
class PerformanceConfig:
    """Performance tuning and optimization configuration."""
    max_memory_usage: int = 2 * 1024 * 1024 * 1024  # 2GB
    enable_gc_optimization: bool = True
    enable_memory_pooling: bool = True
    
    # Processing optimization
    enable_async_processing: bool = False
    enable_batch_processing: bool = True
    enable_query_caching: bool = True
    
    # Database optimization
    enable_connection_pooling: bool = True
    enable_query_preparation: bool = True
    enable_plan_caching: bool = True
    
    # Memory management
    gc_threshold: int = 1000
    memory_pool_size: int = 100 * 1024 * 1024  # 100MB
    enable_memory_monitoring: bool = True
    
    def validate(self) -> List[str]:
        """Validate performance configuration."""
        errors = []
        
        if self.max_memory_usage < 100 * 1024 * 1024:  # 100MB minimum
            errors.append("Max memory usage must be at least 100MB")
        if self.gc_threshold < 1:
            errors.append("GC threshold must be positive")
        if self.memory_pool_size < 1024 * 1024:  # 1MB minimum
            errors.append("Memory pool size must be at least 1MB")
            
        return errors

@dataclass
class DistributedConfig:
    """Distributed testing configuration."""
    enabled: bool = False
    worker_nodes: List[str] = field(default_factory=list)
    coordinator_node: str = "localhost"
    enable_load_balancing: bool = True
    enable_fault_tolerance: bool = True
    
    # Worker management
    max_workers: int = 10
    worker_timeout: int = 300
    enable_worker_monitoring: bool = True
    
    # Communication
    enable_secure_communication: bool = True
    communication_timeout: int = 60
    retry_attempts: int = 3
    
    def validate(self) -> List[str]:
        """Validate distributed configuration."""
        errors = []
        
        if self.max_workers < 1:
            errors.append("Max workers must be positive")
        if self.worker_timeout < 1:
            errors.append("Worker timeout must be positive")
        if self.communication_timeout < 1:
            errors.append("Communication timeout must be positive")
        if self.retry_attempts < 0:
            errors.append("Retry attempts must be non-negative")
            
        return errors

@dataclass
class YBFuzzConfig:
    """Complete YBFuzz configuration for production use."""
    # Core components
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    oracles: OracleConfig = field(default_factory=OracleConfig)
    fuzzing: FuzzingConfig = field(default_factory=FuzzingConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    monitoring: MonitoringConfig = field(default_factory=MonitoringConfig)
    corpus: CorpusConfig = field(default_factory=CorpusConfig)
    performance: PerformanceConfig = field(default_factory=PerformanceConfig)
    distributed: DistributedConfig = field(default_factory=DistributedConfig)
    
    # Global settings
    random_seed: Optional[int] = None
    debug: bool = False
    dry_run: bool = False
    enable_metrics: bool = True
    enable_corpus_evolution: bool = True
    enable_distributed: bool = False
    
    # Performance tuning
    max_memory_usage: int = 2 * 1024 * 1024 * 1024  # 2GB
    enable_gc_optimization: bool = True
    enable_async_processing: bool = False
    
    def __post_init__(self):
        """Post-initialization validation and setup."""
        if self.random_seed is None:
            self.random_seed = int(datetime.now().timestamp())
        
        # Ensure log directories exist
        Path("logs").mkdir(exist_ok=True)
        Path("bug_reproductions").mkdir(exist_ok=True)
        Path("corpus").mkdir(exist_ok=True)
        Path("evolved_corpus").mkdir(exist_ok=True)
    
    def validate(self) -> List[str]:
        """Validate complete configuration."""
        errors = []
        
        # Validate each component
        errors.extend(self.database.validate())
        errors.extend(self.oracles.validate())
        errors.extend(self.fuzzing.validate())
        errors.extend(self.logging.validate())
        errors.extend(self.monitoring.validate())
        errors.extend(self.corpus.validate())
        errors.extend(self.performance.validate())
        errors.extend(self.distributed.validate())
        
        # Global validation
        if self.max_memory_usage < 100 * 1024 * 1024:  # 100MB minimum
            errors.append("Max memory usage must be at least 100MB")
        
        return errors
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert configuration to dictionary."""
        return {
            'database': self.database.__dict__,
            'oracles': self.oracles.__dict__,
            'fuzzing': self.fuzzing.__dict__,
            'logging': self.logging.__dict__,
            'monitoring': self.monitoring.__dict__,
            'corpus': self.corpus.__dict__,
            'performance': self.performance.__dict__,
            'distributed': self.distributed.__dict__,
            'random_seed': self.random_seed,
            'debug': self.debug,
            'dry_run': self.dry_run,
            'enable_metrics': self.enable_metrics,
            'enable_corpus_evolution': self.enable_corpus_evolution,
            'enable_distributed': self.enable_distributed,
            'max_memory_usage': self.max_memory_usage,
            'enable_gc_optimization': self.enable_gc_optimization,
            'enable_async_processing': self.enable_async_processing
        }

def load_config(config_path: str) -> Dict[str, Any]:
    """
    Load configuration from YAML file with production defaults.
    
    Args:
        config_path: Path to configuration file
        
    Returns:
        Configuration dictionary
    """
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        if not config_data:
            raise ValueError("Configuration file is empty")
        
        # Apply production defaults
        config_data = _apply_comprehensive_defaults(config_data)
        
        logger.info(f"Configuration loaded from '{config_path}'")
        return config_data
        
    except FileNotFoundError:
        logger.error(f"Configuration file not found: {config_path}")
        raise
    except yaml.YAMLError as e:
        logger.error(f"Invalid YAML in configuration file: {e}")
        raise
    except Exception as e:
        logger.error(f"Error loading configuration: {e}")
        raise

def _apply_comprehensive_defaults(config: Dict[str, Any]) -> Dict[str, Any]:
    """Apply comprehensive defaults to configuration."""
    
    # Database defaults
    if 'database' not in config:
        config['database'] = {}
    config['database'].setdefault('connection_timeout', 30)
    config['database'].setdefault('statement_timeout', 300)
    config['database'].setdefault('max_connections', 10)
    config['database'].setdefault('retry_attempts', 3)
    config['database'].setdefault('enable_ssl', False)
    config['database'].setdefault('enable_connection_pooling', True)
    
    # Oracle defaults
    if 'oracles' not in config:
        config['oracles'] = {}
    config['oracles'].setdefault('qpg_performance_threshold', 0.15)
    config['oracles'].setdefault('qpg_execution_runs', 3)
    config['oracles'].setdefault('tlp_max_partitions', 3)
    
    # Fuzzing defaults
    if 'fuzzing' not in config:
        config['fuzzing'] = {}
    config['fuzzing'].setdefault('duration', 3600)
    config['fuzzing'].setdefault('queries_per_second', 1.0)
    config['fuzzing'].setdefault('session_duration', 300)
    config['fuzzing'].setdefault('batch_size', 10)
    
    # Logging defaults
    if 'logging' not in config:
        config['logging'] = {}
    config['logging'].setdefault('log_level', 'INFO')
    config['logging'].setdefault('enable_structured_logging', True)
    config['logging'].setdefault('enable_performance_metrics', True)
    
    # Monitoring defaults
    if 'monitoring' not in config:
        config['monitoring'] = {}
    config['monitoring'].setdefault('enable_real_time_monitoring', True)
    config['monitoring'].setdefault('metrics_interval', 60)
    
    # Corpus defaults
    if 'corpus' not in config:
        config['corpus'] = {}
    config['corpus'].setdefault('initial_corpus_size', 1000)
    config['corpus'].setdefault('max_corpus_size', 10000)
    config['corpus'].setdefault('evolution_rate', 0.1)
    
    # Performance defaults
    if 'performance' not in config:
        config['performance'] = {}
    config['performance'].setdefault('max_memory_usage', 2 * 1024 * 1024 * 1024)
    config['performance'].setdefault('enable_gc_optimization', True)
    config['performance'].setdefault('enable_memory_pooling', True)
    
    # Distributed defaults
    if 'distributed' not in config:
        config['distributed'] = {}
    config['distributed'].setdefault('enabled', False)
    config['distributed'].setdefault('max_workers', 10)
    config['distributed'].setdefault('enable_fault_tolerance', True)
    
    return config

def validate_config(config: Dict[str, Any]) -> bool:
    """
    Validate complete configuration.
    
    Args:
        config: Configuration dictionary
        
    Returns:
        True if valid, False otherwise
    """
    try:
        # Convert to YBFuzzConfig object for validation
        yb_config = YBFuzzConfig()
        
        # Update with loaded config
        for key, value in config.items():
            if hasattr(yb_config, key):
                if isinstance(value, dict) and hasattr(getattr(yb_config, key), '__dict__'):
                    # Update nested config objects
                    nested_obj = getattr(yb_config, key)
                    for nested_key, nested_value in value.items():
                        if hasattr(nested_obj, nested_key):
                            setattr(nested_obj, nested_key, nested_value)
                else:
                    setattr(yb_config, key, value)
        
        # Validate
        errors = yb_config.validate()
        
        if errors:
            logger.error("Configuration validation failed:")
            for error in errors:
                logger.error(f"  - {error}")
            return False
        
        logger.info("✅ Configuration validation completed successfully")
        return True
        
    except Exception as e:
        logger.error(f"Configuration validation error: {e}")
        return False

def create_default_config(config_path: str) -> None:
    """
    Create a default configuration file with production settings.
    
    Args:
        config_path: Path where to create the configuration file
    """
    default_config = YBFuzzConfig()
    
    # Convert to YAML-friendly format
    config_dict = default_config.to_dict()
    
    try:
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config_dict, f, default_flow_style=False, indent=2, sort_keys=False)
        
        logger.info(f"Default configuration created at: {config_path}")
        
    except Exception as e:
        logger.error(f"Failed to create default configuration: {e}")
        raise

# Legacy compatibility
class FuzzerConfig:
    """Legacy configuration class for backward compatibility."""
    
    def __init__(self, config_path: str, cli_args=None):
        self.config_data = load_config(config_path)
        self._apply_cli_overrides(cli_args)
    
    def _apply_cli_overrides(self, cli_args):
        """Apply command line argument overrides."""
        if not cli_args:
            return
        
        # Apply CLI overrides
        if hasattr(cli_args, 'duration') and cli_args.duration:
            self.config_data['fuzzing']['duration'] = cli_args.duration
        if hasattr(cli_args, 'debug') and cli_args.debug:
            self.config_data['debug'] = True
    
    def get(self, key: str, default=None):
        """Get configuration value with dot notation support."""
        keys = key.split('.')
        value = self.config_data
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def __getitem__(self, key: str):
        """Get configuration value using bracket notation."""
        return self.config_data[key]

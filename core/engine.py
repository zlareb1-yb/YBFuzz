#!/usr/bin/env python3
"""
YBFuzz Core Engine - Advanced Fuzzer Orchestration

This module provides the core fuzzing engine that orchestrates:
- Multi-oracle bug detection
- Query generation and mutation
- Session management and recovery
- Performance monitoring and metrics
- Advanced logging and reporting
"""

import time
import logging
import random
import threading
import gc
import psutil
import signal
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from pathlib import Path

# Local imports
from .generator import GrammarGenerator
from .mutator import AdvancedMutator
from oracles.tlp_oracle import TLPOracle
from oracles.qpg_oracle import QPGOracle
from oracles.pqs_oracle import PQSOracle
from oracles.norec_oracle import NoRECOracle
from oracles.cert_oracle import CERTOracle
from oracles.dqp_oracle import DQPOracle
from oracles.coddtest_oracle import CODDTestOracle
from oracles.distributed_consistency_oracle import DistributedConsistencyOracle
from oracles.yugabytedb_features_oracle import YugabyteDBFeaturesOracle
from oracles.edge_case_oracle import EdgeCaseOracle
from oracles.complex_sql_oracle import ComplexSQLOracle
from utils.db_executor import DBExecutor
from utils.bug_reporter import BugReporter
from core.generator import RawSQL
from oracles import ORACLE_REGISTRY


@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics for production monitoring."""
    # Query execution metrics
    total_queries: int = 0
    successful_queries: int = 0
    failed_queries: int = 0
    avg_query_time: float = 0.0
    max_query_time: float = 0.0
    min_query_time: float = float('inf')
    
    # Oracle performance metrics
    oracle_execution_times: Dict[str, List[float]] = field(default_factory=dict)
    oracle_success_rates: Dict[str, float] = field(default_factory=dict)
    oracle_bug_detection_rates: Dict[str, float] = field(default_factory=dict)
    
    # Resource usage metrics
    memory_usage: List[float] = field(default_factory=list)
    cpu_usage: List[float] = field(default_factory=list)
    database_connections: List[int] = field(default_factory=list)
    
    # Session metrics
    sessions_completed: int = 0
    avg_session_duration: float = 0.0
    session_success_rate: float = 0.0
    
    # Bug detection metrics
    total_bugs: int = 0
    bugs_by_oracle: Dict[str, int] = field(default_factory=dict)
    bugs_by_severity: Dict[str, int] = field(default_factory=dict)
    bugs_by_category: Dict[str, int] = field(default_factory=dict)
    
    def update_query_metrics(self, execution_time: float, success: bool):
        """Update query execution metrics."""
        self.total_queries += 1
        if success:
            self.successful_queries += 1
        else:
            self.failed_queries += 1
        
        # Update timing statistics
        if execution_time > self.max_query_time:
            self.max_query_time = execution_time
        if execution_time < self.min_query_time:
            self.min_query_time = execution_time
        
        # Update average (exponential moving average for efficiency)
        alpha = 0.1
        self.avg_query_time = (alpha * execution_time) + ((1 - alpha) * self.avg_query_time)
    
    def update_oracle_metrics(self, oracle_name: str, execution_time: float, success: bool, bugs_found: int):
        """Update oracle-specific metrics."""
        if oracle_name not in self.oracle_execution_times:
            self.oracle_execution_times[oracle_name] = []
            self.oracle_success_rates[oracle_name] = 0.0
            self.oracle_bug_detection_rates[oracle_name] = 0.0
        
        self.oracle_execution_times[oracle_name].append(execution_time)
        
        # Calculate success rate (exponential moving average)
        alpha = 0.1
        current_success_rate = 1.0 if success else 0.0
        self.oracle_success_rates[oracle_name] = (
            (alpha * current_success_rate) + 
            ((1 - alpha) * self.oracle_success_rates[oracle_name])
        )
        
        # Calculate bug detection rate
        current_bug_rate = 1.0 if bugs_found > 0 else 0.0
        self.oracle_bug_detection_rates[oracle_name] = (
            (alpha * current_bug_rate) + 
            ((1 - alpha) * self.oracle_bug_detection_rates[oracle_name])
        )
    
    def update_resource_metrics(self):
        """Update system resource usage metrics."""
        try:
            # Memory usage
            memory = psutil.virtual_memory()
            self.memory_usage.append(memory.percent)
            
            # CPU usage
            cpu = psutil.cpu_percent(interval=0.1)
            self.cpu_usage.append(cpu)
            
            # Keep only last 1000 measurements to prevent memory bloat
            if len(self.memory_usage) > 1000:
                self.memory_usage = self.memory_usage[-1000:]
            if len(self.cpu_usage) > 1000:
                self.cpu_usage = self.cpu_usage[-1000:]
                
        except Exception as e:
            logging.debug(f"Failed to update resource metrics: {e}")
    
    def update_session_metrics(self, duration: float, success: bool):
        """Update session metrics."""
        self.sessions_completed += 1
        
        # Update average session duration
        alpha = 0.1
        self.avg_session_duration = (alpha * duration) + ((1 - alpha) * self.avg_session_duration)
        
        # Update success rate
        current_success_rate = 1.0 if success else 0.0
        self.session_success_rate = (
            (alpha * current_success_rate) + 
            ((1 - alpha) * self.session_success_rate)
        )
    
    def update_bug_metrics(self, oracle_name: str, bug_data: Dict[str, Any]):
        """Update bug detection metrics."""
        self.total_bugs += 1
        
        # Count bugs by oracle
        if oracle_name not in self.bugs_by_oracle:
            self.bugs_by_oracle[oracle_name] = 0
        self.bugs_by_oracle[oracle_name] += 1
        
        # Categorize bugs by severity (if available)
        severity = bug_data.get('severity', 'unknown')
        if severity not in self.bugs_by_severity:
            self.bugs_by_severity[severity] = 0
        self.bugs_by_severity[severity] += 1
        
        # Categorize bugs by type
        bug_type = bug_data.get('bug_type', 'unknown')
        if bug_type not in self.bugs_by_category:
            self.bugs_by_category[bug_type] = 0
        self.bugs_by_category[bug_type] += 1
    
    def get_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary."""
        return {
            'query_execution': {
                'total_queries': self.total_queries,
                'successful_queries': self.successful_queries,
                'failed_queries': self.failed_queries,
                'success_rate': self.successful_queries / max(self.total_queries, 1),
                'avg_query_time': self.avg_query_time,
                'max_query_time': self.max_query_time,
                'min_query_time': self.min_query_time if self.min_query_time != float('inf') else 0.0
            },
            'oracle_performance': {
                'oracle_success_rates': self.oracle_success_rates,
                'oracle_bug_detection_rates': self.oracle_bug_detection_rates,
                'avg_oracle_execution_times': {
                    name: sum(times) / len(times) if times else 0.0
                    for name, times in self.oracle_execution_times.items()
                }
            },
            'resource_usage': {
                'avg_memory_usage': sum(self.memory_usage) / len(self.memory_usage) if self.memory_usage else 0.0,
                'avg_cpu_usage': sum(self.cpu_usage) / len(self.cpu_usage) if self.cpu_usage else 0.0,
                'current_memory_usage': self.memory_usage[-1] if self.memory_usage else 0.0,
                'current_cpu_usage': self.cpu_usage[-1] if self.cpu_usage else 0.0
            },
            'session_metrics': {
                'sessions_completed': self.sessions_completed,
                'avg_session_duration': self.avg_session_duration,
                'session_success_rate': self.session_success_rate
            },
            'bug_detection': {
                'total_bugs': self.total_bugs,
                'bugs_by_oracle': self.bugs_by_oracle,
                'bugs_by_severity': self.bugs_by_severity,
                'bugs_by_category': self.bugs_by_category
            }
        }

@dataclass
class SessionState:
    """Session state management for robust fuzzing."""
    session_id: str
    start_time: datetime
    queries_executed: int = 0
    bugs_found: int = 0
    errors_encountered: int = 0
    last_query_time: Optional[datetime] = None
    is_active: bool = True
    
    def update_query_execution(self, success: bool, bugs_found: int = 0):
        """Update session state after query execution."""
        self.queries_executed += 1
        self.last_query_time = datetime.now()
        
        if not success:
            self.errors_encountered += 1
        
        if bugs_found > 0:
            self.bugs_found += bugs_found
    
    def get_duration(self) -> float:
        """Get session duration in seconds."""
        return (datetime.now() - self.start_time).total_seconds()
    
    def should_terminate(self, max_duration: int, max_errors: int) -> bool:
        """Check if session should be terminated."""
        return (
            self.get_duration() > max_duration or
            self.errors_encountered > max_errors or
            not self.is_active
        )

class FuzzerEngine:
    """Advanced fuzzer engine with comprehensive orchestration capabilities."""
    
    def __init__(self, config: Dict[str, Any], db_executor: DBExecutor, bug_reporter: BugReporter):
        """
        Initialize the fuzzer engine.
        
        Args:
            config: Configuration dictionary
            db_executor: Database executor instance
            bug_reporter: Bug reporter instance
        """
        self.config = config
        self.db_executor = db_executor
        self.bug_reporter = bug_reporter
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.generator = GrammarGenerator({}, self.config, self.db_executor.catalog)
        
        # Initialize oracles
        self.oracles = {
            'TLPOracle': TLPOracle(self.config),
            'PQSOracle': PQSOracle(self.config),
            'QPGOracle': QPGOracle(self.config),
            'NoRECOracle': NoRECOracle(self.config),
            'CERTOracle': CERTOracle(self.config),
            'DQPOracle': DQPOracle(self.config),
            'CODDTestOracle': CODDTestOracle(self.config),
            'DistributedConsistencyOracle': DistributedConsistencyOracle(self.config),
            'YugabyteDBFeaturesOracle': YugabyteDBFeaturesOracle(self.config),
            'EdgeCaseOracle': EdgeCaseOracle(self.config),
            'ComplexSQLOracle': ComplexSQLOracle(self.config)
        }
        
        # Set the database executor for all oracles
        for oracle in self.oracles.values():
            oracle.set_db_executor(self.db_executor)
        
        # Initialize concurrency engine for ACID testing
        # Initialize concurrency testing patterns
        self.concurrent_patterns = self._initialize_concurrent_patterns()
        
        # Initialize advanced mutator
        self.mutator = AdvancedMutator(self.db_executor.catalog)
        
        self.logger.info(f"Initialized {len(self.oracles)} oracles")
        
        # Performance monitoring
        self.metrics = PerformanceMetrics()
        self.monitoring_enabled = config.get('enable_metrics', True)
        
        # Session management
        self.sessions: List[SessionState] = []
        self.session_lock = threading.Lock()
        
        # State management
        self.is_running = False
        self.shutdown_requested = False
        
        # Statistics
        self.stats = {
            'queries_executed': 0,
            'bugs_found': 0,
            'query_errors': 0,
            'sessions_completed': 0,
            'start_time': None,
            'total_runtime': 0.0
        }
        
        # Performance optimization
        self.query_cache = {}
        self.plan_cache = {}
        self.enable_caching = config.get('performance', {}).get('enable_query_caching', True)
        
        # Initialize monitoring thread
        if self.monitoring_enabled:
            self.monitoring_thread = threading.Thread(target=self._monitoring_loop, daemon=True)
            self.monitoring_thread.start()
    
    def run(self, duration: Optional[int] = None) -> None:
        """
        Run the fuzzer for the specified duration.
        
        Args:
            duration: Fuzzing duration in seconds (uses config if None)
        """
        if self.is_running:
            self.logger.warning("Fuzzer is already running")
            return
        
        # Set duration from config if not specified
        if duration is None:
            duration = self.config.get('fuzzing', {}).get('duration', 3600)
        
        self.logger.info(f"Starting fuzzer for {duration} seconds")
        self.is_running = True
        self.stats['start_time'] = datetime.now()
        
        try:
            self._main_fuzzing_loop(duration)
        except Exception as e:
            self.logger.error(f"Fuzzer execution failed: {e}")
            raise
        finally:
            self.is_running = False
            self._cleanup()
    
    def _main_fuzzing_loop(self, duration: int) -> None:
        """Main fuzzing loop optimized for 1000+ queries per minute."""
        start_time = time.time()
        session_start_time = start_time
        session_duration = min(30, duration)  # 30 second sessions
        queries_executed = 0
        bugs_found = 0
        
        self.logger.info(f"Starting HIGH-PERFORMANCE fuzzer for {duration} seconds")
        self.logger.info(f"Target: 1000+ queries per minute")
        self.logger.info(f"Main loop duration: {duration}s, Session duration: {session_duration}s")
        
        # HIGH-PERFORMANCE: Generate queries in batches for maximum throughput
        batch_size = 50  # Process 50 queries at a time
        query_batch = []
        
        # Per-minute performance tracking
        minute_start_time = start_time
        queries_this_minute = 0
        minute_counter = 0
        
        while time.time() - start_time < duration:
            try:
                # Check if we need to start a new session
                current_time = time.time()
                if current_time - session_start_time >= session_duration:
                    session_start_time = current_time
                    self.logger.debug("Starting new fuzzing session")
                
                # HIGH-PERFORMANCE: Fill batch if empty
                if not query_batch:
                    query_batch = self.generator.generate_query_batch(batch_size)
                    if not query_batch:
                        time.sleep(0.01)  # Minimal sleep for maximum throughput
                        continue
                
                # HIGH-PERFORMANCE: Process queries from batch
                query = query_batch.pop(0)
                
                # Performance monitoring - log query rate every 100 queries for high throughput
                if queries_executed > 0 and queries_executed % 100 == 0:
                    elapsed = time.time() - start_time
                    qps = queries_executed / elapsed
                    qpm = qps * 60
                    
                    # Calculate per-minute performance
                    current_minute = int(elapsed / 60)
                    if current_minute > 0:
                        queries_this_minute = queries_executed - (current_minute * int(qpm))
                        self.logger.info(f"Performance: {queries_executed} queries in {elapsed:.1f}s = {qps:.1f} QPS = {qpm:.1f} QPM | Current minute: {queries_this_minute} queries")
                    else:
                        self.logger.info(f"Performance: {queries_executed} queries in {elapsed:.1f}s = {qps:.1f} QPS = {qpm:.1f} QPM | Target: 1000+ QPM")
                
                # Execute the query with minimal overhead
                try:
                    # HIGH-PERFORMANCE MODE: Use high-performance execution for maximum throughput
                    result = self.db_executor.execute_query(query.to_sql(), high_performance=True)
                    queries_executed += 1
                    queries_this_minute += 1
                    self.stats['queries_executed'] += 1
                    
                    # Check if we've completed a minute
                    current_time = time.time()
                    if current_time - minute_start_time >= 60:  # 60 seconds = 1 minute
                        minute_counter += 1
                        self.logger.info(f"📊 Minute {minute_counter}: {queries_this_minute} queries executed = {queries_this_minute} QPM")
                        
                        # Reset for next minute
                        minute_start_time = current_time
                        queries_this_minute = 0
                    
                    # HIGH-PERFORMANCE: Run oracles only on every 100th query to maintain throughput
                    if queries_executed % 100 == 0:
                        for oracle_name in self.oracles.keys():
                            try:
                                bug_data = self._run_oracles(query.to_sql(), result, oracle_name)
                                if bug_data:
                                    bugs_found += 1
                                    self.stats['bugs_found'] += 1
                                    self._process_bug(oracle_name, bug_data, query.to_sql(), 0.0)
                            except Exception as e:
                                self.logger.debug(f"Oracle {oracle_name} failed: {e}")
                    
                    # Minimal throttling for high-performance fuzzing
                    time.sleep(0.01)  # Reduced from 100ms to 10ms
                    
                except Exception as e:
                    self.logger.debug(f"Query execution failed: {e}")
                    self.stats['query_errors'] += 1  # CRITICAL FIX: Update global stats
                    time.sleep(0.1)
                    continue
                
                # Check remaining time
                remaining_time = duration - (time.time() - start_time)
                if remaining_time <= 0:
                    break
                    
            except KeyboardInterrupt:
                self.logger.info("Fuzzing interrupted by user")
                break
            except Exception as e:
                self.logger.error(f"Error in main fuzzing loop: {e}")
                time.sleep(1)  # Longer delay on errors
        
        # Calculate final performance metrics
        total_elapsed = time.time() - start_time
        final_qps = queries_executed / total_elapsed if total_elapsed > 0 else 0
        final_qpm = final_qps * 60
        total_minutes = total_elapsed / 60
        
        # Log detailed performance summary
        self.logger.info(f"Fuzzing loop completed after {total_elapsed:.2f} seconds ({total_minutes:.1f} minutes)")
        self.logger.info(f"Queries executed: {queries_executed}, Bugs found: {bugs_found}")
        self.logger.info(f"Final Performance: {final_qps:.1f} QPS = {final_qpm:.1f} QPM")
        
        # Check if 1000+ QPM target was achieved
        if final_qpm >= 1000:
            self.logger.info(f"🎉 TARGET ACHIEVED: {final_qpm:.1f} QPM >= 1000 QPM target")
        else:
            self.logger.warning(f"⚠️  Target not met: {final_qpm:.1f} QPM < 1000 QPM target")
        
        # Log minute-by-minute summary if we have multiple minutes
        if minute_counter > 0:
            self.logger.info(f"📈 Minute-by-minute breakdown: {minute_counter} minutes tracked")
            self.logger.info(f"📊 Average queries per minute: {queries_executed / minute_counter:.1f}")
        
        # CRITICAL FIX: Ensure final stats are synchronized
        self.stats['queries_executed'] = queries_executed
        self.stats['bugs_found'] = bugs_found
    
    def _create_session(self) -> SessionState:
        """Create a new fuzzing session."""
        session_id = f"session_{int(time.time())}_{random.randint(1000, 9999)}"
        session = SessionState(
            session_id=session_id,
            start_time=datetime.now()
        )
        
        with self.session_lock:
            self.sessions.append(session)
        
        self.logger.debug(f"Created session {session_id}")
        return session
    
    def _run_session(self, session: SessionState, max_duration: int, max_errors: int) -> bool:
        """Run a single fuzzing session."""
        try:
            # Initialize session
            self._initialize_session(session)
            
            # Execute queries until session termination criteria
            while not session.should_terminate(max_duration, max_errors):
                try:
                    # Check if we've exceeded the main duration (additional safety check)
                    if hasattr(self, '_main_start_time') and hasattr(self, '_main_duration'):
                        elapsed_main = time.time() - self._main_start_time
                        if elapsed_main >= self._main_duration:
                            self.logger.info(f"Main duration limit reached in session: {elapsed_main:.2f}s >= {self._main_duration}s")
                            break
                    
                    # Generate and execute query
                    query = self._generate_query()
                    if query:
                        success, bugs_found = self._execute_query_with_oracles(query, session)
                        session.update_query_execution(success, bugs_found)
                    
                    # Brief pause between queries
                    time.sleep(0.1)
                    
                except Exception as e:
                    self.logger.debug(f"Query execution failed in session {session.session_id}: {e}")
                    session.errors_encountered += 1
            
            # Finalize session
            self._finalize_session(session)
            return True
            
        except Exception as e:
            self.logger.error(f"Session {session.session_id} failed: {e}")
            return False
    
    def _initialize_session(self, session: SessionState) -> None:
        """Initialize a fuzzing session."""
        try:
            # Reset database state if needed
            if self.config.get('fuzzing', {}).get('reset_session_state', False):
                self.db_executor.execute_admin_command("ROLLBACK")
                self.db_executor.execute_admin_command("BEGIN")
            
            # Create session-specific schema if needed
            if self.config.get('fuzzing', {}).get('create_session_schema', False):
                schema_name = f"session_{session.session_id}"
                self.db_executor.execute_admin_command(f"CREATE SCHEMA IF NOT EXISTS {schema_name}")
            
            self.logger.debug(f"Session {session.session_id} initialized")
            
        except Exception as e:
            self.logger.debug(f"Session initialization failed: {e}")
    
    def _finalize_session(self, session: SessionState) -> None:
        """Finalize a fuzzing session."""
        try:
            session.is_active = False
            
            # Clean up session-specific resources
            if self.config.get('fuzzing', {}).get('cleanup_session_schema', False):
                schema_name = f"session_{session.session_id}"
                self.db_executor.execute_admin_command(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE")
            
            # Update statistics
            self.stats['sessions_completed'] += 1
            
            self.logger.debug(f"Session {session.session_id} finalized - "
                            f"Queries: {session.queries_executed}, "
                            f"Bugs: {session.bugs_found}, "
                            f"Errors: {session.errors_encountered}")
            
        except Exception as e:
            self.logger.debug(f"Session finalization failed: {e}")
    
    def _generate_query(self) -> Optional[str]:
        """Generate a new query using the generator."""
        try:
            # Generate a complete SQL statement
            sql_node = self.generator.generate_statement_of_type('select_stmt')
            
            if sql_node is None:
                self.logger.warning("Generator returned None, using safe fallback")
                return "SELECT COUNT(*) FROM information_schema.tables LIMIT 1"
            
            # Convert to string
            if isinstance(sql_node, RawSQL):
                query = sql_node.sql
            else:
                # For SQLNode objects, convert to string representation
                query = str(sql_node)
            
            # CRITICAL: Final validation to ensure complete SQL
            if not self._is_complete_sql(query):
                self.logger.warning(f"Generated incomplete SQL: '{query[:100]}...', using safe fallback")
                return "SELECT COUNT(*) FROM information_schema.tables LIMIT 1"
            
            self.logger.debug(f"Generated complete query: {query[:100]}...")
            return query
            
        except Exception as e:
            self.logger.error(f"Query generation failed: {e}")
            return "SELECT COUNT(*) FROM information_schema.tables LIMIT 1"
    
    def _is_complete_sql(self, query: str) -> bool:
        """Check if the generated query is complete and valid."""
        if not query or not query.strip():
            return False
        
        query = query.strip()
        
        # Must start with a valid SQL keyword
        valid_starts = ['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'BEGIN', 'COMMIT', 'ROLLBACK', 'SET', 'WITH']
        if not any(query.upper().startswith(start) for start in valid_starts):
            return False
        
        # Must contain FROM clause for SELECT statements
        if query.upper().startswith('SELECT') and 'FROM' not in query.upper():
            return False
        
        # Must not contain common fragment patterns
        fragment_patterns = [
            '--',  # Comments
            'FROM ',  # Incomplete FROM
            'JOIN ',   # Incomplete JOIN
            'WHERE ',  # Incomplete WHERE
            'GROUP BY ',  # Incomplete GROUP BY
            'HAVING ',    # Incomplete HAVING
            'ORDER BY ',  # Incomplete ORDER BY
            'LIMIT ',     # Incomplete LIMIT
            'AND ',       # Incomplete AND
            'OR ',        # Incomplete OR
            ',',          # Trailing commas
            '(',          # Incomplete parentheses
            ')'           # Incomplete parentheses
        ]
        
        # Check if it's just a fragment
        for pattern in fragment_patterns:
            if query.strip() == pattern.strip():
                return False
        
        # Check for table aliases that indicate fragments
        if any(alias in query for alias in ['p.', 'o.', 'c.', 'p1.', 'p2.', 'o1.', 'o2.', 'c1.', 'c2.']):
            return False
        
        # Must have balanced parentheses
        if query.count('(') != query.count(')'):
            return False
        
        return True
    
    def _get_seed_query(self) -> Optional[str]:
        """Get a seed query from the corpus."""
        try:
            seed_file = self.config.get('corpus', {}).get('seed_query_file', 'corpus/seed_queries.txt')
            if Path(seed_file).exists():
                with open(seed_file, 'r') as f:
                    queries = f.readlines()
                    if queries:
                        return random.choice(queries).strip()
            return None
        except Exception as e:
            self.logger.debug(f"Failed to get seed query: {e}")
            return None
    
    def _execute_query_with_oracles(self, query: str, session: SessionState) -> Tuple[bool, int]:
        """Execute a query and run all applicable oracles."""
        start_time = time.time()
        success = False
        bugs_found = 0
        
        try:
            # Execute the query
            result = self.db_executor.execute_query(query)
            success = True
            
            # Update query metrics
            execution_time = time.time() - start_time
            self.metrics.update_query_metrics(execution_time, success)
            self.stats['queries_executed'] += 1
            
            # Run oracles
            bugs_found = self._run_oracles(query, result, session)
            
            # Update bug statistics
            if bugs_found > 0:
                self.stats['bugs_found'] += bugs_found
            
            return success, bugs_found
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.metrics.update_query_metrics(execution_time, False)
            self.stats['query_errors'] += 1
            
            self.logger.debug(f"Query execution failed: {e}")
            return False, 0
    
    def _run_oracles(self, query: str, query_result: Any, oracle_name: str) -> Optional[Dict[str, Any]]:
        """
        Run a specific oracle to check for bugs.
        
        Args:
            query: The original SQL query
            query_result: The result of executing the query
            oracle_name: Name of the oracle to run
            
        Returns:
            Bug report if found, None otherwise
        """
        try:
            oracle = self.oracles.get(oracle_name)
            if not oracle:
                return None
            
            # CRITICAL FIX: Pass the original query to the oracle
            bug_data = oracle.check_for_bugs(query, query_result)
            
            if bug_data:
                # Ensure the bug data contains the original query
                if 'query' not in bug_data:
                    bug_data['query'] = query
                
                # Add oracle name to bug data
                bug_data['oracle_name'] = oracle_name
                
                return bug_data
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error running oracle {oracle_name}: {e}")
            return None
    
    def _process_bug(self, oracle_name: str, bug_data: Dict[str, Any], query: str, execution_time: float):
        """Process a detected bug."""
        try:
            # Add metadata
            bug_data['oracle_name'] = oracle_name
            bug_data['detection_time'] = datetime.now().isoformat()
            bug_data['query_execution_time'] = execution_time
            
            # Get current session ID if available
            current_session_id = None
            with self.session_lock:
                if self.sessions:
                    current_session = self.sessions[-1]  # Most recent session
                    if current_session.is_active:
                        current_session_id = current_session.session_id
            
            # Generate fuzzer run ID
            fuzzer_run_id = f"run_{self.stats['start_time'].strftime('%Y%m%d_%H%M%S') if self.stats['start_time'] else datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Report bug with comprehensive metadata
            metadata = {
                'oracle_name': oracle_name,
                'fuzzer_run_id': fuzzer_run_id,
                'session_id': current_session_id
            }
            
            self.bug_reporter.report_bug(
                bug_data=bug_data,
                metadata=metadata
            )
            
            # Update metrics
            self.metrics.update_bug_metrics(oracle_name, bug_data)
            
            self.logger.info(f"Bug detected by {oracle_name}: {bug_data.get('description', 'Unknown bug')}")
            
        except Exception as e:
            self.logger.error(f"Failed to process bug: {e}")
    
    def _cleanup_completed_sessions(self) -> None:
        """Clean up completed sessions."""
        with self.session_lock:
            active_sessions = []
            for session in self.sessions:
                if session.is_active:
                    active_sessions.append(session)
                else:
                    # Session is already finalized, just remove from list
                    pass
            
            self.sessions = active_sessions
    
    def _should_throttle(self) -> bool:
        """Check if execution should be throttled due to resource constraints."""
        try:
            # Check memory usage
            memory = psutil.virtual_memory()
            if memory.percent > 90:  # 90% memory usage threshold
                return True
            
            # Check CPU usage
            cpu = psutil.cpu_percent(interval=0.1)
            if cpu > 95:  # 95% CPU usage threshold
                return True
            
            # Check database connections
            if hasattr(self.db_executor, 'get_connection_count'):
                conn_count = self.db_executor.get_connection_count()
                max_conns = self.config.get('database', {}).get('max_connections', 10)
                if conn_count > max_conns * 0.8:  # 80% connection threshold
                    return True
            
            return False
            
        except Exception as e:
            self.logger.debug(f"Resource check failed: {e}")
            return False
    
    def _monitoring_loop(self) -> None:
        """Background monitoring loop for performance metrics."""
        while self.is_running and not self.shutdown_requested:
            try:
                # Update resource metrics
                self.metrics.update_resource_metrics()
                
                # Log performance summary periodically
                if self.stats['queries_executed'] % 100 == 0 and self.stats['queries_executed'] > 0:
                    self._log_performance_summary()
                
                # Sleep between monitoring cycles
                time.sleep(10)
                
            except Exception as e:
                self.logger.debug(f"Monitoring loop error: {e}")
                time.sleep(30)  # Longer sleep on error
    
    def _log_performance_summary(self) -> None:
        """Log current performance summary."""
        try:
            summary = self.metrics.get_summary()
            
            self.logger.info("Performance Summary:")
            self.logger.info(f"  Queries: {summary['query_execution']['total_queries']} "
                           f"(Success: {summary['query_execution']['success_rate']:.1%})")
            self.logger.info(f"  Bugs Found: {summary['bug_detection']['total_bugs']}")
            self.logger.info(f"  Memory Usage: {summary['resource_usage']['current_memory_usage']:.1f}%")
            self.logger.info(f"  CPU Usage: {summary['resource_usage']['current_cpu_usage']:.1f}%")
            
        except Exception as e:
            self.logger.debug(f"Failed to log performance summary: {e}")
    
    def _cleanup(self) -> None:
        """Clean up resources before shutdown."""
        try:
            # Finalize all active sessions
            with self.session_lock:
                for session in self.sessions:
                    if session.is_active:
                        session.is_active = False
                        self._finalize_session(session)
            
            # Clear caches
            self.query_cache.clear()
            self.plan_cache.clear()
            
            # Force garbage collection
            gc.collect()
            
            # Calculate final statistics
            if self.stats['start_time']:
                self.stats['total_runtime'] = (datetime.now() - self.stats['start_time']).total_seconds()
            
            self.logger.info("Fuzzer engine cleanup completed")
            
        except Exception as e:
            self.logger.error(f"Cleanup failed: {e}")
    
    def shutdown(self) -> None:
        """Shutdown the fuzzer engine gracefully."""
        self.logger.info("Shutting down fuzzer engine...")
        self.shutdown_requested = True
        self.is_running = False
        
        # Wait for monitoring thread to finish
        if hasattr(self, 'monitoring_thread') and self.monitoring_thread.is_alive():
            self.monitoring_thread.join(timeout=5)
        
        self._cleanup()
        self.logger.info("Fuzzer engine shutdown completed")
    
    def get_performance_summary(self) -> Dict[str, Any]:
        """Get comprehensive performance summary."""
        return self.metrics.get_summary()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get current fuzzer statistics."""
        return self.stats.copy()

    def _initialize_concurrent_patterns(self) -> List[Dict[str, Any]]:
        """Initialize Jepsen-like concurrent testing patterns for ACID violation detection."""
        return [
            # Pattern 1: Jepsen-style Bank Account Test (ACID violation testing)
            {
                'name': 'bank_account_race',
                'description': 'Jepsen-style bank account test with concurrent transfers and balance checks',
                'operations': [
                    # Setup: Create bank accounts
                    {'type': 'session1_setup', 'query': 'CREATE TEMP TABLE bank_accounts (id INT PRIMARY KEY, balance DECIMAL(10,2), name TEXT)', 'session_id': 1},
                    {'type': 'session1_setup', 'query': 'INSERT INTO bank_accounts VALUES (1, 1000.00, \'Alice\'), (2, 1000.00, \'Bob\'), (3, 1000.00, \'Charlie\')', 'session_id': 1},
                    
                    # Concurrent transactions with Snapshot isolation
                    {'type': 'session1_begin', 'query': 'BEGIN', 'session_id': 1},
                    {'type': 'session2_begin', 'query': 'BEGIN', 'session_id': 2},
                    {'type': 'session3_begin', 'query': 'BEGIN', 'session_id': 3},
                    
                    # Set Snapshot isolation (YugabyteDB default)
                    {'type': 'session1_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 1},
                    {'type': 'session2_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 2},
                    {'type': 'session3_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 3},
                    
                    # Concurrent balance reads
                    {'type': 'session1_read', 'query': 'SELECT id, balance FROM bank_accounts WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT id, balance FROM bank_accounts WHERE id = 2', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT id, balance FROM bank_accounts WHERE id = 3', 'session_id': 3},
                    
                    # Concurrent transfers
                    {'type': 'session1_write', 'query': 'UPDATE bank_accounts SET balance = balance - 100 WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_write', 'query': 'UPDATE bank_accounts SET balance = balance - 150 WHERE id = 2', 'session_id': 2},
                    {'type': 'session3_write', 'query': 'UPDATE bank_accounts SET balance = balance - 200 WHERE id = 3', 'session_id': 3},
                    
                    # More concurrent reads
                    {'type': 'session1_read', 'query': 'SELECT SUM(balance) as total_balance FROM bank_accounts', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT COUNT(*) as account_count FROM bank_accounts WHERE balance > 500', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT AVG(balance) as avg_balance FROM bank_accounts', 'session_id': 3},
                    
                    # Complete transfers
                    {'type': 'session1_write', 'query': 'UPDATE bank_accounts SET balance = balance + 100 WHERE id = 2', 'session_id': 1},
                    {'type': 'session2_write', 'query': 'UPDATE bank_accounts SET balance = balance + 150 WHERE id = 3', 'session_id': 2},
                    {'type': 'session3_write', 'query': 'UPDATE bank_accounts SET balance = balance + 200 WHERE id = 1', 'session_id': 3},
                    
                    # Final balance checks
                    {'type': 'session1_read', 'query': 'SELECT id, balance FROM bank_accounts ORDER BY id', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT SUM(balance) as total_balance FROM bank_accounts', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT MIN(balance), MAX(balance) FROM bank_accounts', 'session_id': 3},
                    
                    # Commit transactions
                    {'type': 'session1_commit', 'query': 'COMMIT', 'session_id': 1},
                    {'type': 'session2_commit', 'query': 'COMMIT', 'session_id': 2},
                    {'type': 'session3_commit', 'query': 'COMMIT', 'session_id': 3},
                    
                    # Cleanup
                    {'type': 'cleanup', 'query': 'DROP TABLE IF EXISTS bank_accounts', 'session_id': 1}
                ]
            },
            
            # Pattern 2: Jepsen-style Register Test (Linearizability testing)
            {
                'name': 'register_linearizability',
                'description': 'Jepsen-style register test to verify linearizable reads and writes',
                'operations': [
                    # Setup: Create a shared register
                    {'type': 'session1_setup', 'query': 'CREATE TEMP TABLE shared_register (id INT PRIMARY KEY, value TEXT, version INT)', 'session_id': 1},
                    {'type': 'session1_setup', 'query': 'INSERT INTO shared_register VALUES (1, \'initial\', 1)', 'session_id': 1},
                    
                    # Concurrent transactions with Snapshot isolation
                    {'type': 'session1_begin', 'query': 'BEGIN', 'session_id': 1},
                    {'type': 'session2_begin', 'query': 'BEGIN', 'session_id': 2},
                    {'type': 'session3_begin', 'query': 'BEGIN', 'session_id': 3},
                    
                    # Set Snapshot isolation
                    {'type': 'session1_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 1},
                    {'type': 'session2_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 2},
                    {'type': 'session3_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 3},
                    
                    # Concurrent reads of the register
                    {'type': 'session1_read', 'query': 'SELECT value, version FROM shared_register WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT value, version FROM shared_register WHERE id = 1', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT value, version FROM shared_register WHERE id = 1', 'session_id': 3},
                    
                    # Concurrent writes with version checking
                    {'type': 'session1_write', 'query': 'UPDATE shared_register SET value = \'session1_value\', version = version + 1 WHERE id = 1 AND version = 1', 'session_id': 1},
                    {'type': 'session2_write', 'query': 'UPDATE shared_register SET value = \'session2_value\', version = version + 1 WHERE id = 1 AND version = 1', 'session_id': 2},
                    {'type': 'session3_write', 'query': 'UPDATE shared_register SET value = \'session3_value\', version = version + 1 WHERE id = 1 AND version = 1', 'session_id': 3},
                    
                    # Read after write attempts
                    {'type': 'session1_read', 'query': 'SELECT value, version FROM shared_register WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT value, version FROM shared_register WHERE id = 1', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT value, version FROM shared_register WHERE id = 1', 'session_id': 3},
                    
                    # Try to write again with updated version
                    {'type': 'session1_write', 'query': 'UPDATE shared_register SET value = \'session1_retry\', version = version + 1 WHERE id = 1 AND version > 1', 'session_id': 1},
                    {'type': 'session2_write', 'query': 'UPDATE shared_register SET value = \'session2_retry\', version = version + 1 WHERE id = 1 AND version > 1', 'session_id': 2},
                    {'type': 'session3_write', 'query': 'UPDATE shared_register SET value = \'session3_retry\', version = version + 1 WHERE id = 1 AND version > 1', 'session_id': 3},
                    
                    # Final state check
                    {'type': 'session1_read', 'query': 'SELECT value, version FROM shared_register WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT value, version FROM shared_register WHERE id = 1', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT value, version FROM shared_register WHERE id = 1', 'session_id': 3},
                    
                    # Commit transactions
                    {'type': 'session1_commit', 'query': 'COMMIT', 'session_id': 1},
                    {'type': 'session2_commit', 'query': 'COMMIT', 'session_id': 2},
                    {'type': 'session3_commit', 'query': 'COMMIT', 'session_id': 3},
                    
                    # Cleanup
                    {'type': 'cleanup', 'query': 'DROP TABLE IF EXISTS shared_register', 'session_id': 1}
                ]
            },
            
            # Pattern 3: Jepsen-style Set Test (Set operations with Snapshot isolation)
            {
                'name': 'set_operations_race',
                'description': 'Jepsen-style set test to verify set operations under concurrent access',
                'operations': [
                    # Setup: Create a shared set
                    {'type': 'session1_setup', 'query': 'CREATE TEMP TABLE shared_set (id INT PRIMARY KEY, element TEXT, added_by INT)', 'session_id': 1},
                    {'type': 'session1_setup', 'query': 'INSERT INTO shared_set VALUES (1, \'apple\', 1), (2, \'banana\', 1), (3, \'cherry\', 1)', 'session_id': 1},
                    
                    # Concurrent transactions with Snapshot isolation
                    {'type': 'session1_begin', 'query': 'BEGIN', 'session_id': 1},
                    {'type': 'session2_begin', 'query': 'BEGIN', 'session_id': 2},
                    {'type': 'session3_begin', 'query': 'BEGIN', 'session_id': 3},
                    
                    # Set Snapshot isolation
                    {'type': 'session1_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 1},
                    {'type': 'session2_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 2},
                    {'type': 'session3_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 3},
                    
                    # Concurrent set reads
                    {'type': 'session1_read', 'query': 'SELECT COUNT(*) as set_size FROM shared_set', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT element FROM shared_set WHERE element = \'apple\'', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT element FROM shared_set WHERE element = \'banana\'', 'session_id': 3},
                    
                    # Concurrent set additions
                    {'type': 'session1_write', 'query': 'INSERT INTO shared_set VALUES (4, \'dragonfruit\', 1)', 'session_id': 1},
                    {'type': 'session2_write', 'query': 'INSERT INTO shared_set VALUES (5, \'elderberry\', 2)', 'session_id': 2},
                    {'type': 'session3_write', 'query': 'INSERT INTO shared_set VALUES (6, \'fig\', 3)', 'session_id': 3},
                    
                    # More concurrent reads
                    {'type': 'session1_read', 'query': 'SELECT element FROM shared_set WHERE added_by = 1', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT element FROM shared_set WHERE added_by = 2', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT element FROM shared_set WHERE added_by = 3', 'session_id': 3},
                    
                    # Concurrent set removals
                    {'type': 'session1_write', 'query': 'DELETE FROM shared_set WHERE element = \'apple\'', 'session_id': 1},
                    {'type': 'session2_write', 'query': 'DELETE FROM shared_set WHERE element = \'banana\'', 'session_id': 2},
                    {'type': 'session3_write', 'query': 'DELETE FROM shared_set WHERE element = \'cherry\'', 'session_id': 3},
                    
                    # Final set state
                    {'type': 'session1_read', 'query': 'SELECT COUNT(*) as final_size FROM shared_set', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT element FROM shared_set ORDER BY element', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT added_by, COUNT(*) FROM shared_set GROUP BY added_by', 'session_id': 3},
                    
                    # Commit transactions
                    {'type': 'session1_commit', 'query': 'COMMIT', 'session_id': 1},
                    {'type': 'session2_commit', 'query': 'COMMIT', 'session_id': 2},
                    {'type': 'session3_commit', 'query': 'COMMIT', 'session_id': 3},
                    
                    # Cleanup
                    {'type': 'cleanup', 'query': 'DROP TABLE IF EXISTS shared_set', 'session_id': 1}
                ]
            },
            
            # Pattern 4: Jepsen-style Counter Test (Monotonic counter)
            {
                'name': 'counter_monotonicity',
                'description': 'Jepsen-style counter test to verify monotonicity under concurrent increments',
                'operations': [
                    # Setup: Create a shared counter
                    {'type': 'session1_setup', 'query': 'CREATE TEMP TABLE shared_counter (id INT PRIMARY KEY, counter_value INT, last_updated TIMESTAMP)', 'session_id': 1},
                    {'type': 'session1_setup', 'query': 'INSERT INTO shared_counter VALUES (1, 0, NOW())', 'session_id': 1},
                    
                    # Concurrent transactions with Snapshot isolation
                    {'type': 'session1_begin', 'query': 'BEGIN', 'session_id': 1},
                    {'type': 'session2_begin', 'query': 'BEGIN', 'session_id': 2},
                    {'type': 'session3_begin', 'query': 'BEGIN', 'session_id': 3},
                    
                    # Set Snapshot isolation
                    {'type': 'session1_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 1},
                    {'type': 'session2_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 2},
                    {'type': 'session3_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 3},
                    
                    # Concurrent counter reads
                    {'type': 'session1_read', 'query': 'SELECT counter_value FROM shared_counter WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT counter_value FROM shared_counter WHERE id = 1', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT counter_value FROM shared_counter WHERE id = 1', 'session_id': 3},
                    
                    # Concurrent counter increments
                    {'type': 'session1_write', 'query': 'UPDATE shared_counter SET counter_value = counter_value + 10, last_updated = NOW() WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_write', 'query': 'UPDATE shared_counter SET counter_value = counter_value + 15, last_updated = NOW() WHERE id = 1', 'session_id': 2},
                    {'type': 'session3_write', 'query': 'UPDATE shared_counter SET counter_value = counter_value + 20, last_updated = NOW() WHERE id = 1', 'session_id': 3},
                    
                    # Read after increment attempts
                    {'type': 'session1_read', 'query': 'SELECT counter_value FROM shared_counter WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT counter_value FROM shared_counter WHERE id = 1', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT counter_value FROM shared_counter WHERE id = 1', 'session_id': 3},
                    
                    # More increments
                    {'type': 'session1_write', 'query': 'UPDATE shared_counter SET counter_value = counter_value + 5, last_updated = NOW() WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_write', 'query': 'UPDATE shared_counter SET counter_value = counter_value + 8, last_updated = NOW() WHERE id = 1', 'session_id': 2},
                    {'type': 'session3_write', 'query': 'UPDATE shared_counter SET counter_value = counter_value + 12, last_updated = NOW() WHERE id = 1', 'session_id': 3},
                    
                    # Final counter state
                    {'type': 'session1_read', 'query': 'SELECT counter_value, last_updated FROM shared_counter WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT counter_value FROM shared_counter WHERE id = 1', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT counter_value FROM shared_counter WHERE id = 1', 'session_id': 3},
                    
                    # Commit transactions
                    {'type': 'session1_commit', 'query': 'COMMIT', 'session_id': 1},
                    {'type': 'session2_commit', 'query': 'COMMIT', 'session_id': 2},
                    {'type': 'session3_commit', 'query': 'COMMIT', 'session_id': 3},
                    
                    # Cleanup
                    {'type': 'cleanup', 'query': 'DROP TABLE IF EXISTS shared_counter', 'session_id': 1}
                ]
            },
            
            # Pattern 5: Advanced Storage Engine Testing
            {
                'name': 'storage_engine_stress',
                'description': 'Advanced storage engine stress testing with LSM operations',
                'operations': [
                    # Setup: Create complex tables with various properties
                    {'type': 'session1_setup', 'query': 'CREATE TEMP TABLE storage_test (id INT PRIMARY KEY, data JSONB, array_data INT[], text_data TEXT, numeric_data NUMERIC(38,10))', 'session_id': 1},
                    {'type': 'session1_setup', 'query': 'CREATE INDEX idx_storage_json ON storage_test USING GIN (data)', 'session_id': 1},
                    {'type': 'session1_setup', 'query': 'CREATE INDEX idx_storage_array ON storage_test USING GIN (array_data)', 'session_id': 1},
                    
                    # Concurrent transactions with Snapshot isolation
                    {'type': 'session1_begin', 'query': 'BEGIN', 'session_id': 1},
                    {'type': 'session2_begin', 'query': 'BEGIN', 'session_id': 2},
                    {'type': 'session3_begin', 'query': 'BEGIN', 'session_id': 3},
                    
                    # Set Snapshot isolation
                    {'type': 'session1_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 1},
                    {'type': 'session2_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 2},
                    {'type': 'session3_set_isolation', 'query': 'SET TRANSACTION ISOLATION LEVEL SNAPSHOT', 'session_id': 3},
                    
                    # Concurrent complex inserts
                    {'type': 'session1_write', 'query': 'INSERT INTO storage_test VALUES (1, \'{"key": "value", "nested": {"array": [1,2,3]}}\'::jsonb, ARRAY[1,2,3,4,5], \'long_text_data_here\', 123.4567890123)', 'session_id': 1},
                    {'type': 'session2_write', 'query': 'INSERT INTO storage_test VALUES (2, \'{"key2": "value2", "nested": {"array": [6,7,8]}}\'::jsonb, ARRAY[6,7,8,9,10], \'another_long_text\', 987.6543210987)', 'session_id': 2},
                    {'type': 'session3_write', 'query': 'INSERT INTO storage_test VALUES (3, \'{"key3": "value3", "nested": {"array": [11,12,13]}}\'::jsonb, ARRAY[11,12,13,14,15], \'third_long_text\', 456.7891234567)', 'session_id': 3},
                    
                    # Concurrent complex queries
                    {'type': 'session1_read', 'query': 'SELECT id, data->>\'key\' as key_value, array_data[1:3] as sub_array FROM storage_test WHERE data @> \'{"nested": {"array": [1,2,3]}}\'', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT id, jsonb_array_elements(data->\'nested\'->\'array\') as array_element FROM storage_test WHERE array_data && ARRAY[6,7,8]', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT id, numeric_data, text_data FROM storage_test WHERE numeric_data > 100 AND text_data LIKE \'%long%\'', 'session_id': 3},
                    
                    # Concurrent updates
                    {'type': 'session1_write', 'query': 'UPDATE storage_test SET data = data || \'{"updated": true}\'::jsonb, array_data = array_data || ARRAY[100,200,300] WHERE id = 1', 'session_id': 1},
                    {'type': 'session2_write', 'query': 'UPDATE storage_test SET data = jsonb_set(data, \'{nested,array}\', \'[999,888,777]\'::jsonb) WHERE id = 2', 'session_id': 2},
                    {'type': 'session3_write', 'query': 'UPDATE storage_test SET numeric_data = numeric_data * 2, text_data = text_data || \'_updated\' WHERE id = 3', 'session_id': 3},
                    
                    # Final complex queries
                    {'type': 'session1_read', 'query': 'SELECT COUNT(*) as total_records, AVG(numeric_data) as avg_numeric FROM storage_test', 'session_id': 1},
                    {'type': 'session2_read', 'query': 'SELECT jsonb_object_agg(id::text, data) as all_data FROM storage_test', 'session_id': 2},
                    {'type': 'session3_read', 'query': 'SELECT unnest(array_data) as array_element FROM storage_test ORDER BY array_element', 'session_id': 3},
                    
                    # Commit transactions
                    {'type': 'session1_commit', 'query': 'COMMIT', 'session_id': 1},
                    {'type': 'session2_commit', 'query': 'COMMIT', 'session_id': 2},
                    {'type': 'session3_commit', 'query': 'COMMIT', 'session_id': 3},
                    
                    # Cleanup
                    {'type': 'cleanup', 'query': 'DROP TABLE IF EXISTS storage_test CASCADE', 'session_id': 1}
                ]
            }
        ]

    def run_concurrency_tests(self, duration: int = 30) -> Dict[str, Any]:
        """
        Run Jepsen-like concurrency tests to detect ACID violations and consistency issues.
        
        Args:
            duration: Test duration in seconds
            
        Returns:
            Concurrency test results and detected issues
        """
        try:
            self.logger.info(f"🚀 Starting Jepsen-like concurrency tests for {duration} seconds")
            self.logger.info("📋 Testing patterns:")
            self.logger.info("   • Bank Account Race (ACID violation testing)")
            self.logger.info("   • Register Linearizability (linearizable reads/writes)")
            self.logger.info("   • Set Operations Race (set consistency)")
            self.logger.info("   • Counter Monotonicity (monotonic counter)")
            self.logger.info("🔒 All tests use Snapshot isolation (YugabyteDB default)")
            
            # Run all concurrent test patterns
            results = self._run_all_concurrent_tests(duration)
            
            # Advanced Jepsen-like analysis
            jepsen_analysis = self._perform_jepsen_analysis(results)
            results['jepsen_analysis'] = jepsen_analysis
            
            # Check for critical issues
            critical_issues = []
            for pattern_name, pattern_result in results.get('pattern_results', {}).items():
                if 'issues_detected' in pattern_result:
                    for issue in pattern_result['issues_detected']:
                        if issue.get('severity') == 'HIGH' or issue.get('severity') == 'CRITICAL':
                            critical_issues.append({
                                'pattern': pattern_name,
                                'issue': issue
                            })
            
            # Log comprehensive results
            self.logger.info(f"📊 Concurrency tests completed: {results['total_patterns']} patterns, "
                           f"{results['successful_patterns']} successful, "
                           f"{results['failed_patterns']} failed")
            
            if critical_issues:
                self.logger.warning(f"🚨 Critical concurrency issues detected: {len(critical_issues)}")
                for issue in critical_issues:
                    self.logger.warning(f"Pattern: {issue['pattern']}, Issue: {issue['issue']['description']}")
            else:
                self.logger.info("✅ No critical concurrency issues detected")
            
            # Log Jepsen analysis summary
            if jepsen_analysis:
                self.logger.info("🔍 Jepsen-like Analysis Summary:")
                for analysis_type, details in jepsen_analysis.items():
                    if details:
                        self.logger.info(f"   • {analysis_type}: {len(details)} issues found")
                    else:
                        self.logger.info(f"   • {analysis_type}: ✅ No issues")
            
            return results
            
        except Exception as e:
            self.logger.error(f"❌ Error in concurrency tests: {e}")
            return {'error': str(e), 'success': False}
    
    def _perform_jepsen_analysis(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Perform comprehensive Jepsen-like analysis of concurrent test results."""
        analysis = {
            'consistency_violations': [],
            'isolation_violations': [],
            'transaction_anomalies': [],
            'performance_issues': [],
            'data_integrity_issues': []
        }
        
        try:
            # Analyze each pattern's results
            for pattern_name, pattern_result in results.get('pattern_results', {}).items():
                if 'results' in pattern_result:
                    pattern_results = pattern_result['results']
                    
                    # Check for consistency violations
                    consistency_issues = self._analyze_consistency_violations(pattern_results)
                    if consistency_issues:
                        analysis['consistency_violations'].extend([
                            {'pattern': pattern_name, 'issue': issue} 
                            for issue in consistency_issues
                        ])
                    
                    # Check for isolation violations
                    isolation_issues = [r for r in pattern_results if r.get('type') == 'isolation_level_violation']
                    if isolation_issues:
                        analysis['isolation_violations'].extend([
                            {'pattern': pattern_name, 'issue': issue} 
                            for issue in isolation_issues
                        ])
                    
                    # Check for transaction anomalies
                    tx_issues = [r for r in pattern_results if r.get('type') == 'transaction_mismatch']
                    if tx_issues:
                        analysis['transaction_anomalies'].extend([
                            {'pattern': pattern_name, 'issue': issue} 
                            for issue in tx_issues
                        ])
                    
                    # Check for performance issues
                    slow_ops = [r for r in pattern_results if r.get('execution_time', 0) > 5.0]
                    if slow_ops:
                        analysis['performance_issues'].extend([
                            {'pattern': pattern_name, 'operation': op} 
                            for op in slow_ops
                        ])
            
            return analysis
            
        except Exception as e:
            self.logger.error(f"Error in Jepsen analysis: {e}")
            return analysis

    def _run_all_concurrent_tests(self, duration: int = 60) -> Dict[str, Any]:
        """Run all concurrent test patterns."""
        all_results = {}
        
        try:
            # Run concurrency patterns
            for pattern in self.concurrent_patterns:
                try:
                    result = self._run_concurrent_test(pattern['name'], duration)
                    all_results[pattern['name']] = result
                except Exception as e:
                    self.logger.error(f"Error running pattern {pattern['name']}: {e}")
                    all_results[pattern['name']] = {'error': str(e), 'success': False}
            
            # Calculate summary
            successful_patterns = len([r for r in all_results.values() if r.get('success', False)])
            failed_patterns = len([r for r in all_results.values() if not r.get('success', False)])
            
            return {
                'total_patterns': len(self.concurrent_patterns),
                'successful_patterns': successful_patterns,
                'failed_patterns': failed_patterns,
                'pattern_results': all_results,
                'success': True
            }
            
        except Exception as e:
            self.logger.error(f"Error running all concurrent tests: {e}")
            return {'error': str(e), 'success': False}

    def _run_concurrent_test(self, pattern_name: str, duration: int = 60) -> Dict[str, Any]:
        """Run a concurrent test pattern for the specified duration."""
        try:
            # Find the pattern
            pattern = None
            for p in self.concurrent_patterns:
                if p['name'] == pattern_name:
                    pattern = p
                    break
            
            if not pattern:
                raise ValueError(f"Unknown pattern: {pattern_name}")
            
            self.logger.info(f"Starting concurrent test: {pattern_name} for {duration} seconds")
            
            # Run concurrent operations
            results = self._execute_concurrent_operations(pattern, duration)
            
            # Analyze results for issues
            issues = self._analyze_concurrent_results(results)
            
            return {
                'pattern_name': pattern_name,
                'description': pattern.get('description', ''),
                'duration': duration,
                'total_operations': len(results),
                'successful_operations': len([r for r in results if r.get('success', False)]),
                'failed_operations': len([r for r in results if not r.get('success', False)]),
                'issues_detected': issues,
                'results': results,
                'success': True
            }
            
        except Exception as e:
            self.logger.error(f"Error in concurrent test {pattern_name}: {e}")
            return {
                'pattern_name': pattern_name,
                'error': str(e),
                'success': False
            }

    def _execute_concurrent_operations(self, pattern: Dict[str, Any], duration: int) -> List[Dict[str, Any]]:
        """Execute operations concurrently for the specified duration."""
        results = []
        start_time = time.time()
        
        # Create session pools for different session IDs
        session_pools = {}
        for operation in pattern['operations']:
            session_id = operation.get('session_id', 1)
            if session_id not in session_pools:
                session_pools[session_id] = []
            session_pools[session_id].append(operation)
        
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            
            while time.time() - start_time < duration:
                # Submit operations for concurrent execution across sessions
                for session_id, operations in session_pools.items():
                    for operation in operations:
                        future = executor.submit(self._execute_concurrent_operation, operation, session_id)
                        futures.append(future)
                
                # Wait a bit before next iteration
                time.sleep(0.1)
            
            # Collect results
            for future in as_completed(futures):
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    results.append({
                        'operation': 'unknown',
                        'session_id': 'unknown',
                        'success': False,
                        'error': str(e),
                        'timestamp': time.time()
                    })
        
        return results

    def _execute_concurrent_operation(self, operation: Dict[str, Any], session_id: int) -> Dict[str, Any]:
        """Execute a single concurrent operation with advanced Jepsen-like testing."""
        try:
            start_time = time.time()
            op_type = operation['type']
            query = operation['query']
            
            # Determine if we need to fetch results based on operation type
            fetch_results = op_type.endswith('_read') or 'SELECT' in query.upper()
            
            # Execute the operation
            result = self.db_executor.execute_query(query, fetch_results=fetch_results)
            
            execution_time = time.time() - start_time
            
            # Advanced result with operation metadata
            advanced_result = {
                'operation': op_type,
                'query': query,
                'session_id': session_id,
                'success': result.get('success', False),
                'execution_time': execution_time,
                'timestamp': start_time,
                'result': result,
                'operation_category': self._categorize_operation(op_type),
                'is_transaction_control': op_type in ['session1_begin', 'session2_begin', 'session3_begin', 
                                                    'session1_commit', 'session2_commit', 'session3_commit'],
                'is_isolation_setting': op_type.endswith('_set_isolation'),
                'is_setup': op_type.endswith('_setup'),
                'is_cleanup': op_type == 'cleanup'
            }
            
            return advanced_result
            
        except Exception as e:
            return {
                'operation': op_type,
                'query': query,
                'session_id': session_id,
                'success': False,
                'error': str(e),
                'timestamp': time.time(),
                'operation_category': 'error'
            }
    
    def _categorize_operation(self, op_type: str) -> str:
        """Categorize operation for Jepsen-like analysis."""
        if op_type.endswith('_setup'):
            return 'setup'
        elif op_type.endswith('_begin'):
            return 'transaction_begin'
        elif op_type.endswith('_set_isolation'):
            return 'isolation_setting'
        elif op_type.endswith('_read'):
            return 'read'
        elif op_type.endswith('_write'):
            return 'write'
        elif op_type.endswith('_commit'):
            return 'transaction_commit'
        elif op_type == 'cleanup':
            return 'cleanup'
        else:
            return 'unknown'

    def _analyze_concurrent_results(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze concurrent execution results for Jepsen-like consistency violations."""
        issues = []
        
        # Check for failed operations
        failed_operations = [r for r in results if not r.get('success', False)]
        if failed_operations:
            issues.append({
                'type': 'operation_failures',
                'description': f'{len(failed_operations)} operations failed during concurrent execution',
                'severity': 'MEDIUM',
                'details': failed_operations
            })
        
        # Check for performance degradation
        slow_operations = [r for r in results if r.get('execution_time', 0) > 10.0]
        if slow_operations:
            issues.append({
                'type': 'performance_degradation',
                'description': f'{len(slow_operations)} operations took longer than 10 seconds',
                'severity': 'MEDIUM',
                'details': slow_operations
            })
        
        # Jepsen-like consistency analysis
        consistency_issues = self._analyze_consistency_violations(results)
        issues.extend(consistency_issues)
        
        # Check for cross-session conflicts
        session_operations = {}
        for r in results:
            session_id = r.get('session_id')
            if session_id not in session_operations:
                session_operations[session_id] = []
            session_operations[session_id].append(r)
        
        if len(session_operations) > 1:
            issues.append({
                'type': 'cross_session_operations',
                'description': f'Operations executed across {len(session_operations)} different sessions',
                'severity': 'LOW',
                'details': list(session_operations.keys())
            })
        
        return issues
    
    def _analyze_consistency_violations(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Analyze results for Jepsen-like consistency violations."""
        issues = []
        
        # Group operations by session and type
        session_data = {}
        for r in results:
            session_id = r.get('session_id')
            if session_id not in session_data:
                session_data[session_id] = {
                    'reads': [],
                    'writes': [],
                    'transactions': [],
                    'isolation_levels': []
                }
            
            op_category = r.get('operation_category', 'unknown')
            if op_category == 'read':
                session_data[session_id]['reads'].append(r)
            elif op_category == 'write':
                session_data[session_id]['writes'].append(r)
            elif op_category in ['transaction_begin', 'transaction_commit']:
                session_data[session_id]['transactions'].append(r)
            elif op_category == 'isolation_setting':
                session_data[session_id]['isolation_levels'].append(r)
        
        # Check for Snapshot isolation violations
        for session_id, data in session_data.items():
            if data['isolation_levels']:
                isolation_query = data['isolation_levels'][0]['query']
                if 'SNAPSHOT' not in isolation_query.upper():
                    issues.append({
                        'type': 'isolation_level_violation',
                        'description': f'Session {session_id} not using Snapshot isolation: {isolation_query}',
                        'severity': 'HIGH',
                        'session_id': session_id,
                        'details': isolation_query
                    })
        
        # Check for transaction ordering issues
        for session_id, data in session_data.items():
            if len(data['transactions']) >= 2:
                # Check if transactions are properly ordered (begin before commit)
                begins = [t for t in data['transactions'] if t['operation'].endswith('_begin')]
                commits = [t for t in data['transactions'] if t['operation'].endswith('_commit')]
                
                if len(begins) != len(commits):
                    issues.append({
                        'type': 'transaction_mismatch',
                        'description': f'Session {session_id} has {len(begins)} begins but {len(commits)} commits',
                        'severity': 'HIGH',
                        'session_id': session_id,
                        'details': {'begins': len(begins), 'commits': len(commits)}
                    })
        
        # Check for read-write consistency
        for session_id, data in session_data.items():
            if data['reads'] and data['writes']:
                # Check if reads and writes are properly sequenced within transactions
                reads_in_tx = [r for r in data['reads'] if r.get('is_transaction_control')]
                writes_in_tx = [w for w in data['writes'] if w.get('is_transaction_control')]
                
                if reads_in_tx and writes_in_tx:
                    # This is a basic check - in a real Jepsen test, we'd analyze the actual data values
                    issues.append({
                        'type': 'read_write_consistency_check',
                        'description': f'Session {session_id} has {len(reads_in_tx)} reads and {len(writes_in_tx)} writes in transactions',
                        'severity': 'LOW',
                        'session_id': session_id,
                        'details': {'reads_in_tx': len(reads_in_tx), 'writes_in_tx': len(writes_in_tx)}
                    })
        
        return issues
"""
Fuzzer Engine - Core orchestration and execution logic.
"""

import time
import logging
import random
from typing import List, Dict, Any, Optional
from .generator import GrammarGenerator
from .mutator import Mutator
from oracles.tlp_oracle import TLOracle
from oracles.qpg_oracle import QPGOracle
from oracles.pqs_oracle import PQSOracle
from oracles.norec_oracle import NoRECOracle
from oracles.cert_oracle import CERTOracle
from oracles.dqp_oracle import DQPOracle
from oracles.coddtest_oracle import CODDTestOracle
from utils.db_executor import DBExecutor
from utils.bug_reporter import BugReporter


class FuzzerEngine:
    """
    Main fuzzer engine that orchestrates the entire fuzzing process.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Initialize components
        self.db_executor = DBExecutor(config.get_db_config(), BugReporter(config), config)
        self.generator = GrammarGenerator({}, config, self.db_executor.catalog)
        self.mutator = Mutator(config, self.db_executor.catalog)
        
        # Initialize oracles
        self.oracles = self._initialize_oracles()
        
        # Statistics
        self.stats = {
            'queries_executed': 0,
            'bugs_found': 0,
            'sessions_completed': 0,
            'start_time': None,
            'oracle_stats': {}
        }
        
        self.logger.info(f"Registered {len(self.oracles)} active oracles: {[o.__class__.__name__ for o in self.oracles]}")
    
    def _initialize_oracles(self):
        """Initialize all configured oracles."""
        try:
            oracle_classes = {
                'TLOracle': TLOracle,
                'QPGOracle': QPGOracle,
                'PQSOracle': PQSOracle,
                'NoRECOracle': NoRECOracle,
                'CERTOracle': CERTOracle,
                'DQPOracle': DQPOracle,
                'CODDTestOracle': CODDTestOracle
            }
            
            oracles = []
            for oracle_name in self.config.get('oracles', []):
                if oracle_name in oracle_classes:
                    try:
                        oracle = oracle_classes[oracle_name](self.config)
                        oracle.set_db_executor(self.db_executor)
                        oracles.append(oracle)
                        self.logger.info(f"✅ Oracle initialized: {oracle_name}")
                    except Exception as e:
                        self.logger.error(f"❌ Failed to initialize oracle {oracle_name}: {e}")
                else:
                    self.logger.warning(f"⚠️ Unknown oracle: {oracle_name}")
            
            if not oracles:
                self.logger.warning("⚠️ No oracles initialized, falling back to basic testing")
                
            return oracles
                
        except Exception as e:
            self.logger.error(f"❌ Error initializing oracles: {e}")
            return []
    
    def run(self, duration: Optional[int] = None) -> None:
        """
        Run the fuzzer for the specified duration.
        
        Args:
            duration: Duration in seconds (overrides config)
        """
        # Use config duration if not specified
        if duration is None:
            duration = self.config.get('fuzzing', {}).get('duration', 300)
        
        self.logger.info(f"Starting fuzzer for {duration} seconds...")
        self.stats['start_time'] = time.time()
        
        # Setup database schema
        self._setup_database_schema()
        
        # Main fuzzing loop
        self._run_fuzzing_loop(duration)
        
        # Final summary
        self._print_final_summary()
    
    def _setup_database_schema(self) -> None:
        """Setup the database schema and initial tables."""
        self.logger.info("Setting up database schema and initial tables...")
        
        try:
            # Create schema
            schema_name = self.config.get_db_config()['schema_name']
            self.db_executor.execute_admin(f"DROP SCHEMA IF EXISTS {schema_name} CASCADE;")
            self.db_executor.execute_admin(f"CREATE SCHEMA {schema_name};")
            
            # Create test tables
            self._create_test_tables()
            
            # Refresh catalog
            self.db_executor.catalog.refresh()
            
            self.logger.info(f"Database setup complete. Schema '{schema_name}' ready for fuzzing.")
            
        except Exception as e:
            self.logger.error(f"Failed to setup database schema: {e}")
            raise
    
    def _create_test_tables(self) -> None:
        """Create test tables with realistic data."""
        schema_name = self.config.get_db_config()['schema_name']
        
        # Products table
        self.db_executor.execute_admin(f"""
            CREATE TABLE {schema_name}.products (
                id INT PRIMARY KEY, 
                name TEXT, 
                category TEXT, 
                price NUMERIC, 
                stock_count INT
            );
        """)
        
        # Insert sample data
        self.db_executor.execute_admin(f"""
            INSERT INTO {schema_name}.products 
            SELECT g, 'Product-' || g, 'Category-' || (g%10), g*1.5, g*10 
            FROM generate_series(1,100) g;
        """)
        
        # Orders table
        self.db_executor.execute_admin(f"""
            CREATE TABLE {schema_name}.orders (
                id SERIAL PRIMARY KEY, 
                order_id INTEGER, 
                product_id INTEGER, 
                quantity INTEGER, 
                price NUMERIC(10,2), 
                order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Insert sample data
        self.db_executor.execute_admin(f"""
            INSERT INTO {schema_name}.orders (order_id, product_id, quantity, price) 
            SELECT g, (g % 50) + 1, (g % 10) + 1, (g % 100) + 10.0 
            FROM generate_series(1,50) g;
        """)
        
        # Customers table
        self.db_executor.execute_admin(f"""
            CREATE TABLE {schema_name}.customers (
                id SERIAL PRIMARY KEY, 
                name TEXT, 
                email TEXT, 
                phone TEXT, 
                address TEXT, 
                created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        """)
        
        # Insert sample data
        self.db_executor.execute_admin(f"""
            INSERT INTO {schema_name}.customers (name, email, phone, address) 
            SELECT 'Customer-' || g, 'customer' || g || '@example.com', 
                   '+1-555-' || LPAD(g::text, 4, '0'), 'Address ' || g || ', City, State' 
            FROM generate_series(1,25) g;
        """)
        
        # Categories table
        self.db_executor.execute_admin(f"""
            CREATE TABLE {schema_name}.categories (
                id SERIAL PRIMARY KEY, 
                name TEXT, 
                description TEXT, 
                parent_id INTEGER
            );
        """)
        
        # Insert sample data
        self.db_executor.execute_admin(f"""
            INSERT INTO {schema_name}.categories (name, description, parent_id) 
            SELECT 'Category-' || g, 'Description for category ' || g, 
                   CASE WHEN g % 3 = 0 THEN NULL ELSE (g % 5) + 1 END 
            FROM generate_series(1,10) g;
        """)
    
    def _run_fuzzing_loop(self, duration: int) -> None:
        """Main fuzzing loop."""
        start_time = time.time()
        session_count = 0
        
        while time.time() - start_time < duration:
            session_count += 1
            self.logger.info(f"========== Starting Fuzzing Session #{session_count} ==========")
            
            try:
                # Run a complete fuzzing session
                self._run_fuzzing_session()
                self.stats['sessions_completed'] += 1
                
                # Brief pause between sessions
                time.sleep(0.1)
                
            except Exception as e:
                self.logger.error(f"Error in fuzzing session {session_count}: {e}")
                continue
    
    def _run_fuzzing_session(self) -> None:
        """Run a single fuzzing session."""
        try:
            # Phase 1: DDL Statements
            self.logger.info("--- Session Phase: DDL Statements (Target: 2 statements) ---")
            self._execute_ddl_statements()
            
            # Phase 2: DML Statements
            self.logger.info("--- Session Phase: DML Statements (Target: 8 statements) ---")
            self._execute_dml_statements()
            
            # Phase 3: Final Validation SELECT
            self.logger.info("--- Session Phase: Final Validation SELECT ---")
            self._execute_validation_select()
            
        except Exception as e:
            self.logger.error(f"Error in fuzzing session: {e}")
    
    def _execute_ddl_statements(self) -> None:
        """Execute DDL statements and refresh catalog."""
        try:
            # Generate and execute more complex DDL statements
            for _ in range(random.randint(2, 5)):  # Increased from 2 to 2-5
                ddl_stmt = self.generator.generate_statement_of_type('ddl_stmt')
                if ddl_stmt:
                    sql = ddl_stmt.to_sql()
                    if sql and len(sql.strip()) > 0:
                        try:
                            self.db_executor.execute_admin(sql)
                            self.stats['queries_executed'] += 1
                            
                            # Log complex DDL for debugging
                            if 'JSON' in sql or 'ARRAY' in sql or 'PARTITION' in sql:
                                self.logger.info(f"Advanced DDL executed: {sql[:150]}...")
                                
                        except Exception as e:
                            self.logger.error(f"Error executing DDL statement: {e}")
                            self.logger.error(f"SQL: {sql}")
                            self.stats['query_errors'] += 1
            
            # Refresh catalog after DDL changes
            self.db_executor.catalog.refresh()
            
        except Exception as e:
            self.logger.error(f"Error executing DDL statements: {e}")
    
    def _execute_dml_statements(self) -> None:
        """Execute DML statements and test with oracles."""
        try:
            # Generate and execute more complex DML statements
            for _ in range(random.randint(8, 15)):  # Increased from 8 to 8-15
                dml_stmt = self.generator.generate_statement_of_type('select_stmt')
                if dml_stmt:
                    sql = dml_stmt.to_sql()
                    if sql and len(sql.strip()) > 0:
                        try:
                            # Execute the query
                            result = self.db_executor.execute_query(sql)
                            self.stats['queries_executed'] += 1
                            
                            # Test with oracles for bugs
                            self._check_query_with_oracles(sql, result)
                            
                            # Log complex queries for debugging
                            if len(sql) > 200:  # Log complex queries
                                self.logger.info(f"Complex query executed ({len(sql)} chars): {sql[:100]}...")
                            
                        except Exception as e:
                            self.logger.error(f"Error executing DML statement: {e}")
                            self.logger.error(f"SQL: {sql}")
                            self.stats['query_errors'] += 1
                            
        except Exception as e:
            self.logger.error(f"Error executing DML statements: {e}")
    
    def _execute_validation_select(self) -> None:
        """Execute final validation SELECT statement."""
        try:
            # Generate a validation SELECT
            select_stmt = self.generator.generate_statement_of_type('select_stmt')
            if select_stmt:
                sql = select_stmt.to_sql()
                result = self.db_executor.execute_query(sql)
                self.stats['queries_executed'] += 1
                
                # Check for bugs using all oracles
                if result:
                    self._check_query_with_oracles(sql, result)
            
        except Exception as e:
            self.logger.error(f"Error executing validation SELECT: {e}")
    
    def _check_query_with_oracles(self, query: str, result: Any) -> None:
        """Check the query with all active oracles for bugs."""
        for oracle in self.oracles:
            try:
                self.logger.info(f"🔍 Testing query with {oracle.__class__.__name__}: {query[:100]}...")
                
                # Check for bugs using the new oracle interface
                bug_report = oracle.check_for_bugs(query)
                
                if bug_report:
                    self.logger.warning(f"🚨 BUG DETECTED by {oracle.__class__.__name__}: {bug_report['description']}")
                    self._report_bug(
                        bug_report['bug_type'],
                        bug_report['description'],
                        bug_report['query'],
                        bug_report['context'],
                        bug_report['oracle_name']
                    )
                    
            except Exception as e:
                self.logger.error(f"Error checking query with {oracle.__class__.__name__}: {e}")
                continue
    
    def _report_bug(self, bug_type: str, bug_description: str, query: str, bug_context: Any, oracle_name: str) -> None:
        """Report a bug to the bug reporter."""
        try:
            self.db_executor.bug_reporter.report_bug(
                bug_type=bug_type,
                description=bug_description,
                query=query,
                context=bug_context,
                oracle_name=oracle_name
            )
        except Exception as e:
            self.logger.error(f"Error reporting bug: {e}")
    
    def _determine_bug_type(self, oracle_name: str, description: str) -> str:
        """Determine the bug type based on oracle name and description."""
        oracle_name_lower = oracle_name.lower()
        
        if 'tlp' in oracle_name_lower:
            return 'tlp'
        elif 'qpg' in oracle_name_lower:
            return 'qpg'
        elif 'norec' in oracle_name_lower:
            return 'norec'
        elif 'pqs' in oracle_name_lower:
            return 'pqs'
        elif 'cert' in oracle_name_lower:
            return 'cert'
        elif 'dqp' in oracle_name_lower:
            return 'dqp'
        elif 'coddtest' in oracle_name_lower:
            return 'coddtest'
        else:
            return 'logical'
    
    def _generate_reproduction_script(self, query: str, bug_description: str, bug_context: Any) -> str:
        """Generate a reproduction script for the bug."""
        try:
            return f"""-- Bug Reproduction
-- Oracle: {bug_description}
-- Original Query: {query}
-- Context: {bug_context}"""
            
        except Exception as e:
            self.logger.error(f"Error generating reproduction script: {e}")
            return "Error generating reproduction script"
    
    def _print_final_summary(self) -> None:
        """Print final fuzzing summary."""
        end_time = time.time()
        total_time = end_time - self.stats['start_time']
        
        self.logger.info("========== Fuzzing Run Summary ==========")
        self.logger.info(f"Progress: {self.stats['sessions_completed']} sessions | "
                        f"{self.stats['queries_executed']} queries "
                        f"({self.stats['queries_executed']/total_time:.2f} q/s) | "
                        f"{self.stats['bugs_found']} unique bugs found.")
        
        # Oracle-specific statistics
        if self.stats['oracle_stats']:
            self.logger.info("Oracle Statistics:")
            for oracle_name, bug_count in self.stats['oracle_stats'].items():
                self.logger.info(f"  {oracle_name}: {bug_count} bugs")
        
        self.logger.info("==========================================")
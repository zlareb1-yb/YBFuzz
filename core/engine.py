"""
Fuzzer Engine - Core orchestration and execution logic.
"""

import time
import logging
import random
from typing import List, Dict, Any, Optional
from .generator import GrammarGenerator
from .mutator import Mutator
from oracles import ORACLE_REGISTRY
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
        
        self.logger.info(f"Registered {len(self.oracles)} active oracles: {[o.name for o in self.oracles]}")
    
    def _initialize_oracles(self) -> List[Any]:
        """Initialize all available oracles based on configuration."""
        oracles = []
        oracle_config = self.config.get('oracles', {})
        
        # Always enable core oracles
        core_oracles = ['TLOracle', 'QPGOracle']
        
        # Advanced oracles (configurable)
        advanced_oracles = [
            'PQSOracle',      # Pivoted Query Synthesis
            'NoRECOracle',    # Non-optimizing Reference Engine Construction
            'CERTOracle',     # Cardinality Estimation Restriction Testing
            'DQPOracle',      # Differential Query Plans
            'CODDTestOracle'  # Constant Optimization Driven Testing
        ]
        
        # Initialize core oracles
        for oracle_name in core_oracles:
            if oracle_config.get(oracle_name.lower(), {}).get('enabled', True):
                try:
                    oracle_class = ORACLE_REGISTRY[oracle_name]
                    oracle = oracle_class(self.db_executor)
                    oracles.append(oracle)
                    self.logger.info(f"Oracle '{oracle_name}' is ENABLED.")
                except Exception as e:
                    self.logger.error(f"Failed to initialize oracle '{oracle_name}': {e}")
        
        # Initialize advanced oracles
        for oracle_name in advanced_oracles:
            if oracle_config.get(oracle_name.lower(), {}).get('enabled', False):
                try:
                    oracle_class = ORACLE_REGISTRY[oracle_name]
                    oracle = oracle_class(self.db_executor)
                    oracles.append(oracle)
                    self.logger.info(f"Advanced Oracle '{oracle_name}' is ENABLED.")
                except Exception as e:
                    self.logger.error(f"Failed to initialize advanced oracle '{oracle_name}': {e}")
        
        return oracles
    
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
            # Generate and execute DDL statements
            for _ in range(2):
                ddl_stmt = self.generator.generate_statement_of_type('ddl_stmt')
                if ddl_stmt:
                    sql = ddl_stmt.to_sql()
                    self.db_executor.execute_admin_command(sql)
                    self.stats['queries_executed'] += 1
            
            # Refresh catalog after DDL changes
            self.db_executor.catalog.refresh()
            
        except Exception as e:
            self.logger.error(f"Error executing DDL statements: {e}")
    
    def _execute_dml_statements(self) -> None:
        """Execute DML statements."""
        try:
            # Generate and execute DML statements
            for _ in range(8):
                dml_stmt = self.generator.generate_statement_of_type('dml_stmt')
                if dml_stmt:
                    sql = dml_stmt.to_sql()
                    result = self.db_executor.execute_query(sql)
                    self.stats['queries_executed'] += 1
                    
                    # Check for bugs using all oracles
                    if result:
                        self._check_query_with_oracles(sql, result)
            
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
        """Check a query using all available oracles."""
        for oracle in self.oracles:
            try:
                bug_found, bug_description, bug_context = oracle.check_for_bugs(query)
                if bug_found:
                    self._report_bug(query, bug_description, bug_context, oracle.get_oracle_name())
                    
            except Exception as e:
                self.logger.error(f"Error in oracle {oracle.get_oracle_name()}: {e}")
    
    def _report_bug(self, query: str, bug_description: str, bug_context: Any, oracle_name: str) -> None:
        """Report a detected bug."""
        try:
            # Update statistics
            self.stats['bugs_found'] += 1
            if oracle_name not in self.stats['oracle_stats']:
                self.stats['oracle_stats'][oracle_name] = 0
            self.stats['oracle_stats'][oracle_name] += 1
            
            # Log the bug
            self.logger.warning(f"🚨 BUG DETECTED by {oracle_name}: {bug_description}")
            self.logger.warning(f"Original Query: {query}")
            
            # Generate reproduction script
            reproduction = self._generate_reproduction_script(query, bug_description, bug_context)
            self.logger.warning(f"Reproduction: {reproduction}")
            
            # Report to bug reporter
            self.db_executor.bug_reporter.report_bug({
                'oracle': oracle_name,
                'description': bug_description,
                'query': query,
                'context': bug_context
            })
            
        except Exception as e:
            self.logger.error(f"Error reporting bug: {e}")
    
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
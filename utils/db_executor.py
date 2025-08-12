# This module encapsulates all direct interaction with the database.
# This optimized version includes a dedicated logger that creates a clean
# SQL script for easy bug reproduction.

import psycopg2
import logging
import random
from config import FuzzerConfig
from utils.bug_reporter import BugReporter
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple, Union

# --- Schema and Vocabulary Representation ---
@dataclass
class Column:
    name: str
    data_type: str

@dataclass
class Table:
    name: str
    columns: list[Column] = field(default_factory=list)

@dataclass
class DiscoveredFunction:
    name: str
    arg_types: list[str]

class Catalog:
    """
    Maintains an in-memory representation of the database schema and discovered
    vocabulary (functions, types, etc.).
    """
    def __init__(self, conn_provider: callable, schema_name: str):
        self._get_conn = conn_provider
        self.schema_name = schema_name
        self.logger = logging.getLogger(self.__class__.__name__)

        # Discovered items
        self.tables: dict[str, Table] = {}
        self.views: dict[str, Table] = {}
        self.functions: list[DiscoveredFunction] = []
        self.types: list[str] = []

        self.refresh()
        self.discover_vocabulary()

    def refresh(self):
        """Reloads the table and column schema from the database."""
        self.logger.info("Refreshing schema catalog (tables and columns)...")
        self.tables = {}
        self.views = {}
        # Query to distinguish between tables and views
        query = """
        SELECT table_name, table_type 
        FROM information_schema.tables 
        WHERE table_schema = %s;
        """
        try:
            with self._get_conn().cursor() as cur:
                cur.execute(query, (self.schema_name,))
                for row in cur.fetchall():
                    table_name, table_type = row
                    if table_type == 'BASE TABLE':
                        self._add_table_to_catalog(table_name, is_view=False)
                    elif table_type == 'VIEW':
                        self._add_table_to_catalog(table_name, is_view=True)
        except psycopg2.Error as e:
            error_code = e.pgcode
            if error_code in ['25P02', '25P03']:  # Transaction state errors
                self.logger.warning(f"Transaction state error during catalog refresh, reconnecting: {e}")
                try:
                    # Reconnect and retry
                    self._connect()
                    # Retry the catalog refresh
                    with self._get_conn().cursor() as cur:
                        cur.execute(query, (self.schema_name,))
                        for row in cur.fetchall():
                            table_name, table_type = row
                            if table_type == 'BASE TABLE':
                                self._add_table_to_catalog(table_name, is_view=False)
                            elif table_type == 'VIEW':
                                self._add_table_to_catalog(table_name, is_view=True)
                except Exception as retry_error:
                    self.logger.error(f"Catalog refresh retry failed: {retry_error}")
            else:
                self.logger.error(f"Failed to refresh catalog: {e}")
        self.logger.info(f"Catalog refreshed. Found {len(self.tables)} tables and {len(self.views)} views.")

    def _add_table_to_catalog(self, table_name: str, is_view: bool = False):
        table = Table(name=table_name)
        query = "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = %s AND table_name = %s;"
        try:
            with self._get_conn().cursor() as cur:
                cur.execute(query, (self.schema_name, table_name))
                for row in cur.fetchall():
                    table.columns.append(Column(name=row[0], data_type=row[1]))
            if table.columns:
                if is_view:
                    self.views[table_name] = table
                else:
                    self.tables[table_name] = table
        except psycopg2.Error as e:
            self.logger.error(f"Failed to add table '{table_name}' to catalog: {e}")

    def discover_vocabulary(self):
        """Queries pg_catalog to discover functions and types."""
        self.logger.info("Discovering database vocabulary (functions, types)...")
        try:
            with self._get_conn().cursor() as cur:
                # Discover functions - only safe, user-callable functions
                func_query = """
                SELECT p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) as arg_types
                FROM pg_catalog.pg_proc p
                JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'pg_catalog' 
                  AND p.prokind = 'f' 
                  AND p.prorettype <> 'pg_catalog.trigger'::pg_catalog.regtype
                  AND p.proname IN ('length', 'upper', 'lower', 'trim', 'abs', 'round', 'coalesce', 'nullif', 'greatest', 'least', 'count', 'sum', 'avg', 'min', 'max')
                  AND pg_catalog.pg_function_is_visible(p.oid)
                ORDER BY p.proname;
                """
                cur.execute(func_query)
                for row in cur.fetchall():
                    func_name, arg_types = row
                    # Only include functions with simple argument types
                    if arg_types and not arg_types.startswith('internal'):
                        self.functions.append(DiscoveredFunction(name=func_name, arg_types=[arg_types]))
                
                # Discover base types
                type_query = """
                SELECT t.typname 
                FROM pg_catalog.pg_type t
                JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
                WHERE n.nspname IN ('pg_catalog', 'public')
                  AND t.typtype = 'b'
                  AND t.typname NOT LIKE 'pg_%'
                  AND t.typname NOT LIKE 'information_schema%'
                ORDER BY t.typname;
                """
                cur.execute(type_query)
                for row in cur.fetchall():
                    self.types.append(row[0])
                    
        except psycopg2.Error as e:
            self.logger.error(f"Failed to discover vocabulary: {e}")
        
        self.logger.info(f"Discovered {len(self.functions)} functions and {len(self.types)} base types.")

    def get_random_table(self, exclude_views: bool = False) -> Table | None:
        if exclude_views:
            # Only return actual tables, not views
            return random.choice(list(self.tables.values())) if self.tables else None
        else:
            # Return either a table or a view
            all_objects = list(self.tables.values()) + list(self.views.values())
            return random.choice(all_objects) if all_objects else None

    def get_random_column(self, table: Table, of_type: str | None = None) -> Column | None:
        if not table or not table.columns: return None
        candidates = table.columns
        if of_type == 'numeric':
            candidates = [c for c in table.columns if any(t in c.data_type.lower() for t in ['int', 'numeric', 'real', 'double'])]
        return random.choice(candidates) if candidates else None

class DBExecutor:
    """Handles resilient connection and execution of SQL queries."""
    def __init__(self, db_config: dict, bug_reporter: BugReporter, config: FuzzerConfig):
        self.db_config = db_config
        self.bug_reporter = bug_reporter
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.conn = None
        self._connect()
        
        self.catalog = Catalog(self.get_connection, self.db_config['schema_name'])
        self.query_history = []
        
        # --- New: Dedicated SQL Logger ---
        self._setup_sql_logger()

    def _setup_sql_logger(self):
        """Sets up a dedicated logger for just the SQL statements."""
        self.sql_logger = logging.getLogger('SQLScript')
        self.sql_logger.setLevel(logging.INFO)
        self.sql_logger.propagate = False
        
        sql_log_file = self.config.get('sql_log_file', 'executed_queries.sql')
        
        if not self.sql_logger.handlers:
            handler = logging.FileHandler(sql_log_file, mode='w')
            # Use a formatter that only outputs the message, making it a clean script
            formatter = logging.Formatter('%(message)s')
            handler.setFormatter(formatter)
            self.sql_logger.addHandler(handler)
            self.logger.info(f"Clean SQL reproduction script will be saved to '{sql_log_file}'")

    def _connect(self):
        """Establishes a database connection with proper settings for fuzzing."""
        try:
            self.conn = psycopg2.connect(
                host=self.db_config['host'],
                port=self.db_config['port'],
                database=self.db_config['dbname'],
                user=self.db_config['user'],
                password=self.db_config['password']
            )
            
            # CRITICAL: Enable autocommit for fuzzing to ensure query independence
            self.conn.autocommit = True
            
            # Set isolation level to READ COMMITTED for YugabyteDB compatibility
            self.conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_READ_COMMITTED)
            
            self.logger.info(f"Connected to database '{self.db_config['dbname']}' on {self.db_config['host']}:{self.db_config['port']}")
            
        except psycopg2.Error as e:
            self.logger.error(f"Failed to connect to database: {e}")
            raise

    def get_connection(self):
        """Returns a database connection."""
        if not self.conn or self.conn.closed:
            self._connect()
        return self.conn

    def execute_query(self, query: str, fetch_results: bool = True) -> Any:
        """Execute a SQL query and return results or row count. Each query runs independently."""
        try:
            # Use existing connection if available and healthy
            if not self.conn or self.conn.closed:
                self._connect()
            
            with self.conn.cursor() as cursor:
                cursor.execute(query)
                
                if fetch_results:
                    data = cursor.fetchall()
                    # Return a result object with success attribute
                    class QueryResult:
                        def __init__(self, data):
                            self.success = True
                            self.data = data
                    return QueryResult(data)
                else:
                    rowcount = cursor.rowcount
                    # Return a result object with success attribute
                    class QueryResult:
                        def __init__(self, rowcount):
                            self.success = True
                            self.data = None
                            self.rowcount = rowcount
                    return QueryResult(rowcount)
                    
        except psycopg2.Error as e:
            error_code = e.pgcode
            
            # Handle transaction state errors by reconnecting
            if error_code in ['25P02', '25P03']:  # Transaction state errors
                self.logger.warning(f"Transaction state error, reconnecting: {e}")
                try:
                    if self.conn and not self.conn.closed:
                        self.conn.close()
                    self._connect()
                    # Retry the query once
                    with self.conn.cursor() as cursor:
                        cursor.execute(query)
                        if fetch_results:
                            data = cursor.fetchall()
                            class QueryResult:
                                def __init__(self, data):
                                    self.success = True
                                    self.data = data
                            return QueryResult(data)
                        else:
                            rowcount = cursor.rowcount
                            class QueryResult:
                                def __init__(self, rowcount):
                                    self.success = True
                                    self.data = None
                                    self.rowcount = rowcount
                            return QueryResult(rowcount)
                except Exception as retry_error:
                    self.logger.error(f"Retry failed: {retry_error}")
                    # Return failed result
                    class QueryResult:
                        def __init__(self):
                            self.success = False
                            self.data = None
                            self.error = str(retry_error)
                    return QueryResult()
            
            # Handle syntax errors and other non-critical errors gracefully
            elif error_code in ['42601', '42703', '42P01', '42P02', '42P03', '42P04', '42P05', '42P06', '42P07', '42P08', '42P09', '42P10', '42P11', '42P12', '42P13', '42P14', '42P15', '42P16', '42P17', '42P18', '42P19', '42P20', '42P21', '42P22', '42P23', '42P24', '42P25', '42P26', '42P27', '42P28', '42P29', '42P30', '42P31', '42P32', '42P33', '42P34', '42P35', '42P36', '42P37', '42P38', '42P39', '42P40', '42P41', '42P42', '42P43', '42P44', '42P45', '42P46', '42P47', '42P48', '42P49', '42P50', '42P51', '42P52', '42P53', '42P54', '42P55', '42P56', '42P57', '42P58', '42P59', '42P60', '42P61', '42P62', '42P63', '42P64', '42P65', '42P66', '42P67', '42P68', '42P69', '42P70', '42P71', '42P72', '42P73', '42P74', '42P75', '42P76', '42P77', '42P78', '42P79', '42P80', '42P81', '42P82', '42P83', '42P84', '42P85', '42P86', '42P87', '42P88', '42P89', '42P90', '42P91', '42P92', '42P93', '42P94', '42P95', '42P96', '42P97', '42P98', '42P99']:
                self.logger.warning(f"Query failed with non-critical error: {e}")
                # Return failed result for non-critical errors
                class QueryResult:
                    def __init__(self):
                        self.success = False
                        self.data = None
                        self.error = str(e)
                return QueryResult()
            else:
                # Other database errors - log and continue
                self.logger.warning(f"Query failed with database error: {e}")
                # Return failed result
                class QueryResult:
                    def __init__(self):
                        self.success = False
                        self.data = None
                        self.error = str(e)
                return QueryResult()
                
        except Exception as e:
            # Handle any other unexpected errors
            self.logger.error(f"Unexpected error executing query: {e}")
            # Return failed result
            class QueryResult:
                def __init__(self):
                    self.success = False
                    self.data = None
                    self.error = str(e)
            return QueryResult()

    def execute_query_with_setup(self, setup_sqls: list[str], query: str, teardown_sqls: list[str]) -> tuple[list | None, Exception | None]:
        """Executes a query with setup and teardown SQL statements."""
        try:
            # Execute setup
            for setup_sql in setup_sqls:
                self.execute_query(setup_sql, fetch_results=False)
            
            # Execute main query
            result = self.execute_query(query, fetch_results=True)
            
            # Execute teardown
            for teardown_sql in teardown_sqls:
                self.execute_query(teardown_sql, fetch_results=False)
            
            return result, None
        except Exception as e:
            self.logger.error(f"Error in setup/teardown execution: {e}")
            return None, e

    def execute_admin(self, sql: str):
        """Executes administrative SQL commands."""
        self.logger.info(f"Executing admin command: {sql}")
        try:
            with self.get_connection().cursor() as cur:
                cur.execute(sql)
            # No need to commit when using autocommit mode
        except psycopg2.Error as e:
            self.logger.error(f"Admin command failed: {e}")
            raise

    def close(self):
        """Closes the database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()
            self.logger.info("Database connection closed.")

    def _extract_missing_table_name(self, error_msg: str) -> str | None:
        """Extracts table name from 'relation does not exist' error messages."""
        import re
        # Look for patterns like "relation \"table_name\" does not exist"
        match = re.search(r'relation "([^"]+)" does not exist', error_msg)
        if match:
            return match.group(1)
        
        # Also check for unquoted table names
        match = re.search(r'relation ([^\s]+) does not exist', error_msg)
        if match:
            return match.group(1)
        
        return None

    def _create_missing_table(self, table_name: str) -> bool:
        """Creates a missing table with a basic structure."""
        try:
            self.logger.info(f"Creating missing table '{table_name}' with basic structure")
            
            # Create a simple table structure
            create_sql = f"""
                CREATE TABLE ybfuzz_schema."{table_name}" (
                    id SERIAL PRIMARY KEY,
                    name TEXT,
                    value NUMERIC(10,2),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO ybfuzz_schema."{table_name}" (name, value) 
                SELECT 'Item-' || g, (g % 100) + 1.0 
                FROM generate_series(1, 20) g;
                """
            
            self.execute_admin(create_sql)
            
            # Refresh the catalog to include the new table
            self.catalog.refresh()
            
            return True
        except Exception as e:
            self.logger.error(f"Failed to create missing table '{table_name}': {e}")
            return False

    def _capture_catalog_snapshot(self) -> Dict[str, Any]:
        """Captures a snapshot of the current database catalog state."""
        return {
            'tables': {name: {'columns': [{'name': col.name, 'type': col.data_type} for col in table.columns]} 
                      for name, table in self.catalog.tables.items()},
            'views': {name: {'columns': [{'name': col.name, 'type': col.data_type} for col in table.columns]} 
                     for name, table in self.catalog.views.items()},
            'functions': [{'name': func.name, 'arg_types': func.arg_types} for func in self.catalog.functions],
            'types': self.catalog.types
        }

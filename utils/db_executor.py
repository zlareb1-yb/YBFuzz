# This module encapsulates all direct interaction with the database.
# This optimized version includes a dedicated logger that creates a clean
# SQL script for easy bug reproduction.

import psycopg2
import logging
import random
from config import FuzzerConfig
from utils.bug_reporter import BugReporter
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional, Tuple

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
        self.functions: list[DiscoveredFunction] = []
        self.types: list[str] = []

        self.refresh()
        self.discover_vocabulary()

    def refresh(self):
        """Reloads the table and column schema from the database."""
        self.logger.info("Refreshing schema catalog (tables and columns)...")
        self.tables = {}
        query = "SELECT table_name FROM information_schema.tables WHERE table_schema = %s;"
        try:
            with self._get_conn().cursor() as cur:
                cur.execute(query, (self.schema_name,))
                table_names = [row[0] for row in cur.fetchall()]
                for table_name in table_names:
                    self._add_table_to_catalog(table_name)
        except psycopg2.Error as e:
            self.logger.error(f"Failed to refresh catalog: {e}")
        self.logger.info(f"Catalog refreshed. Found {len(self.tables)} tables.")

    def _add_table_to_catalog(self, table_name: str):
        table = Table(name=table_name)
        query = "SELECT column_name, data_type FROM information_schema.columns WHERE table_schema = %s AND table_name = %s;"
        try:
            with self._get_conn().cursor() as cur:
                cur.execute(query, (self.schema_name, table_name))
                for row in cur.fetchall():
                    table.columns.append(Column(name=row[0], data_type=row[1]))
            if table.columns:
                self.tables[table_name] = table
        except psycopg2.Error as e:
            self.logger.error(f"Failed to add table '{table_name}' to catalog: {e}")

    def discover_vocabulary(self):
        """Queries pg_catalog to discover functions and types."""
        self.logger.info("Discovering database vocabulary (functions, types)...")
        try:
            with self._get_conn().cursor() as cur:
                # Discover functions
                func_query = """
                SELECT p.proname, pg_catalog.pg_get_function_identity_arguments(p.oid) as arg_types
                FROM pg_catalog.pg_proc p
                JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
                WHERE n.nspname = 'pg_catalog' AND p.prokind = 'f' AND p.prorettype <> 'pg_catalog.trigger'::pg_catalog.regtype;
                """
                cur.execute(func_query)
                self.functions = []
                for row in cur.fetchall():
                    func_name, arg_types_str = row
                    arg_types = [t.strip() for t in arg_types_str.split(',')] if arg_types_str else []
                    # Filter out functions with complex types we don't handle yet
                    if any(t in ['internal', 'any', 'oid', 'record', 'trigger'] for t in arg_types_str):
                        continue
                    self.functions.append(DiscoveredFunction(name=func_name, arg_types=arg_types))
                
                # Discover types
                type_query = "SELECT typname FROM pg_catalog.pg_type WHERE typtype = 'b';" # Base types
                cur.execute(type_query)
                self.types = [row[0] for row in cur.fetchall()]

        except psycopg2.Error as e:
            self.logger.error(f"Failed to discover database vocabulary: {e}")
        
        self.logger.info(f"Discovered {len(self.functions)} functions and {len(self.types)} base types.")


    def get_random_table(self) -> Table | None:
        return random.choice(list(self.tables.values())) if self.tables else None

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
        """Establishes a connection to the database."""
        try:
            # Filter out non-connection parameters
            valid_conn_params = ['host', 'port', 'user', 'password', 'dbname']
            conn_config = {k: v for k, v in self.db_config.items() if k in valid_conn_params}
            
            self.logger.info(f"Connecting to database '{conn_config['dbname']}' on {conn_config['host']}...")
            self.conn = psycopg2.connect(**conn_config)
        except psycopg2.OperationalError as e:
            self.logger.critical(f"Database connection failed: {e}")
            raise

    def get_connection(self):
        """Returns the current connection, attempting to reconnect if closed."""
        if self.conn is None or self.conn.closed:
            self.logger.warning("Database connection is closed. Attempting to reconnect...")
            self._connect()
        return self.conn

    def execute_query(self, sql: str) -> tuple[list | None, Exception | None]:
        """Executes a single SQL query in its own transaction."""
        self.query_history.append(sql)
        self.logger.debug(f"Executing: {sql[:400]}")
        
        # Log to the clean SQL script file
        self.sql_logger.info(f"{sql.strip()}\n")

        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                cur.execute(sql)
                if cur.description:
                    result = cur.fetchall()
                else:
                    result = [] # For DML/DDL that don't return rows
                conn.commit()
                return result, None
        except psycopg2.Error as e:
            conn.rollback()
            
            # Check if this is a missing table error and try to create it
            if "does not exist" in str(e) and "relation" in str(e):
                table_name = self._extract_missing_table_name(str(e))
                if table_name and self._create_missing_table(table_name):
                    # Retry the query after creating the table
                    try:
                        with conn.cursor() as cur:
                            cur.execute(sql)
                            if cur.description:
                                result = cur.fetchall()
                            else:
                                result = []
                            conn.commit()
                            self.logger.info(f"Successfully executed query after creating missing table '{table_name}'")
                            return result, None
                    except psycopg2.Error as retry_e:
                        conn.rollback()
                        self.logger.warning(f"Query still failed after creating table '{table_name}': {retry_e}")
            
            # Handle duplicate object errors gracefully
            if "already exists" in str(e):
                self.logger.debug(f"Object already exists (expected in fuzzing): {e}")
                return [], None  # Return empty result for duplicate objects
            
            if isinstance(e, (psycopg2.InternalError, psycopg2.OperationalError)):
                # Capture catalog snapshot for bug reproduction
                catalog_snapshot = self._capture_catalog_snapshot()
                self.bug_reporter.report_bug(
                    "DBExecutor", 
                    "Critical Database Error", 
                    "Query caused a server-side error.", 
                    original_query=sql, 
                    exception=e,
                    query_history=self.query_history[-10:],  # Last 10 queries for context
                    catalog_snapshot=catalog_snapshot
                )
            elif "column.*is of type.*but expression is of type" in str(e):
                # Type mismatch bug - this is a real bug
                catalog_snapshot = self._capture_catalog_snapshot()
                self.bug_reporter.report_bug(
                    "DBExecutor",
                    "Type Mismatch Bug",
                    "Column type mismatch in UPDATE/SET statement.",
                    original_query=sql,
                    exception=e,
                    query_history=self.query_history[-10:],
                    catalog_snapshot=catalog_snapshot
                )
            elif "syntax error at or near" in str(e) and "UPDATE" in sql.upper():
                # Syntax error in UPDATE statement - this could be a parser bug
                catalog_snapshot = self._capture_catalog_snapshot()
                self.bug_reporter.report_bug(
                    "DBExecutor",
                    "Syntax Error Bug",
                    "Unexpected syntax error in UPDATE statement.",
                    original_query=sql,
                    exception=e,
                    query_history=self.query_history[-10:],
                    catalog_snapshot=catalog_snapshot
                )
            elif "null value in column.*violates not-null constraint" in str(e):
                # Constraint violation bug
                catalog_snapshot = self._capture_catalog_snapshot()
                self.bug_reporter.report_bug(
                    "DBExecutor",
                    "Constraint Violation Bug",
                    "Unexpected null value violation in INSERT/UPDATE.",
                    original_query=sql,
                    exception=e,
                    query_history=self.query_history[-10:],
                    catalog_snapshot=catalog_snapshot
                )
            else:
                self.logger.warning(f"Query failed with non-critical error: {e}")
            return None, e

    def execute_query_with_setup(self, setup_sqls: list[str], query: str, teardown_sqls: list[str]) -> tuple[list | None, Exception | None]:
        """Executes a query within a setup/teardown context for oracles."""
        conn = self.get_connection()
        try:
            with conn.cursor() as cur:
                for sql in setup_sqls: cur.execute(sql)
                cur.execute(query)
                result = cur.fetchall() if cur.description else []
                for sql in teardown_sqls: cur.execute(sql)
            conn.commit()
            return result, None
        except psycopg2.Error as e:
            conn.rollback()
            return None, e

    def execute_admin(self, sql: str):
        """Executes an administrative command with error handling."""
        self.logger.info(f"Executing admin command: {sql}")
        self.execute_query(sql)

    def close(self):
        """Closes the database connection."""
        if self.conn and not self.conn.closed:
            self.conn.close()
            self.logger.info("Database connection closed.")
    
    def _extract_missing_table_name(self, error_msg: str) -> str | None:
        """Extracts the missing table name from a PostgreSQL error message."""
        import re
        # Look for patterns like "relation "table_name" does not exist"
        match = re.search(r'relation "([^"]+)" does not exist', error_msg)
        if match:
            table_name = match.group(1)
            # Remove schema prefix if present
            if '.' in table_name:
                table_name = table_name.split('.')[-1]
            return table_name
        return None
    
    def _create_missing_table(self, table_name: str) -> bool:
        """Creates a missing table with a basic structure."""
        try:
            schema_name = self.config.get_db_config()['schema_name']
            full_table_name = f"{schema_name}.{table_name}"
            
            # Create a basic table structure based on common patterns
            if table_name.lower() in ['orders', 'order_items', 'order_details']:
                create_sql = f"""
                CREATE TABLE {full_table_name} (
                    id SERIAL PRIMARY KEY,
                    order_id INTEGER,
                    product_id INTEGER,
                    quantity INTEGER,
                    price NUMERIC(10,2),
                    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO {full_table_name} (order_id, product_id, quantity, price) 
                SELECT g, (g % 50) + 1, (g % 10) + 1, (g % 100) + 10.0 
                FROM generate_series(1, 50) g;
                """
            elif table_name.lower() in ['customers', 'users', 'clients']:
                create_sql = f"""
                CREATE TABLE {full_table_name} (
                    id SERIAL PRIMARY KEY,
                    name TEXT,
                    email TEXT,
                    phone TEXT,
                    address TEXT,
                    created_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO {full_table_name} (name, email, phone, address) 
                SELECT 
                    'Customer-' || g,
                    'customer' || g || '@example.com',
                    '+1-555-' || LPAD(g::text, 4, '0'),
                    'Address ' || g || ', City, State'
                FROM generate_series(1, 25) g;
                """
            elif table_name.lower() in ['categories', 'departments']:
                create_sql = f"""
                CREATE TABLE {full_table_name} (
                    id SERIAL PRIMARY KEY,
                    name TEXT,
                    description TEXT,
                    parent_id INTEGER
                );
                INSERT INTO {full_table_name} (name, description, parent_id) 
                SELECT 
                    'Category-' || g,
                    'Description for category ' || g,
                    CASE WHEN g % 3 = 0 THEN NULL ELSE (g % 5) + 1 END
                FROM generate_series(1, 10) g;
                """
            else:
                # Generic table structure
                create_sql = f"""
                CREATE TABLE {full_table_name} (
                    id SERIAL PRIMARY KEY,
                    name TEXT,
                    value NUMERIC(10,2),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                );
                INSERT INTO {full_table_name} (name, value) 
                SELECT 'Item-' || g, (g % 100) + 1.0 
                FROM generate_series(1, 20) g;
                """
            
            self.logger.info(f"Creating missing table '{table_name}' with basic structure")
            self.execute_admin(create_sql)
            
            # Refresh the catalog to include the new table
            self.catalog.refresh()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to create missing table '{table_name}': {e}")
            return False

    def _capture_catalog_snapshot(self) -> Dict[str, Any]:
        """Captures a snapshot of the current database catalog for bug reproduction."""
        try:
            snapshot = {
                "tables": {},
                "functions": [],
                "types": []
            }
            
            # Capture table schemas
            if hasattr(self, 'catalog') and self.catalog:
                for table in self.catalog.tables:
                    if hasattr(table, 'name') and hasattr(table, 'columns'):
                        table_info = {
                            "name": table.name,
                            "columns": []
                        }
                        for col in table.columns:
                            if hasattr(col, 'name') and hasattr(col, 'data_type'):
                                table_info["columns"].append({
                                    "name": col.name,
                                    "type": col.data_type
                                })
                        snapshot["tables"][table.name] = table_info
                
                # Capture functions and types if available
                if hasattr(self.catalog, 'functions'):
                    snapshot["functions"] = [f.name for f in self.catalog.functions[:20]]  # Limit to first 20
                if hasattr(self.catalog, 'types'):
                    snapshot["types"] = [t for t in self.catalog.types[:20]]  # Limit to first 20
            
            return snapshot
        except Exception as e:
            self.logger.warning(f"Failed to capture catalog snapshot: {e}")
            return {}
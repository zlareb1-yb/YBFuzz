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
            self.logger.info(f"Connecting to database '{self.db_config['dbname']}' on {self.db_config['host']}...")
            self.conn = psycopg2.connect(**self.db_config)
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
            if isinstance(e, (psycopg2.InternalError, psycopg2.OperationalError)):
                self.bug_reporter.report_bug("DBExecutor", "Critical Database Error", "Query caused a server-side error.", original_query=sql, exception=e)
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
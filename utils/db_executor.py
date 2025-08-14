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
import time

# --- Schema and Vocabulary Representation ---
@dataclass
class Column:
    name: str
    type: str
    nullable: bool = True
    default_value: Optional[str] = None

@dataclass
class Table:
    name: str
    schema: str = "public"
    type: str = "BASE TABLE"
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
        """Reloads the table and column schema from the database using bulk queries for maximum performance."""
        self.logger.info("Refreshing schema catalog (tables and columns)...")
        start_time = time.time()
        
        self.tables = {}
        self.views = {}
        
        try:
            # BULK APPROACH: Get all tables and columns in minimal queries
            # This reduces 150+ individual queries to just 2-3 bulk queries
            
            # Query 1: Get all tables and views in one query
            tables_query = """
                SELECT table_name, table_schema, table_type 
                FROM information_schema.tables 
                WHERE table_schema IN ('public', 'information_schema', 'pg_catalog')
                AND table_type IN ('BASE TABLE', 'VIEW')
                ORDER BY table_schema, table_name
                LIMIT 200
            """
            
            with self._get_conn().cursor() as cur:
                cur.execute(tables_query)
                tables_result = cur.fetchall()
                
                if not tables_result:
                    self.logger.warning("No tables found during catalog refresh")
                    return
                
                # Query 2: Get all columns for all tables in one bulk query
                # This is the key optimization - instead of 150+ individual queries
                columns_query = """
                    SELECT c.table_name, c.table_schema, c.column_name, c.data_type, 
                           c.is_nullable, c.column_default
                    FROM information_schema.columns c
                    INNER JOIN information_schema.tables t 
                        ON c.table_name = t.table_name AND c.table_schema = t.table_schema
                    WHERE t.table_schema IN ('public', 'information_schema', 'pg_catalog')
                    AND t.table_type IN ('BASE TABLE', 'VIEW')
                    ORDER BY c.table_schema, c.table_name, c.ordinal_position
                    LIMIT 2000
                """
                
                cur.execute(columns_query)
                columns_result = cur.fetchall()
                
                # Process results efficiently
                tables_dict = {}
                
                # Build tables dictionary
                for row in tables_result:
                    table_name, table_schema, table_type = row
                    table_key = f"{table_schema}.{table_name}"
                    
                    table = Table(
                        name=table_name,
                        schema=table_schema,
                        type=table_type,
                        columns=[]
                    )
                    
                    if table_type == 'VIEW':
                        self.views[table_name] = table
                    else:
                        self.tables[table_name] = table
                    
                    tables_dict[table_key] = table
                
                # Build columns dictionary and assign to tables
                if columns_result:
                    for row in columns_result:
                        table_name, table_schema, column_name, data_type, is_nullable, column_default = row
                        table_key = f"{table_schema}.{table_name}"
                        
                        if table_key in tables_dict:
                            column = Column(
                                name=column_name,
                                type=data_type,
                                nullable=is_nullable == 'YES' if is_nullable else False,
                                default_value=column_default
                            )
                            tables_dict[table_key].columns.append(column)
                
                elapsed_time = time.time() - start_time
                self.logger.info(f"Catalog refreshed in {elapsed_time:.2f}s. Found {len(self.tables)} tables and {len(self.views)} views.")
                
        except psycopg2.Error as e:
            error_code = e.pgcode
            if error_code in ['25P02', '25P03']:  # Transaction state errors
                self.logger.warning(f"Transaction state error during catalog refresh, reconnecting: {e}")
                try:
                    # Force a clean reconnection through the DBExecutor
                    self._get_conn().close()
                    # Retry with fresh connection
                    self.refresh()
                except Exception as retry_error:
                    self.logger.error(f"Catalog refresh retry failed: {retry_error}")
            else:
                self.logger.error(f"Failed to refresh catalog: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error during catalog refresh: {e}")

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
    
    def get_table(self, table_name: str, schema: str = None) -> Table | None:
        """Get a table by name and schema."""
        if schema is None:
            schema = self.schema_name
        
        # First check in tables
        if table_name in self.tables:
            return self.tables[table_name]
        
        # Then check in views
        if table_name in self.views:
            return self.views[table_name]
        
        # If schema is specified and different from current, try to find it
        if schema != self.schema_name:
            # This would require additional logic to query other schemas
            # For now, return None if table not found in current schema
            pass
        
        return None
    
    def get_all_tables(self) -> List[Table]:
        """Get all tables and views."""
        return list(self.tables.values()) + list(self.views.values())

class DBExecutor:
    """Handles resilient connection and execution of SQL queries."""
    def __init__(self, db_config: dict, bug_reporter: BugReporter, config: FuzzerConfig):
        self.db_config = db_config
        self.bug_reporter = bug_reporter
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.conn = None
        self._connect()
        
        # Set database type for oracle compatibility
        self.db_type = 'yugabyte'  # or 'postgresql' if needed
        
        # Add schema_name attribute for oracle compatibility
        self.schema_name = self.db_config['schema_name']
        
        self.catalog = Catalog(self.get_connection, self.db_config['schema_name'])
        self.query_history = []

    def _connect(self) -> None:
        """Establish database connection."""
        try:
            # Parse hosts if multiple
            hosts = self.db_config.get('host', 'localhost').split(',')
            host = hosts[0].strip()  # Use first host for now
            
            # Build connection parameters
            conn_params = {
                'host': host,
                'port': self.db_config.get('port', 5433),
                'database': self.db_config.get('dbname', 'yugabyte'),
                'user': self.db_config.get('user', 'yugabyte'),
                'password': self.db_config.get('password', ''),
                'connect_timeout': self.db_config.get('connect_timeout', 10),
                'application_name': 'YBFuzz'
            }
            
            # Add SSL configuration if enabled
            if self.db_config.get('enable_ssl', False):
                conn_params['sslmode'] = self.db_config.get('ssl_mode', 'require')
            
            # Establish connection
            self.conn = psycopg2.connect(**conn_params)
            self.conn.autocommit = True
            
            # Set session parameters
            with self.conn.cursor() as cursor:
                cursor.execute("SET statement_timeout = 30000")  # 30 seconds
                cursor.execute("SET lock_timeout = 10000")       # 10 seconds
            
            self.logger.info(f"Connected to database '{conn_params['database']}' on {host}:{conn_params['port']}")
            
        except Exception as e:
            self.logger.error(f"Database connection failed: {e}")
            raise

    def get_connection(self):
        """Returns a database connection."""
        if not self.conn or self.conn.closed:
            self._connect()
        return self.conn
    
    def reconnect(self):
        """Force a reconnection to handle transaction state errors."""
        try:
            if self.conn and not self.conn.closed:
                self.conn.close()
            self._connect()
            self.logger.info("Successfully reconnected to database")
        except Exception as e:
            self.logger.error(f"Failed to reconnect: {e}")
            raise

    def _validate_and_fix_sql(self, query: str) -> str:
        """
        Validate and fix SQL queries to ensure they are safe to execute.
        Returns a safe SQL query or a fallback query.
        """
        try:
            # Clean up the query
            clean_query = query.strip()
            if not clean_query:
                return "SELECT COUNT(*) FROM information_schema.tables LIMIT 1"
            
            # Check for valid SQL statements
            valid_sql_starts = [
                'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER',
                'BEGIN', 'COMMIT', 'ROLLBACK', 'SET', 'RESET', 'EXPLAIN', 'ANALYZE', 'VACUUM',
                'WITH'  # CRITICAL FIX: Add CTE support
            ]
            
            if any(clean_query.upper().startswith(start) for start in valid_sql_starts):
                if self._looks_like_complete_sql(clean_query):
                    return clean_query
            
            # Handle comments - just return safe query
            if clean_query.startswith('--') or clean_query.startswith('/*'):
                return "SELECT COUNT(*) FROM information_schema.tables LIMIT 1"
            
            # If we get here, the query is incomplete or invalid
            # Return a safe fallback query
            return "SELECT COUNT(*) FROM information_schema.tables LIMIT 1"
            
        except Exception as e:
            # If anything goes wrong, return a safe fallback
            return "SELECT COUNT(*) FROM information_schema.tables LIMIT 1"
    
    def _looks_like_complete_sql(self, query: str) -> bool:
        """Check if a query looks like a complete SQL statement using advanced parsing."""
        try:
            # Clean up the query by removing extra whitespace and newlines
            clean_query = ' '.join(query.split())
            query_upper = clean_query.upper()
            
            # Always complete statements
            always_complete = [
                "SET ", "RESET ", "EXPLAIN", "BEGIN", "COMMIT", "ROLLBACK",
                "CREATE ", "DROP ", "ALTER ", "INSERT ", "UPDATE ", "DELETE ",
                "ANALYZE", "VACUUM", "GRANT", "REVOKE"
            ]
            
            if any(query_upper.startswith(prefix) for prefix in always_complete):
                return True
            
            # SELECT statements - use advanced validation
            if query_upper.startswith("SELECT "):
                return self._is_complete_select_statement(clean_query, query_upper)
            
            # WITH statements (CTEs) - PERMISSIVE: Always treat as complete
            if query_upper.startswith("WITH "):
                # CRITICAL FIX: CTEs are complex but valid - always accept them
                return True
            
            # If we get here, it's probably incomplete
            return False
            
        except Exception as e:
            # If anything goes wrong, assume it's incomplete
            return False
    
    def _is_complete_select_statement(self, query: str, query_upper: str) -> bool:
        """Advanced validation for SELECT statements including complex patterns."""
        try:
            # Basic structure checks
            if "FROM " not in query_upper:
                return False
            
            # Check for balanced parentheses (important for complex expressions)
            if query.count('(') != query.count(')'):
                return False
            
            # Check for proper ending patterns
            proper_endings = [
                ";", "LIMIT", "ORDER BY", "GROUP BY", "HAVING", 
                "UNION", "UNION ALL", "INTERSECT", "EXCEPT"
            ]
            
            if any(query_upper.endswith(ending) for ending in proper_endings):
                return True
            
            # Check for complete structure patterns
            structure_patterns = [
                ("FROM ", "WHERE "),
                ("FROM ", "GROUP BY "),
                ("FROM ", "ORDER BY "),
                ("FROM ", "LIMIT "),
                ("FROM ", "HAVING "),
                ("FROM ", "UNION "),
                ("FROM ", "INTERSECT "),
                ("FROM ", "EXCEPT ")
            ]
            
            for pattern in structure_patterns:
                if pattern[0] in query_upper and pattern[1] in query_upper:
                    return True
            
            # Simple SELECT with FROM is complete
            if query_upper.count("SELECT") == 1 and query_upper.count("FROM") == 1:
                return True
            
            # Complex patterns that are always complete
            complex_patterns = [
                "OVER (", "PARTITION BY", "ROWS BETWEEN", "RANGE BETWEEN",
                "CASE WHEN", "THEN ", "ELSE ", "END",
                "EXISTS (", "IN (", "NOT IN (",
                "JOIN ", "INNER JOIN", "LEFT JOIN", "RIGHT JOIN", "FULL JOIN",
                "CROSS JOIN", "OUTER JOIN"
            ]
            
            if any(pattern in query_upper for pattern in complex_patterns):
                return True
            
            return False
            
        except Exception:
            return False
    
    def _is_complete_cte_statement(self, query: str, query_upper: str) -> bool:
        """Advanced validation for CTE (Common Table Expression) statements."""
        try:
            # CTEs must have balanced parentheses
            if query.count('(') != query.count(')'):
                return False
            
            # Check for proper CTE structure
            if "WITH RECURSIVE " in query_upper:
                # Recursive CTEs are complex but valid - be more permissive
                # Must have at least one CTE definition and a main query
                if "AS (" in query_upper and "SELECT " in query_upper:
                    return True
                # Also check for UNION ALL pattern in recursive CTEs
                if "UNION ALL" in query_upper:
                    return True
                # Recursive CTEs with complex patterns are valid
                if "JOIN " in query_upper or "WHERE " in query_upper or "ORDER BY " in query_upper:
                    return True
                # For recursive CTEs, be more permissive - they're complex by nature
                return True
            
            if "WITH " in query_upper:
                # Regular CTEs
                # Must have at least one CTE definition and a main query
                if "AS (" in query_upper and "SELECT " in query_upper:
                    return True
                # Also check for complex CTE patterns
                if "JOIN " in query_upper or "WHERE " in query_upper or "ORDER BY " in query_upper:
                    return True
            
            return False
            
        except Exception:
            return False
    
    def execute_query(self, query: str, fetch_results: bool = True, high_performance: bool = False) -> Any:
        """Execute a SQL query and return results or row count. Each query runs independently."""
        # HIGH-PERFORMANCE MODE: Skip validation for maximum speed
        if high_performance:
            valid_query = query
        else:
            # CRITICAL: Validate and fix the SQL before execution
            valid_query = self._validate_and_fix_sql(query)
            
            # Log if we had to fix the query
            if valid_query != query:
                self.logger.warning(f"Fixed incomplete SQL: '{query}' -> '{valid_query}'")
        
        # Auto-detect query type and set fetch_results appropriately
        query_upper = valid_query.strip().upper()
        if query_upper.startswith(('INSERT', 'UPDATE', 'DELETE', 'CREATE', 'DROP', 'ALTER', 'TRUNCATE', 'GRANT', 'REVOKE')):
            fetch_results = False  # These queries don't return result sets
        elif query_upper.startswith(('SET', 'RESET')):
            fetch_results = False  # Session management commands don't return result sets
        
        try:
            # Use existing connection if available and healthy
            if not self.conn or self.conn.closed:
                self._connect()
            
            with self.conn.cursor() as cursor:
                cursor.execute(valid_query)
                
                if fetch_results:
                    # HIGH-PERFORMANCE MODE: Use fetchmany for maximum speed
                    if high_performance:
                        data = cursor.fetchmany(5)  # Limit to 5 rows for speed
                    else:
                        data = cursor.fetchall()
                    
                    # Return a result object with expected structure for oracles
                    class QueryResult:
                        def __init__(self, data):
                            self.success = True
                            self.data = data
                            self.rows = data if data else []
                            self.columns = [desc[0] for desc in cursor.description] if cursor.description else []
                        
                        def get(self, key, default=None):
                            """Support dictionary-style access for oracle compatibility."""
                            if hasattr(self, key):
                                return getattr(self, key)
                            return default
                        
                        def __getitem__(self, key):
                            """Support bracket access for oracle compatibility."""
                            if hasattr(self, key):
                                return getattr(self, key)
                            raise KeyError(key)
                    return QueryResult(data)
                else:
                    rowcount = cursor.rowcount
                    # Return a result object with success attribute
                    class QueryResult:
                        def __init__(self, rowcount):
                            self.success = True
                            self.data = None
                            self.rows = []
                            self.rowcount = rowcount
                        
                        def get(self, key, default=None):
                            """Support dictionary-style access for oracle compatibility."""
                            if hasattr(self, key):
                                return getattr(self, key)
                            return default
                        
                        def __getitem__(self, key):
                            """Support bracket access for oracle compatibility."""
                            if hasattr(self, key):
                                return getattr(self, key)
                            raise KeyError(key)
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
                        cursor.execute(valid_query)
                        if fetch_results:
                            data = cursor.fetchall()
                            class QueryResult:
                                def __init__(self, data):
                                    self.success = True
                                    self.data = data
                                    self.rows = data if data else []
                                    self.columns = [desc[0] for desc in cursor.description] if cursor.description else []
                            return QueryResult(data)
                        else:
                            rowcount = cursor.rowcount
                            class QueryResult:
                                def __init__(self, rowcount):
                                    self.success = True
                                    self.data = None
                                    self.rows = []
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
            
            # Handle "no results to fetch" - this is expected for non-SELECT queries
            elif (error_code == '02000' or 
                  'no results to fetch' in str(e).lower() or 
                  'no data' in str(e).lower() or
                  'no rows' in str(e).lower()):  # Various "no results" scenarios
                if not fetch_results:
                    # For non-SELECT queries, this is expected behavior
                    class QueryResult:
                        def __init__(self):
                            self.success = True
                            self.data = None
                            self.rows = []
                            self.rowcount = 0
                    return QueryResult()
                else:
                    # For SELECT queries, this might indicate an issue
                    self.logger.debug(f"Query returned no results: {e}")
                    class QueryResult:
                        def __init__(self):
                            self.success = True
                            self.data = []
                            self.rows = []
                            self.columns = []
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

    def refresh_catalog(self) -> None:
        """Refresh the schema catalog with bulk queries for maximum performance."""
        try:
            self.logger.info("Refreshing schema catalog (tables and columns)...")
            start_time = time.time()
            
            # BULK APPROACH: Get all tables and columns in minimal queries
            # This reduces 150+ individual queries to just 2-3 bulk queries
            
            try:
                # Query 1: Get all tables and views in one query
                tables_query = """
                    SELECT table_name, table_schema, table_type 
                    FROM information_schema.tables 
                    WHERE table_schema IN ('public', 'information_schema', 'pg_catalog')
                    AND table_type IN ('BASE TABLE', 'VIEW')
                    ORDER BY table_schema, table_name
                    LIMIT 200
                """
                
                tables_result = self.execute_query(tables_query)
                if not tables_result or not tables_result.rows:
                    self.logger.warning("No tables found during catalog refresh")
                    return
                
                # Query 2: Get all columns for all tables in one bulk query
                # This is the key optimization - instead of 150+ individual queries
                columns_query = """
                    SELECT c.table_name, c.table_schema, c.column_name, c.data_type, 
                           c.is_nullable, c.column_default
                    FROM information_schema.columns c
                    INNER JOIN information_schema.tables t 
                        ON c.table_name = t.table_name AND c.table_schema = t.table_schema
                    WHERE t.table_schema IN ('public', 'information_schema', 'pg_catalog')
                    AND t.table_type IN ('BASE TABLE', 'VIEW')
                    ORDER BY c.table_schema, c.table_name, c.ordinal_position
                    LIMIT 2000
                """
                
                columns_result = self.execute_query(columns_query)
                
                # Process results efficiently
                tables_dict = {}
                columns_dict = {}
                
                # Build tables dictionary
                for row in tables_result.rows:
                    table_name, table_schema, table_type = row
                    table_key = f"{table_schema}.{table_name}"
                    
                    table = Table(
                        name=table_name,
                        schema=table_schema,
                        type=table_type,
                        columns=[]
                    )
                    
                    if table_type == 'VIEW':
                        self.views.append(table)
                    else:
                        self.tables.append(table)
                    
                    tables_dict[table_key] = table
                
                # Build columns dictionary and assign to tables
                if columns_result and columns_result.rows:
                    for row in columns_result.rows:
                        table_name, table_schema, column_name, data_type, is_nullable, column_default = row
                        table_key = f"{table_schema}.{table_name}"
                        
                        if table_key in tables_dict:
                            column = Column(
                                name=column_name,
                                type=data_type,
                                nullable=is_nullable == 'YES',
                                default_value=column_default
                            )
                            tables_dict[table_key].columns.append(column)
                
                elapsed_time = time.time() - start_time
                self.logger.info(f"Catalog refreshed in {elapsed_time:.2f}s. Found {len(self.tables)} tables and {len(self.views)} views.")
                
            except Exception as e:
                self.logger.error(f"Catalog refresh failed: {e}")
                # Continue with empty catalog rather than failing completely
                
        except Exception as e:
            self.logger.error(f"Failed to refresh catalog: {e}")
            # Continue with empty catalog rather than failing completely

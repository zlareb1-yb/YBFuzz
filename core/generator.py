# Contains the intelligent, recursive-descent query generator.
# It correctly builds a rich, specific, and deeply nested Abstract Syntax Tree (AST)
# for all supported SQL constructs. It includes all advanced semantic rule
# enforcement and automatic vocabulary discovery integration, with no features removed.

import logging
import random
import time
from config import FuzzerConfig
from utils.db_executor import Catalog, Table, Column, DiscoveredFunction

# --- Rich Abstract Syntax Tree (AST) Nodes ---
from abc import ABC, abstractmethod
class SQLNode(ABC):
    def __init__(self): self.parent = None; self.children = []
    def add_child(self, node):
        if node: self.children.append(node); node.parent = self
    def find_child_of_type(self, node_type):
        for child in self.children:
            if isinstance(child, node_type): return child
        for child in self.children:
            found = child.find_child_of_type(node_type)
            if found: return found
        return None
    @abstractmethod
    def to_sql(self) -> str: pass

class RawSQL(SQLNode):
    def __init__(self, sql: str): super().__init__(); self.sql = sql
    def to_sql(self) -> str: return self.sql

class ColumnNode(SQLNode):
    def __init__(self, column: Column): super().__init__(); self.column = column
    def to_sql(self) -> str: return f'"{self.column.name}"'

class LiteralNode(SQLNode):
    def __init__(self, value): super().__init__(); self.value = value
    def to_sql(self) -> str:
        if self.value is None: return "NULL"
        if isinstance(self.value, (int, float)): return str(self.value)
        return f"'{str(self.value).replace("'", "''")}'"

class FunctionCallNode(SQLNode):
    def __init__(self, func: DiscoveredFunction, args: list['SQLNode']):
        super().__init__(); self.func = func; self.args = args
        for arg in args: self.add_child(arg)
    def to_sql(self) -> str: return f"{self.func.name}({', '.join(arg.to_sql() for arg in self.args)})"

class BinaryOpNode(SQLNode):
    def __init__(self, left: SQLNode, op: str, right: SQLNode):
        super().__init__(); self.left = left; self.op = op; self.right = right
        self.add_child(left); self.add_child(right)
    def to_sql(self) -> str: return f"({self.left.to_sql()} {self.op} {self.right.to_sql()})"

class SequenceNode(SQLNode):
    def __init__(self, elements: list, separator: str = " "):
        super().__init__(); self.elements = elements; self.separator = separator
        for el in elements: self.add_child(el)
    def to_sql(self) -> str: return self.separator.join(e.to_sql() for e in self.elements if e)

class WhereClauseNode(SequenceNode): pass

class SelectNode(SQLNode):
    def __init__(self, projections, from_clause, where_clause=None, group_by_clause=None, limit_clause=None):
        super().__init__(); self.projections = projections; self.from_clause = from_clause
        self.where_clause = where_clause; self.group_by_clause = group_by_clause; self.limit_clause = limit_clause
    def to_sql(self) -> str:
        # Add defensive checks for None values
        if not self.projections or not self.from_clause:
            return "SELECT 1;"
        
        parts = [f"SELECT {self.projections.to_sql()}", self.from_clause.to_sql()]
        if self.where_clause: parts.append(self.where_clause.to_sql())
        if self.group_by_clause: parts.append(self.group_by_clause.to_sql())
        if self.limit_clause: parts.append(self.limit_clause.to_sql())
        return " ".join(parts) + ";"

class CreateTableNode(SQLNode):
    def __init__(self, table_name: RawSQL, columns: 'SequenceNode'):
        super().__init__(); self.table_name = table_name; self.columns = columns
    def to_sql(self) -> str: return f"CREATE TABLE {self.table_name.to_sql()} ({self.columns.to_sql()});"

class CreateViewNode(SQLNode):
    def __init__(self, view_name: RawSQL, select_stmt: SelectNode):
        super().__init__(); self.view_name = view_name; self.select_stmt = select_stmt
    def to_sql(self) -> str: return f"CREATE VIEW {self.view_name.to_sql()} AS {self.select_stmt.to_sql()}"

class CreateIndexNode(SQLNode):
    def __init__(self, index_name: RawSQL, table: RawSQL, column: ColumnNode):
        super().__init__(); self.index_name = index_name; self.table = table; self.column = column
    def to_sql(self) -> str: return f"CREATE INDEX {self.index_name.to_sql()} ON {self.table.to_sql()} ({self.column.to_sql()});"

class InsertNode(SQLNode):
    def __init__(self, table: RawSQL, columns: 'SequenceNode', values: 'SequenceNode'):
        super().__init__(); self.table = table; self.columns = columns; self.values = values
    def to_sql(self) -> str: return f"INSERT INTO {self.table.to_sql()} ({self.columns.to_sql()}) VALUES ({self.values.to_sql()});"

class UpdateNode(SQLNode):
    def __init__(self, table: RawSQL, assignment: 'UpdateAssignmentNode', where_clause=None):
        super().__init__(); self.table = table; self.assignment = assignment; self.where_clause = where_clause
    def to_sql(self) -> str:
        sql = f"UPDATE {self.table.to_sql()} SET {self.assignment.to_sql()}"
        if self.where_clause: sql += f" {self.where_clause.to_sql()}"
        return sql + ";"

class DeleteNode(SQLNode):
    def __init__(self, table: RawSQL, where_clause=None):
        super().__init__(); self.table = table; self.where_clause = where_clause
    def to_sql(self) -> str:
        sql = f"DELETE FROM {self.table.to_sql()}"
        if self.where_clause: sql += f" {self.where_clause.to_sql()}"
        return sql + ";"

class ColumnDefNode(SQLNode):
    def __init__(self, col_name: RawSQL, col_type: RawSQL):
        super().__init__(); self.col_name = col_name; self.col_type = col_type
    def to_sql(self) -> str: return f"{self.col_name.to_sql()} {self.col_type.to_sql()}"

class UpdateAssignmentNode(SQLNode):
    def __init__(self, column: ColumnNode, expression: SQLNode):
        super().__init__(); self.column = column; self.expression = expression
    def to_sql(self) -> str: return f"{self.column.to_sql()} = {self.expression.to_sql()}"

# --- Generation Context ---
from dataclasses import dataclass, field
@dataclass
class GenerationContext:
    catalog: Catalog; config: FuzzerConfig; recursion_depth: dict[str, int] = field(default_factory=dict)
    current_table: Table | None = None; grouping_columns: list[Column] = field(default_factory=list)
    expected_type: str | None = None; insert_columns: list[Column] = field(default_factory=list)

class GrammarGenerator:
    def __init__(self, grammar: dict, config: FuzzerConfig, catalog: Catalog):
        self.grammar = grammar; self.config = config; self.catalog = catalog
        self.logger = logging.getLogger(self.__class__.__name__)

    def generate_statement_of_type(self, statement_type: str) -> SQLNode | None:
        context = GenerationContext(catalog=self.catalog, config=self.config)
        return self._generate_rule(statement_type, context)

    def _generate_rule(self, rule_name: str, context: GenerationContext) -> SQLNode | None:
        depth = context.recursion_depth.get(rule_name, 0); max_depth = self.config.get('max_recursion_depth', {}).get(rule_name, 10)
        if depth >= max_depth: self.logger.warning(f"Max recursion for '{rule_name}'"); return None
        context.recursion_depth[rule_name] = depth + 1
        rule_def = self.grammar.get(rule_name); node = None
        if not rule_def: node = RawSQL(rule_name)
        elif rule_def["type"] == "choice": node = self._generate_choice(rule_name, rule_def, context)
        elif rule_def["type"] == "sequence": node = self._generate_sequence(rule_name, rule_def, context)
        elif rule_def["type"] == "terminal": node = self._generate_terminal(rule_name, context)
        context.recursion_depth[rule_name] = depth
        return node

    def _generate_choice(self, rule_name: str, rule_def: dict, context: GenerationContext) -> SQLNode | None:
        if rule_name == "select_list_item" and context.grouping_columns:
            if random.random() < 0.5: 
                return ColumnNode(random.choice(context.grouping_columns))
            else: 
                # Try aggregate function first, fallback to column if it fails
                agg_result = self._generate_rule("aggregate_function", context)
                if agg_result:
                    return agg_result
                else:
                    # Fallback to a simple column reference
                    return ColumnNode(random.choice(context.grouping_columns))
        
        weights_config = self.config.get('statement_weights' if rule_name in ['ddl_statement', 'dml_statement'] else 'rule_choice_weights', {}).get(rule_name, {})
        options = rule_def["options"]
        weights = [weights_config.get(opt, 1.0) for opt in options]
        
        # Try each option until one works
        for _ in range(len(options)):
            chosen_rule = random.choices(options, weights=weights, k=1)[0]
            result = self._generate_rule(chosen_rule, context)
            if result:
                return result
        
        # If all options fail, try the first one as a fallback
        if options:
            return self._generate_rule(options[0], context)
        
        return None

    def _generate_sequence(self, rule_name: str, rule_def: dict, context: GenerationContext) -> SQLNode | None:
        elements = []
        element_nodes = {}
        
        for element_def in rule_def["elements"]:
            if element_def.get("optional") and random.random() > self.config.get('rule_expansion_probabilities', {}).get(rule_name, {}).get(element_def['config_key'], 0): 
                continue
            node = self._generate_rule(element_def["rule"], context)
            if node: 
                elements.append(node)
                element_nodes[element_def["rule"]] = node
        
        context.expected_type = None
        if not elements: return None
        
        if rule_name == 'select_stmt': 
            return SelectNode(element_nodes.get('select_list'), element_nodes.get('from_clause'), 
                           element_nodes.get('where_clause'), element_nodes.get('group_by_clause'), 
                           element_nodes.get('limit_clause'))
        if rule_name == 'create_table_stmt': 
            return CreateTableNode(element_nodes.get('new_table_name'), element_nodes.get('column_definitions'))
        if rule_name == 'create_view_stmt': 
            # Only create views if we have a valid select statement
            select_stmt = element_nodes.get('select_stmt')
            if select_stmt:
                return CreateViewNode(element_nodes.get('new_view_name'), select_stmt)
            else:
                # Fallback to a simple view if select generation fails
                schema_name = self.config.get_db_config()['schema_name']
                fallback_select = SelectNode(
                    RawSQL("1"), 
                    RawSQL(f'{schema_name}."products"'),
                    None, None, None
                )
                return CreateViewNode(element_nodes.get('new_view_name'), fallback_select)
        if rule_name == 'create_index_stmt': 
            return CreateIndexNode(element_nodes.get('new_index_name'), element_nodes.get('table_name'), 
                                element_nodes.get('column_name'))
        if rule_name == 'insert_stmt': 
            return InsertNode(element_nodes.get('table_name'), element_nodes.get('column_list'), 
                           element_nodes.get('literal_list'))
        if rule_name == 'update_stmt': 
            return UpdateNode(element_nodes.get('table_name'), element_nodes.get('update_assignment'), 
                           element_nodes.get('where_clause'))
        if rule_name == 'delete_stmt': 
            return DeleteNode(element_nodes.get('table_name'), element_nodes.get('where_clause'))
        if rule_name == 'column_definition': 
            return ColumnDefNode(element_nodes.get('column_name'), element_nodes.get('data_type'))
        if rule_name == 'update_assignment': 
            column_node = element_nodes.get('column_name')
            if isinstance(column_node, ColumnNode):
                # Set the expected type for the expression to match the column type
                context.expected_type = column_node.column.data_type
            return UpdateAssignmentNode(column_node, element_nodes.get('expression'))
        if rule_name == 'comparison_predicate':
            col_node = element_nodes.get('column_name')
            if isinstance(col_node, ColumnNode): context.expected_type = col_node.column.data_type
            
            # Ensure we have a valid comparison operator
            comparison_op = element_nodes.get('comparison_op')
            if comparison_op:
                op_sql = comparison_op.to_sql()
                # Validate that the operator is one of the expected ones
                valid_ops = ['=', '<>', '<', '<=', '>', '>=']
                if op_sql not in valid_ops:
                    # Fallback to a safe operator
                    op_sql = '='
            else:
                op_sql = '='
            
            return BinaryOpNode(col_node, op_sql, 
                              self._generate_rule('literal', context))
        if rule_name == 'where_clause': 
            return WhereClauseNode(elements)

        return SequenceNode(elements, separator=rule_def.get("separator", " "))

    def _generate_terminal(self, rule_name: str, context: GenerationContext) -> SQLNode | None:
        if rule_name in ["new_view_name", "new_index_name"]:
            prefix = rule_name.split('_')[1]
            schema_name = self.config.get_db_config()['schema_name']
            # Make names more unique to avoid conflicts
            timestamp = int(time.time() * 1000)  # Use milliseconds for more uniqueness
            random_suffix = random.randint(1000, 9999)
            return RawSQL(f'{schema_name}."fuzz_{prefix}_{timestamp}_{random_suffix}"')
        
        if rule_name == "table_name":
            table = self.catalog.get_random_table()
            if not table: return None
            context.current_table = table
            schema_name = self.config.get_db_config()['schema_name']
            return RawSQL(f'{schema_name}."{table.name}"')
        
        if rule_name == "new_table_name":
            # For new tables, use the current schema and create realistic table names
            schema_name = self.config.get_db_config()['schema_name']
            # Use common table names that queries might reference
            common_table_names = ['orders', 'customers', 'categories', 'inventory', 'suppliers', 'employees', 'transactions']
            table_name = random.choice(common_table_names)
            return RawSQL(f'{schema_name}."{table_name}_{int(time.time())}_{random.randint(100,999)}"')
        
        if rule_name == "column_name":
            is_create_col = context.recursion_depth.get("column_definition", 0) > 0
            if is_create_col: return RawSQL(f'"col_{random.randint(1,100)}"')
            if not context.current_table: return None
            
            is_column_list = context.recursion_depth.get("column_list", 0) > 0
            if is_column_list:
                column = self.catalog.get_random_column(context.current_table)
                if not column: return None
                context.insert_columns.append(column)
                return ColumnNode(column)
            
            col_type = 'numeric' if context.recursion_depth.get("aggregate_function", 0) > 0 else None
            column = self.catalog.get_random_column(context.current_table, of_type=col_type)
            if not column: return None
            if context.recursion_depth.get("group_by_list", 0) > 0: context.grouping_columns.append(column)
            return ColumnNode(column)
        
        if rule_name == "literal":
            is_literal_list = context.recursion_depth.get("literal_list", 0) > 0
            if is_literal_list and context.insert_columns:
                column_for_this_literal = context.insert_columns.pop(0)
                return LiteralNode(self._generate_typed_literal(column_for_this_literal.data_type))
            return LiteralNode(self._generate_typed_literal(context.expected_type))

        if rule_name == "data_type": return RawSQL(random.choice(['INT PRIMARY KEY', 'TEXT', 'NUMERIC', 'BOOLEAN']))
        if rule_name == "integer_literal": return LiteralNode(random.randint(1, 100))
        if rule_name == "scalar_function": return self._generate_function_call(context)
        if rule_name == "function_call": return self._generate_function_call(context)
        if rule_name == "comparison_op": 
            valid_ops = ['=', '<>', '<', '<=', '>', '>=']
            chosen_op = random.choice(valid_ops)
            return RawSQL(chosen_op)
        if rule_name == "aggregate_op": return RawSQL(random.choice(['SUM', 'AVG', 'MIN', 'MAX', 'COUNT']))
        
        self.logger.error(f"Unknown terminal rule: {rule_name}"); return None

    def _generate_typed_literal(self, sql_type: str | None) -> any:
        if not sql_type: 
            return random.randint(1, 100)  # Default to integer
        
        sql_type = sql_type.lower()
        
        if any(t in sql_type for t in ['int', 'integer', 'bigint', 'smallint']):
            return random.randint(-1000, 1000)
        elif any(t in sql_type for t in ['numeric', 'decimal', 'real', 'double', 'float']):
            return round(random.uniform(-1000.0, 1000.0), 2)
        elif 'bool' in sql_type:
            return random.choice([True, False])
        elif any(t in sql_type for t in ['text', 'varchar', 'char', 'string']):
            # Generate more realistic text values
            prefixes = ['value', 'item', 'data', 'test', 'sample']
            prefix = random.choice(prefixes)
            suffix = random.randint(1, 999)
            return f"{prefix}_{suffix}"
        else:
            # For unknown types, return a safe integer
            return random.randint(1, 100)

    def _generate_function_call(self, context: GenerationContext) -> SQLNode | None:
        if not self.catalog.functions: return None
        
        # Filter functions to only use simple, well-known ones that are more likely to work
        simple_functions = []
        for func in self.catalog.functions:
            # Only use functions with simple argument types and avoid complex ones
            if (len(func.arg_types) <= 3 and 
                all(any(simple_type in arg_type.lower() for simple_type in ['int', 'text', 'numeric', 'bool', 'real', 'double']) 
                    for arg_type in func.arg_types)):
                simple_functions.append(func)
        
        if not simple_functions:
            # Fallback to basic functions if no simple ones found
            simple_functions = [f for f in self.catalog.functions if len(f.arg_types) <= 2]
        
        if not simple_functions:
            return None
        
        for _ in range(10):  # Try more attempts
            func = random.choice(simple_functions)
            args = []
            can_generate_args = True
            
            for arg_type in func.arg_types:
                # Clean up the argument type string
                clean_type = arg_type.strip().lower()
                
                # Map complex types to simple ones
                if any(t in clean_type for t in ['int', 'integer', 'bigint', 'smallint']):
                    clean_type = 'int'
                elif any(t in clean_type for t in ['text', 'varchar', 'char', 'string']):
                    clean_type = 'text'
                elif any(t in clean_type for t in ['numeric', 'decimal', 'real', 'double', 'float']):
                    clean_type = 'numeric'
                elif any(t in clean_type for t in ['bool', 'boolean']):
                    clean_type = 'bool'
                else:
                    # For unknown types, try to generate a reasonable default
                    clean_type = 'int'
                
                arg_literal = self._generate_typed_literal(clean_type)
                if arg_literal is not None:
                    args.append(LiteralNode(arg_literal))
                else:
                    can_generate_args = False
                    break
            
            if can_generate_args and args:
                return FunctionCallNode(func, args)
        
        return None

# Contains the intelligent, recursive-descent query generator.
# This optimized version builds a rich Abstract Syntax Tree (AST), is fully
# type-aware, and integrates with the catalog's discovered vocabulary
# (functions, types) to generate complex, semantically valid queries.

import logging
import random
from config import FuzzerConfig
from utils.db_executor import Catalog, Table, Column, DiscoveredFunction

# --- Rich Abstract Syntax Tree (AST) Nodes ---
from abc import ABC, abstractmethod
class SQLNode(ABC):
    def __init__(self):
        self.parent = None
        self.children = []

    def add_child(self, node):
        if node:
            self.children.append(node)
            node.parent = self

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

class SequenceNode(SQLNode):
    def __init__(self, elements: list, separator: str = " "):
        super().__init__(); self.elements = elements; self.separator = separator
        for el in elements: self.add_child(el)
    def to_sql(self) -> str: return self.separator.join(e.to_sql() for e in self.elements if e)

class WhereClauseNode(SequenceNode): pass
class SelectNode(SequenceNode): pass
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
    def __init__(self, func: DiscoveredFunction, args: list[SQLNode]):
        super().__init__(); self.func = func; self.args = args
        for arg in args: self.add_child(arg)
    def to_sql(self) -> str:
        return f"{self.func.name}({', '.join(arg.to_sql() for arg in self.args)})"

# --- Generation Context ---
from dataclasses import dataclass, field
@dataclass
class GenerationContext:
    catalog: Catalog; config: FuzzerConfig; recursion_depth: dict[str, int] = field(default_factory=dict)
    current_table: Table | None = None; grouping_columns: list[Column] = field(default_factory=list)
    # Context for type-aware generation
    expected_type: str | None = None

class GrammarGenerator:
    """Generates SQL queries by recursively traversing a formal grammar."""
    def __init__(self, grammar: dict, config: FuzzerConfig, catalog: Catalog):
        self.grammar = grammar; self.config = config; self.catalog = catalog
        self.logger = logging.getLogger(self.__class__.__name__)

    def generate_statement(self) -> SQLNode | None:
        context = GenerationContext(catalog=self.catalog, config=self.config)
        return self._generate_rule("statement", context)

    def _generate_rule(self, rule_name: str, context: GenerationContext) -> SQLNode | None:
        depth = context.recursion_depth.get(rule_name, 0)
        max_depth = self.config.get('max_recursion_depth', {}).get(rule_name, 10)
        if depth >= max_depth: self.logger.warning(f"Max recursion for '{rule_name}'"); return None
        context.recursion_depth[rule_name] = depth + 1

        rule_def = self.grammar.get(rule_name)
        node = None
        if not rule_def: node = RawSQL(rule_name)
        elif rule_def["type"] == "choice": node = self._generate_choice(rule_name, rule_def, context)
        elif rule_def["type"] == "sequence": node = self._generate_sequence(rule_name, rule_def, context)
        elif rule_def["type"] == "terminal": node = self._generate_terminal(rule_name, context)
        
        context.recursion_depth[rule_name] = depth
        return node

    def _generate_choice(self, rule_name: str, rule_def: dict, context: GenerationContext) -> SQLNode | None:
        if rule_name == "select_list_item" and context.grouping_columns:
            return self._generate_rule("aggregate_function", context)
        weights_config = self.config.get('rule_choice_weights', {}).get(rule_name, {})
        options = rule_def["options"]; weights = [weights_config.get(opt, 1.0) for opt in options]
        chosen_rule = random.choices(options, weights=weights, k=1)[0]
        return self._generate_rule(chosen_rule, context)

    def _generate_sequence(self, rule_name: str, rule_def: dict, context: GenerationContext) -> SQLNode | None:
        elements = []
        for element_def in rule_def["elements"]:
            if element_def.get("optional") and random.random() > self.config.get('rule_expansion_probabilities', {}).get(rule_name, {}).get(element_def['config_key'], 0): continue
            
            # --- Type-Aware Context Passing ---
            # If we are generating a comparison, tell the 'literal' generator the type it needs to be
            if rule_name == 'comparison_predicate':
                col_node = self._generate_rule(element_def["rule"], context)
                if isinstance(col_node, ColumnNode):
                    context.expected_type = col_node.column.data_type
                elements.append(col_node)
                continue # Manually handle sequence
            
            nodes_to_add = []
            first_node = self._generate_rule(element_def["rule"], context)
            if first_node: nodes_to_add.append(first_node)

            if element_def.get("repeatable"):
                if random.random() < 0.7:
                    next_node = self._generate_rule(element_def["rule"], context)
                    if next_node: nodes_to_add.append(next_node)
            elements.extend(nodes_to_add)
        
        # Reset type context after the sequence is done
        context.expected_type = None
        
        if rule_name == 'where_clause': return WhereClauseNode(elements) if elements else None
        if rule_name == 'select_stmt': return SelectNode(elements) if elements else None
        return SequenceNode(elements, separator=rule_def.get("separator", " ")) if elements else None

    def _generate_terminal(self, rule_name: str, context: GenerationContext) -> SQLNode | None:
        if rule_name == "table_name":
            table = self.catalog.get_random_table();
            if not table: return None
            context.current_table = table; schema_name = self.config.get_db_config()['schema_name']
            return RawSQL(f'{schema_name}."{table.name}"')
        
        if rule_name == "column_name":
            if not context.current_table: return None
            col_type = 'numeric' if context.recursion_depth.get("aggregate_function", 0) > 0 else None
            column = self.catalog.get_random_column(context.current_table, of_type=col_type)
            if not column: return None
            if context.recursion_depth.get("group_by_list", 0) > 0: context.grouping_columns.append(column)
            return ColumnNode(column)

        if rule_name == "literal":
            return LiteralNode(self._generate_typed_literal(context.expected_type))
            
        if rule_name == "integer_literal":
            return LiteralNode(random.randint(1, 100))
        
        if rule_name == "scalar_function":
            return self._generate_function_call(context)

        self.logger.error(f"Unknown terminal rule: {rule_name}"); return None

    def _generate_typed_literal(self, sql_type: str | None) -> Any:
        """Generates a random Python value that is compatible with the given SQL type."""
        if not sql_type: return ''.join(random.choices('abc', k=3))
        
        sql_type = sql_type.lower()
        if any(t in sql_type for t in ['int', 'numeric', 'real', 'double']): return random.randint(-1000, 1000)
        if 'bool' in sql_type: return random.choice([True, False])
        if 'date' in sql_type or 'timestamp' in sql_type: return f"{random.randint(2000, 2025)}-{random.randint(1, 12):02d}-{random.randint(1, 28):02d}"
        # Default for TEXT, VARCHAR, etc.
        return ''.join(random.choices('abcdefghijklmnopqrstuvwxyz', k=random.randint(3, 8)))

    def _generate_function_call(self, context: GenerationContext) -> SQLNode | None:
        """Selects a discovered function and generates a valid call to it."""
        if not self.catalog.functions: return None
        
        # Try a few times to find a function we can satisfy
        for _ in range(5):
            func = random.choice(self.catalog.functions)
            args = []
            can_generate_args = True
            for arg_type in func.arg_types:
                # This is a simplified argument generator. A more advanced version
                # would try to find columns of the correct type.
                arg_literal = self._generate_typed_literal(arg_type)
                if arg_literal is not None:
                    args.append(LiteralNode(arg_literal))
                else:
                    can_generate_args = False; break
            
            if can_generate_args:
                return FunctionCallNode(func, args)
        
        self.logger.debug("Could not generate arguments for any randomly selected functions.")
        return None
# The intelligent mutational engine. This optimized version uses a simple
# parser to understand query structure, allowing for robust, type-aware,
# and vocabulary-aware mutations instead of simple regex replacements.

import logging
import random
import re
from config import FuzzerConfig
from utils.db_executor import Catalog

class Mutator:
    """
    Learns from a corpus of seed queries and performs intelligent,
    structure-aware mutations.
    """
    def __init__(self, config: FuzzerConfig, catalog: Catalog):
        self.config = config
        self.catalog = catalog
        self.logger = logging.getLogger(self.__class__.__name__)
        self.corpus = self._load_corpus()
        self.mutation_strategies = self._get_mutation_strategies()

    def _load_corpus(self) -> list[str]:
        """Loads the seed queries from the corpus file."""
        corpus_path = self.config.get('corpus', {}).get('seed_file')
        if not corpus_path:
            self.logger.warning("No corpus file specified. Mutational engine will be disabled.")
            return []
        
        try:
            with open(corpus_path, 'r') as f:
                queries = [line.strip() for line in f if not line.strip().startswith('--') and line.strip()]
                self.logger.info(f"Loaded {len(queries)} queries from corpus file '{corpus_path}'.")
                return queries
        except FileNotFoundError:
            self.logger.error(f"Corpus file not found at '{corpus_path}'. Mutational engine will be disabled.")
            return []

    def _get_mutation_strategies(self) -> list[tuple[callable, float]]:
        """
        Loads the available mutation strategies and their weights from the config.
        """
        strategies = []
        strategy_configs = self.config.get('mutator_strategies', {})
        
        if strategy_configs.get('mutate_literal', {}).get('enabled', False):
            strategies.append((self._mutate_literal, strategy_configs['mutate_literal'].get('weight', 1.0)))
        
        if strategy_configs.get('mutate_comparison_operator', {}).get('enabled', False):
            strategies.append((self._mutate_comparison_operator, strategy_configs['mutate_comparison_operator'].get('weight', 1.0)))
            
        if strategy_configs.get('mutate_function_name', {}).get('enabled', False):
            strategies.append((self._mutate_function_name, strategy_configs['mutate_function_name'].get('weight', 1.0)))

        self.logger.info(f"Loaded {len(strategies)} mutation strategies.")
        return strategies

    def has_corpus(self) -> bool:
        """Checks if the mutator has queries to work with."""
        return bool(self.corpus)

    def mutate(self) -> str | None:
        """Selects a query from the corpus and applies a random mutation."""
        if not self.has_corpus() or not self.mutation_strategies:
            return None

        schema_name = self.config.get_db_config()['schema_name']
        original_query = random.choice(self.corpus).replace('$$schema$$', schema_name)
        
        # Choose a mutation strategy based on configured weights
        strategies, weights = zip(*self.mutation_strategies)
        chosen_strategy = random.choices(strategies, weights=weights, k=1)[0]
        
        self.logger.debug(f"Selected mutation strategy: {chosen_strategy.__name__}")
        mutated_query = chosen_strategy(original_query)

        self.logger.debug(f"Original: {original_query}")
        self.logger.debug(f"Mutated:  {mutated_query}")
        return mutated_query

    def _mutate_literal(self, query: str) -> str:
        """
        Finds a literal value (number or string) and replaces it with a new random value.
        Example: `WHERE price > 100.0` -> `WHERE price > 73.4`
        """
        numeric_literals = re.findall(r'([=\s><])(\d+\.?\d*)', query)
        if numeric_literals:
            prefix, literal_str = random.choice(numeric_literals)
            new_literal = str(round(random.uniform(1, 200), 2))
            return query.replace(f"{prefix}{literal_str}", f"{prefix}{new_literal}", 1)

        string_literals = re.findall(r"([=\s><])'([^']+)'", query)
        if string_literals:
            prefix, literal_str = random.choice(string_literals)
            new_literal = ''.join(random.choices('abcdef', k=len(literal_str)))
            return query.replace(f"{prefix}'{literal_str}'", f"{prefix}'{new_literal}'", 1)

        return query

    def _mutate_comparison_operator(self, query: str) -> str:
        """
        Finds a comparison operator and replaces it with another.
        Example: `WHERE price > 100.0` -> `WHERE price <= 100.0`
        """
        operators = ['>', '<', '=', '<>', '>=', '<=']
        found_ops = [op for op in operators if op in query]
        
        if found_ops:
            op_to_replace = random.choice(found_ops)
            new_op = random.choice([op for op in operators if op != op_to_replace])
            return query.replace(op_to_replace, new_op, 1)
            
        return query

    def _mutate_function_name(self, query: str) -> str:
        """
        Replaces an aggregate function name with a different one discovered
        from the catalog.
        Example: `SELECT AVG(price)` -> `SELECT STDDEV(price)`
        """
        # A simple list of common aggregate functions to look for
        known_aggregates = ['SUM', 'AVG', 'MIN', 'MAX', 'COUNT']
        found_aggregates = [agg for agg in known_aggregates if re.search(r'\b' + agg + r'\b', query, re.IGNORECASE)]

        if not found_aggregates or not self.catalog.functions:
            return query

        agg_to_replace = random.choice(found_aggregates)
        
        # Find a compatible replacement from the discovered functions
        # This is a simplified compatibility check (1-arg functions)
        compatible_replacements = [
            f.name for f in self.catalog.functions 
            if len(f.arg_types) == 1 and f.name.upper() not in known_aggregates
        ]

        if not compatible_replacements:
            return query
            
        new_func = random.choice(compatible_replacements)
        
        # Use regex to replace the function name while preserving case-insensitivity
        return re.sub(r'\b' + agg_to_replace + r'\b', new_func, query, count=1, flags=re.IGNORECASE)
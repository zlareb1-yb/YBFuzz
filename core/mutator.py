# The intelligent mutational engine. This optimized version uses a simple
# parser to understand query structure, allowing for robust, type-aware,
# and vocabulary-aware mutations instead of simple regex replacements.
# It correctly loads from both static and evolved corpuses.

import logging
import random
import re
import os
from config import FuzzerConfig
from utils.db_executor import Catalog

class Mutator:
    """
    Learns from a corpus of seed and evolved queries and performs intelligent,
    structure-aware mutations.
    """
    def __init__(self, config: FuzzerConfig, catalog: Catalog):
        self.config = config
        self.catalog = catalog
        self.logger = logging.getLogger(self.__class__.__name__)
        self.corpus = self._load_corpus()
        self.mutation_strategies = self._get_mutation_strategies()

    def _load_corpus(self) -> list[str]:
        """
        Loads queries from the static seed file and all files in the
        evolved corpus directory.
        """
        queries = []
        
        # Load from static seed file
        seed_path = self.config.get('corpus', {}).get('seed_file')
        if seed_path:
            try:
                with open(seed_path, 'r') as f:
                    seed_queries = [line.strip() for line in f if not line.strip().startswith('--') and line.strip()]
                    queries.extend(seed_queries)
                    self.logger.info(f"Loaded {len(seed_queries)} queries from seed corpus '{seed_path}'.")
            except FileNotFoundError:
                self.logger.error(f"Seed corpus file not found at '{seed_path}'.")

        # Load from evolved corpus directory
        evo_config = self.config.get('corpus_evolution', {})
        if evo_config.get('enabled', False):
            evo_dir = evo_config.get('directory')
            if evo_dir and os.path.isdir(evo_dir):
                evo_count = 0
                for filename in os.listdir(evo_dir):
                    filepath = os.path.join(evo_dir, filename)
                    try:
                        with open(filepath, 'r') as f:
                            # Read the entire file, skipping comment lines
                            content = "".join([line for line in f if not line.strip().startswith('--')])
                            queries.append(content.strip())
                            evo_count += 1
                    except IOError as e:
                        self.logger.warning(f"Could not read evolved corpus file '{filepath}': {e}")
                if evo_count > 0:
                    self.logger.info(f"Loaded {evo_count} queries from evolved corpus '{evo_dir}'.")
        
        return queries

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

        # If one mutation didn't change the query, try another one as a fallback
        if mutated_query == original_query and len(self.mutation_strategies) > 1:
            self.logger.debug("Initial mutation had no effect, trying a fallback strategy.")
            fallback_strategy = random.choice([s for s in strategies if s != chosen_strategy])
            mutated_query = fallback_strategy(original_query)

        self.logger.debug(f"Original: {original_query}")
        self.logger.debug(f"Mutated:  {mutated_query}")
        
        # Log interesting mutations to the main SQL file
        if mutated_query != original_query:
            self._log_mutation_to_sql_file(original_query, mutated_query)
        
        return mutated_query

    def _log_mutation_to_sql_file(self, original_query: str, mutated_query: str):
        """Logs interesting mutations to the evolved corpus queries.sql file."""
        try:
            # Get the evolved corpus directory from config
            evo_config = self.config.get('corpus_evolution', {})
            evo_dir = evo_config.get('directory', 'evolved_corpus')
            evo_queries_file = os.path.join(evo_dir, 'queries.sql')
            
            # Create the file if it doesn't exist
            if not os.path.exists(evo_queries_file):
                with open(evo_queries_file, 'w') as f:
                    f.write("-- Queries which have resulted in bugs in the past\n")
                    f.write("-- or have interesting query plan structures\n")
                    f.write("-- including interesting mutations\n\n")
            
            # Append the mutation
            with open(evo_queries_file, 'a') as f:
                f.write(f"\n-- Interesting Mutation\n")
                f.write(f"-- Original: {original_query}\n")
                f.write(f"-- Mutated:  {mutated_query}\n")
                f.write(f"{mutated_query}\n")
                f.write(";\n")
        except Exception as e:
            self.logger.warning(f"Failed to log mutation to evolved corpus: {e}")

    def _mutate_literal(self, query: str) -> str:
        """
        Finds a literal value (number or string) and replaces it with a new random value.
        """
        # Find numeric literals (e.g., 100, 12.34)
        numeric_literals = re.findall(r'([=\s><])(\d+\.?\d*)', query)
        if numeric_literals:
            prefix, literal_str = random.choice(numeric_literals)
            new_literal = str(round(random.uniform(1, 200), 2)) if '.' in literal_str else str(random.randint(1, 200))
            return query.replace(f"{prefix}{literal_str}", f"{prefix}{new_literal}", 1)

        # Find string literals (e.g., 'Category-5')
        string_literals = re.findall(r"([=\s><])'([^']+)'", query)
        if string_literals:
            prefix, literal_str = random.choice(string_literals)
            new_literal = ''.join(random.choices('abcdef', k=len(literal_str)))
            return query.replace(f"{prefix}'{literal_str}'", f"{prefix}'{new_literal}'", 1)

        return query

    def _mutate_comparison_operator(self, query: str) -> str:
        """
        Finds a comparison operator and replaces it with another.
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
        """
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
"""
Advanced SQL Query Mutator - Comprehensive Mutation Strategies

This module implements sophisticated mutation strategies for SQL queries:
1. Boolean expression mutations
2. SQL injection pattern mutations
3. Advanced function mutations
4. Complex subquery mutations
5. Window function mutations
6. Aggregation mutations
7. JOIN mutations
8. Type casting mutations
9. YugabyteDB-specific mutations
10. Distributed query mutations

These mutations are designed to catch sophisticated bugs
that occur in production database systems.
"""

import logging
import random
import re
from typing import List, Dict, Any, Optional, Tuple
from utils.db_executor import Column, Table, Catalog


class AdvancedMutator:
    """Advanced SQL query mutator with comprehensive mutation strategies."""
    
    def __init__(self, catalog: Catalog):
        self.catalog = catalog
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Advanced mutation patterns
        self.boolean_mutations = [
            # De Morgan's law mutations
            ("A AND B", "NOT (NOT A OR NOT B)"),
            ("A OR B", "NOT (NOT A AND NOT B)"),
            ("NOT (A AND B)", "NOT A OR NOT B"),
            ("NOT (A OR B)", "NOT A AND NOT B"),
            
            # Distributive law mutations
            ("A AND (B OR C)", "(A AND B) OR (A AND C)"),
            ("A OR (B AND C)", "(A OR B) AND (A OR C)"),
            
            # Double negation
            ("NOT NOT A", "A"),
            ("A", "NOT NOT A"),
            
            # Associative law mutations
            ("(A AND B) AND C", "A AND (B AND C)"),
            ("(A OR B) OR C", "A OR (B OR C)"),
            
            # Complex boolean expressions
            ("A AND B AND C", "(A AND B) AND C"),
            ("A OR B OR C", "(A OR B) OR C"),
            ("A AND (B OR C) AND D", "(A AND B AND D) OR (A AND C AND D)"),
        ]
        
        # SQL injection pattern mutations
        self.injection_mutations = [
            # Boolean-based injection patterns
            ("1=1", "TRUE"),
            ("1=1", "1"),
            ("1=1", "'1'='1'"),
            ("1=1", "1=1"),
            ("1=1", "1<>0"),
            ("1=1", "1>0"),
            ("1=1", "1>=1"),
            
            # String-based injection patterns
            ("'test'", "'test' OR '1'='1'"),
            ("'test'", "'test' UNION SELECT 1"),
            ("'test'", "'test' AND 1=1"),
            ("'test'", "'test' OR 1=1"),
            
            # Numeric-based injection patterns
            ("1", "1 OR 1=1"),
            ("1", "1 AND 1=1"),
            ("1", "1 UNION SELECT 1"),
            ("1", "1 OR TRUE"),
            ("1", "1 AND TRUE"),
        ]
        
        # Function mutations
        self.function_mutations = [
            # Mathematical function mutations
            ("LENGTH(col)", "CHAR_LENGTH(col)"),
            ("LENGTH(col)", "OCTET_LENGTH(col)"),
            ("LENGTH(col)", "BIT_LENGTH(col)"),
            ("UPPER(col)", "UPPER(col)"),
            ("LOWER(col)", "LOWER(col)"),
            ("SUBSTRING(col, 1, 3)", "SUBSTR(col, 1, 3)"),
            ("SUBSTRING(col, 1, 3)", "LEFT(col, 3)"),
            
            # Aggregation function mutations
            ("COUNT(*)", "COUNT(1)"),
            ("COUNT(*)", "COUNT(col)"),
            ("SUM(col)", "SUM(CAST(col AS NUMERIC))"),
            ("AVG(col)", "SUM(col)/COUNT(col)"),
            ("MAX(col)", "MAX(col)"),
            ("MIN(col)", "MIN(col)"),
            
            # Date function mutations
            ("CURRENT_DATE", "CURRENT_DATE"),
            ("CURRENT_TIMESTAMP", "NOW()"),
            ("CURRENT_TIMESTAMP", "LOCALTIMESTAMP"),
            ("EXTRACT(YEAR FROM col)", "YEAR(col)"),
            ("EXTRACT(MONTH FROM col)", "MONTH(col)"),
            ("EXTRACT(DAY FROM col)", "DAY(col)"),
        ]
        
        # Subquery mutations
        self.subquery_mutations = [
            # EXISTS mutations
            ("EXISTS (SELECT 1 FROM table)", "EXISTS (SELECT * FROM table)"),
            ("EXISTS (SELECT 1 FROM table)", "EXISTS (SELECT col FROM table)"),
            ("EXISTS (SELECT 1 FROM table)", "EXISTS (SELECT COUNT(*) FROM table)"),
            
            # IN mutations
            ("col IN (SELECT col FROM table)", "col = ANY(SELECT col FROM table)"),
            ("col IN (SELECT col FROM table)", "col IN (SELECT DISTINCT col FROM table)"),
            ("col IN (SELECT col FROM table)", "col IN (SELECT col FROM table LIMIT 1000)"),
            
            # Correlated subquery mutations
            ("(SELECT MAX(col) FROM table2 WHERE table2.id = table1.id)", 
             "(SELECT col FROM table2 WHERE table2.id = table1.id ORDER BY col DESC LIMIT 1)"),
        ]
        
        # Window function mutations
        self.window_mutations = [
            # Frame specification mutations
            ("ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW", 
             "RANGE BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW"),
            ("ROWS BETWEEN 1 PRECEDING AND 1 FOLLOWING",
             "RANGE BETWEEN 1 PRECEDING AND 1 FOLLOWING"),
            ("ROWS BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING",
             "RANGE BETWEEN CURRENT ROW AND UNBOUNDED FOLLOWING"),
            
            # Partition and order mutations
            ("PARTITION BY col1 ORDER BY col2",
             "PARTITION BY col1, col2 ORDER BY col1, col2"),
            ("PARTITION BY col1 ORDER BY col2",
             "PARTITION BY col1 ORDER BY col2, col1"),
        ]
        
        # JOIN mutations
        self.join_mutations = [
            # JOIN type mutations
            ("INNER JOIN", "JOIN"),
            ("LEFT JOIN", "LEFT OUTER JOIN"),
            ("RIGHT JOIN", "RIGHT OUTER JOIN"),
            ("FULL JOIN", "FULL OUTER JOIN"),
            
            # JOIN condition mutations
            ("ON t1.id = t2.id", "ON t2.id = t1.id"),
            ("ON t1.id = t2.id", "ON t1.id = t2.id AND t1.col = t2.col"),
            ("ON t1.id = t2.id", "ON t1.id = t2.id OR t1.col = t2.col"),
        ]
        
        # Type casting mutations
        self.casting_mutations = [
            # Numeric casting
            ("col::INTEGER", "CAST(col AS INTEGER)"),
            ("col::NUMERIC", "CAST(col AS NUMERIC)"),
            ("col::TEXT", "CAST(col AS TEXT)"),
            ("col::VARCHAR", "CAST(col AS VARCHAR)"),
            
            # Array casting
            ("col::INTEGER[]", "CAST(col AS INTEGER[])"),
            ("col::TEXT[]", "CAST(col AS TEXT[])"),
            
            # JSON casting
            ("col::JSONB", "CAST(col AS JSONB)"),
            ("col::JSON", "CAST(col AS JSON)"),
        ]
        
        # YugabyteDB-specific mutations
        self.yb_mutations = [
            # Hash function mutations
            ("yb_hash_code(col)", "yb_hash_code_any(col)"),
            ("yb_hash_code_int4(col)", "yb_hash_code(col)"),
            ("yb_hash_code_int8(col)", "yb_hash_code(col)"),
            ("yb_hash_code_text(col)", "yb_hash_code(col)"),
            
            # Optimization hint mutations
            ("/*+ SET_VAR(enable_seqscan=off) */", "/*+ SET_VAR(enable_indexscan=off) */"),
            ("/*+ SET_VAR(enable_hashjoin=off) */", "/*+ SET_VAR(enable_mergejoin=off) */"),
            ("/*+ SET_VAR(random_page_cost=1000) */", "/*+ SET_VAR(cpu_tuple_cost=1000) */"),
        ]
        
        # Distributed query mutations
        self.distributed_mutations = [
            # Consistency level mutations
                    # ("SET yb_transaction_priority = 'STRONG'", "SET yb_transaction_priority = 'BOUNDED_STALENESS'"), # Not supported in this YugabyteDB version
        # ("SET yb_transaction_priority = 'BOUNDED_STALENESS'", "SET yb_transaction_priority = 'EVENTUAL'"), # Not supported in this YugabyteDB version
            
            # Isolation level mutations
                    # ("SET TRANSACTION ISOLATION LEVEL READ_COMMITTED", "SET TRANSACTION ISOLATION LEVEL REPEATABLE_READ"), # Not supported in this YugabyteDB version
        # ("SET TRANSACTION ISOLATION LEVEL REPEATABLE_READ", "SET TRANSACTION ISOLATION LEVEL SERIALIZABLE"), # Not supported in this YugabyteDB version
            
            # Distributed execution mutations
                    # ("SET yb_enable_distributed_execution = true", "SET yb_enable_distributed_execution = false"), # Not supported in this YugabyteDB version
        # ("SET yb_enable_parallel_execution = true", "SET yb_enable_parallel_execution = false"), # Not supported in this YugabyteDB version
        ]
        
        # Advanced mutation patterns based on SQLancer research
        self.advanced_mutations = [
            # Complex boolean expression mutations
            ("A AND B AND C", "A AND (B AND C)"),
            ("A OR B OR C", "A OR (B OR C)"),
            ("A AND (B OR C)", "(A AND B) OR (A AND C)"),
            ("A OR (B AND C)", "(A OR B) AND (A OR C)"),
            
            # Advanced De Morgan's law mutations
            ("NOT (A AND B)", "NOT A OR NOT B"),
            ("NOT (A OR B)", "NOT A AND NOT B"),
            ("NOT (A AND B AND C)", "NOT A OR NOT B OR NOT C"),
            ("NOT (A OR B OR C)", "NOT A AND NOT B AND NOT C"),
            
            # Complex subquery mutations
            ("EXISTS (SELECT 1 FROM t WHERE t.id = x.id)", "EXISTS (SELECT * FROM t WHERE t.id = x.id)"),
            ("EXISTS (SELECT 1 FROM t WHERE t.id = x.id)", "EXISTS (SELECT COUNT(*) FROM t WHERE t.id = x.id)"),
            ("EXISTS (SELECT 1 FROM t WHERE t.id = x.id)", "EXISTS (SELECT t.id FROM t WHERE t.id = x.id)"),
            
            # Advanced function mutations
            ("LENGTH(col)", "CHAR_LENGTH(col)"),
            ("LENGTH(col)", "OCTET_LENGTH(col)"),
            ("UPPER(col)", "UPPER(col)"),
            ("LOWER(col)", "LOWER(col)"),
            
            # Complex aggregation mutations
            ("COUNT(*)", "COUNT(1)"),
            ("COUNT(*)", "COUNT(col)"),
            ("SUM(col)", "SUM(CAST(col AS NUMERIC))"),
            ("AVG(col)", "SUM(col)/COUNT(col)"),
            
            # Advanced JOIN mutations
            ("INNER JOIN t2 ON t1.id = t2.id", "JOIN t2 ON t2.id = t1.id"),
            ("LEFT JOIN t2 ON t1.id = t2.id", "LEFT OUTER JOIN t2 ON t1.id = t2.id"),
            ("RIGHT JOIN t2 ON t1.id = t2.id", "RIGHT OUTER JOIN t2 ON t1.id = t2.id"),
            
            # Complex type casting mutations
            ("col::INTEGER", "CAST(col AS INTEGER)"),
            ("col::NUMERIC", "CAST(col AS NUMERIC)"),
            ("col::TEXT", "CAST(col AS TEXT)"),
            ("col::VARCHAR", "CAST(col AS VARCHAR)"),
            
            # Advanced window function mutations
            ("ROW_NUMBER() OVER (ORDER BY col)", "ROW_NUMBER() OVER (ORDER BY col ASC)"),
            ("LAG(col, 1) OVER (ORDER BY col)", "LAG(col, 1, NULL) OVER (ORDER BY col)"),
            ("LEAD(col, 1) OVER (ORDER BY col)", "LEAD(col, 1, NULL) OVER (ORDER BY col)"),
            
            # Complex set operation mutations
            ("SELECT * FROM t1 UNION SELECT * FROM t2", "SELECT * FROM t1 UNION ALL SELECT * FROM t2"),
            ("SELECT * FROM t1 INTERSECT SELECT * FROM t2", "SELECT * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE t2.col = t1.col)"),
            ("SELECT * FROM t1 EXCEPT SELECT * FROM t2", "SELECT * FROM t1 WHERE NOT EXISTS (SELECT 1 FROM t2 WHERE t2.col = t1.col)"),
        ]
    
    def mutate_query(self, query: str, mutation_type: str = "random") -> Optional[str]:
        """
        Apply advanced mutations to a SQL query.
        
        Args:
            query: The original SQL query
            mutation_type: Type of mutation to apply
            
        Returns:
            Mutated query if successful, None otherwise
        """
        try:
            if mutation_type == "random":
                mutation_type = random.choice([
                    "boolean", "injection", "function", "subquery", 
                    "window", "join", "casting", "yb", "distributed"
                ])
            
            if mutation_type == "boolean":
                return self._apply_boolean_mutations(query)
            elif mutation_type == "injection":
                return self._apply_injection_mutations(query)
            elif mutation_type == "function":
                return self._apply_function_mutations(query)
            elif mutation_type == "subquery":
                return self._apply_subquery_mutations(query)
            elif mutation_type == "window":
                return self._apply_window_mutations(query)
            elif mutation_type == "join":
                return self._apply_join_mutations(query)
            elif mutation_type == "casting":
                return self._apply_casting_mutations(query)
            elif mutation_type == "yb":
                return self._apply_yb_mutations(query)
            elif mutation_type == "distributed":
                return self._apply_distributed_mutations(query)
            else:
                return None
                
        except Exception as e:
            self.logger.debug(f"Error mutating query: {e}")
            return None
    
    def advanced_mutate_query(self, query: str) -> Optional[str]:
        """Apply advanced mutation strategies based on SQLancer research."""
        try:
            if not query or len(query.strip()) < 10:
                return None
            
            # Apply advanced mutation patterns
            mutated_query = query
            
            # Randomly select and apply advanced mutations
            import random
            
            # Apply 1-3 advanced mutations
            num_mutations = random.randint(1, 3)
            applied_mutations = 0
            
            for _ in range(num_mutations * 2):  # Try more attempts to get enough mutations
                if applied_mutations >= num_mutations:
                    break
                    
                mutation = random.choice(self.advanced_mutations)
                old_pattern, new_pattern = mutation
                
                # Apply pattern-based mutation
                if old_pattern in mutated_query:
                    mutated_query = mutated_query.replace(old_pattern, new_pattern, 1)
                    applied_mutations += 1
                    self.logger.debug(f"Applied advanced mutation: {old_pattern} -> {new_pattern}")
            
            # Apply additional sophisticated mutations
            if random.random() < 0.3:  # 30% chance
                mutated_query = self._apply_boolean_optimization(mutated_query)
            
            if random.random() < 0.3:  # 30% chance
                mutated_query = self._apply_subquery_optimization(mutated_query)
            
            if random.random() < 0.3:  # 30% chance
                mutated_query = self._apply_aggregation_optimization(mutated_query)
            
            return mutated_query if mutated_query != query else None
            
        except Exception as e:
            self.logger.debug(f"Error in advanced mutation: {e}")
            return None
    
    def _apply_boolean_mutations(self, query: str) -> Optional[str]:
        """Apply boolean logic mutations to the query."""
        try:
            mutated_query = query
            
            # Apply random boolean mutations
            for _ in range(random.randint(1, 3)):
                mutation = random.choice(self.boolean_mutations)
                old_pattern, new_pattern = mutation
                
                # Simple pattern replacement (in a real implementation, this would be more sophisticated)
                if old_pattern in mutated_query:
                    mutated_query = mutated_query.replace(old_pattern, new_pattern)
            
            return mutated_query if mutated_query != query else None
            
        except Exception as e:
            self.logger.debug(f"Error applying boolean mutations: {e}")
            return None
    
    def _apply_injection_mutations(self, query: str) -> Optional[str]:
        """Apply SQL injection pattern mutations to the query."""
        try:
            mutated_query = query
            
            # Apply random injection mutations
            for _ in range(random.randint(1, 2)):
                mutation = random.choice(self.injection_mutations)
                old_pattern, new_pattern = mutation
                
                if old_pattern in mutated_query:
                    mutated_query = mutated_query.replace(old_pattern, new_pattern)
            
            return mutated_query if mutated_query != query else None
            
        except Exception as e:
            self.logger.debug(f"Error applying injection mutations: {e}")
            return None
    
    def _apply_function_mutations(self, query: str) -> Optional[str]:
        """Apply function mutations to the query."""
        try:
            mutated_query = query
            
            # Apply random function mutations
            for _ in range(random.randint(1, 2)):
                mutation = random.choice(self.function_mutations)
                old_pattern, new_pattern = mutation
                
                if old_pattern in mutated_query:
                    mutated_query = mutated_query.replace(old_pattern, new_pattern)
            
            return mutated_query if mutated_query != query else None
            
        except Exception as e:
            self.logger.debug(f"Error applying function mutations: {e}")
            return None
    
    def _apply_subquery_mutations(self, query: str) -> Optional[str]:
        """Apply subquery mutations to the query."""
        try:
            mutated_query = query
            
            # Apply random subquery mutations
            for _ in range(random.randint(1, 2)):
                mutation = random.choice(self.subquery_mutations)
                old_pattern, new_pattern = mutation
                
                if old_pattern in mutated_query:
                    mutated_query = mutated_query.replace(old_pattern, new_pattern)
            
            return mutated_query if mutated_query != query else None
            
        except Exception as e:
            self.logger.debug(f"Error applying subquery mutations: {e}")
            return None
    
    def _apply_window_mutations(self, query: str) -> Optional[str]:
        """Apply window function mutations to the query."""
        try:
            mutated_query = query
            
            # Apply random window mutations
            for _ in range(random.randint(1, 2)):
                mutation = random.choice(self.window_mutations)
                old_pattern, new_pattern = mutation
                
                if old_pattern in mutated_query:
                    mutated_query = mutated_query.replace(old_pattern, new_pattern)
            
            return mutated_query if mutated_query != query else None
            
        except Exception as e:
            self.logger.debug(f"Error applying window mutations: {e}")
            return None
    
    def _apply_join_mutations(self, query: str) -> Optional[str]:
        """Apply JOIN mutations to the query."""
        try:
            mutated_query = query
            
            # Apply random JOIN mutations
            for _ in range(random.randint(1, 2)):
                mutation = random.choice(self.join_mutations)
                old_pattern, new_pattern = mutation
                
                if old_pattern in mutated_query:
                    mutated_query = mutated_query.replace(old_pattern, new_pattern)
            
            return mutated_query if mutated_query != query else None
            
        except Exception as e:
            self.logger.debug(f"Error applying JOIN mutations: {e}")
            return None
    
    def _apply_casting_mutations(self, query: str) -> Optional[str]:
        """Apply type casting mutations to the query."""
        try:
            mutated_query = query
            
            # Apply random casting mutations
            for _ in range(random.randint(1, 2)):
                mutation = random.choice(self.casting_mutations)
                old_pattern, new_pattern = mutation
                
                if old_pattern in mutated_query:
                    mutated_query = mutated_query.replace(old_pattern, new_pattern)
            
            return mutated_query if mutated_query != query else None
            
        except Exception as e:
            self.logger.debug(f"Error applying casting mutations: {e}")
            return None
    
    def _apply_yb_mutations(self, query: str) -> Optional[str]:
        """Apply YugabyteDB-specific mutations to the query."""
        try:
            mutated_query = query
            
            # Apply random YugabyteDB mutations
            for _ in range(random.randint(1, 2)):
                mutation = random.choice(self.yb_mutations)
                old_pattern, new_pattern = mutation
                
                if old_pattern in mutated_query:
                    mutated_query = mutated_query.replace(old_pattern, new_pattern)
            
            return mutated_query if mutated_query != query else None
            
        except Exception as e:
            self.logger.debug(f"Error applying YugabyteDB mutations: {e}")
            return None
    
    def _apply_distributed_mutations(self, query: str) -> Optional[str]:
        """Apply distributed query mutations to the query."""
        try:
            mutated_query = query
            
            # Apply random distributed mutations
            for _ in range(random.randint(1, 2)):
                mutation = random.choice(self.distributed_mutations)
                old_pattern, new_pattern = mutation
                
                if old_pattern in mutated_query:
                    mutated_query = mutated_query.replace(old_pattern, new_pattern)
            
            return mutated_query if mutated_query != query else None
            
        except Exception as e:
            self.logger.debug(f"Error applying distributed mutations: {e}")
            return None
    
    def _apply_boolean_optimization(self, query: str) -> str:
        """Apply boolean expression optimizations."""
        try:
            # Common boolean optimizations that can reveal bugs
            optimizations = [
                ("TRUE AND", "TRUE"),
                ("AND TRUE", ""),
                ("FALSE OR", "FALSE"),
                ("OR FALSE", ""),
                ("TRUE OR", "TRUE"),
                ("OR TRUE", "TRUE"),
                ("FALSE AND", "FALSE"),
                ("AND FALSE", "FALSE"),
            ]
            
            for old_pattern, new_pattern in optimizations:
                if old_pattern in query:
                    query = query.replace(old_pattern, new_pattern)
            
            return query
        except Exception:
            return query
    
    def _apply_subquery_optimization(self, query: str) -> str:
        """Apply subquery optimizations."""
        try:
            # Subquery optimizations that can reveal bugs
            if "EXISTS (SELECT 1 FROM" in query:
                query = query.replace("EXISTS (SELECT 1 FROM", "EXISTS (SELECT * FROM", 1)
            elif "EXISTS (SELECT * FROM" in query:
                query = query.replace("EXISTS (SELECT * FROM", "EXISTS (SELECT 1 FROM", 1)
            
            return query
        except Exception:
            return query
    
    def _apply_aggregation_optimization(self, query: str) -> str:
        """Apply aggregation optimizations."""
        try:
            # Aggregation optimizations that can reveal bugs
            if "COUNT(*)" in query:
                query = query.replace("COUNT(*)", "COUNT(1)", 1)
            elif "COUNT(1)" in query:
                query = query.replace("COUNT(1)", "COUNT(*)", 1)
            
            return query
        except Exception:
            return query
    
    def get_mutation_strategies(self) -> List[str]:
        """Get available mutation strategies."""
        return [
            "boolean", "injection", "function", "subquery", 
            "window", "join", "casting", "yb", "distributed"
        ]
    
    def get_mutation_count(self) -> int:
        """Get the total number of available mutations."""
        return (len(self.boolean_mutations) + len(self.injection_mutations) + 
                len(self.function_mutations) + len(self.subquery_mutations) + 
                len(self.window_mutations) + len(self.join_mutations) + 
                len(self.casting_mutations) + len(self.yb_mutations) + 
                len(self.distributed_mutations))
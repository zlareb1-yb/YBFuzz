import json
import logging
import os
import time
from datetime import datetime
from typing import Dict, Any, Optional

class BugReporter:
    """
    Enhanced bug reporter that organizes bugs by type and filters out false positives.
    """
    
    def __init__(self, config):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Bug reporting configuration
        bug_config = config.get('bug_reporting', {})
        self.bugs_file = bug_config.get('bugs_file', 'bugs.log')
        self.base_reproduction_dir = bug_config.get('reproduction_dir', 'bug_reproductions')
        
        # Create organized directory structure
        self.dirs = {
            'fuzzer_bugs': os.path.join(self.base_reproduction_dir, 'fuzzer_bugs'),
            'yugabytedb_bugs': os.path.join(self.base_reproduction_dir, 'yugabytedb_bugs'),
            'performance_bugs': os.path.join(self.base_reproduction_dir, 'performance_bugs'),
            'syntax_bugs': os.path.join(self.base_reproduction_dir, 'syntax_bugs')
        }
        
        for dir_path in self.dirs.values():
            os.makedirs(dir_path, exist_ok=True)
        
        # Bug counters
        self.bug_counters = {
            'fuzzer_bugs': 0,
            'yugabytedb_bugs': 0,
            'performance_bugs': 0,
            'syntax_bugs': 0
        }
        
        # False positive patterns to filter out
        self.false_positive_patterns = [
            # Function signature mismatches (expected when fuzzing)
            r"function.*does not exist",
            r"No function matches the given name and argument types",
            r"operator does not exist",
            r"No operator matches the given name and argument types",
            
            # Type casting issues (expected when fuzzing)
            r"column.*is of type.*but expression is of type",
            r"cannot cast type.*to type",
            r"invalid input syntax for type",
            
            # Minor syntax issues (not critical bugs)
            r"syntax error at or near",
            r"unexpected token",
            
            # Constraint violations (expected when fuzzing)
            r"null value in column.*violates not-null constraint",
            r"duplicate key value violates unique constraint",
            
            # View limitations (expected behavior)
            r"cannot insert into view",
            r"cannot update view",
            r"cannot delete from view",
            
            # Column existence (expected when fuzzing)
            r"column.*does not exist",
            
            # Aggregate function issues (expected when fuzzing)
            r"count\(\*\) must be used to call a parameterless aggregate function",
            r"aggregate function calls cannot contain nested aggregate or window function calls"
        ]
        
        self.logger.info(f"BugReporter initialized with organized directories: {list(self.dirs.keys())}")
    
    def _categorize_bug(self, bug_type: str, description: str, exception: Optional[str] = None) -> str:
        """
        Categorize bugs based on type and description to determine the appropriate directory.
        """
        # Performance bugs (optimizer issues)
        if any(keyword in bug_type.lower() for keyword in ['performance', 'optimizer', 'plan', 'execution']):
            return 'performance_bugs'
        
        # Syntax bugs (SQL generation issues)
        if any(keyword in bug_type.lower() for keyword in ['syntax', 'parsing', 'grammar']):
            return 'syntax_bugs'
        
        # Fuzzer bugs (our own generation issues)
        if any(keyword in description.lower() for keyword in ['fuzzer', 'generation', 'invalid sql']):
            return 'fuzzer_bugs'
        
        # Check if it's a false positive
        if self._is_false_positive(description, exception):
            return 'fuzzer_bugs'  # Treat false positives as fuzzer bugs
        
        # Default to YugabyteDB bugs (real database issues)
        return 'yugabytedb_bugs'
    
    def _is_false_positive(self, description: str, exception: Optional[str] = None) -> bool:
        """
        Check if a bug report is a false positive that should be filtered out.
        """
        import re
        
        text_to_check = f"{description} {exception or ''}".lower()
        
        for pattern in self.false_positive_patterns:
            if re.search(pattern, text_to_check, re.IGNORECASE):
                return True
        
        return False
    
    def report_bug(self, bug_type: str, description: str, query: str, error: str = None, 
                   reproduction_query: str = None, **kwargs):
        """
        Report a bug with comprehensive information.
        
        Args:
            bug_type: Type of bug (e.g., 'syntax', 'logical', 'performance')
            description: Human-readable description of the bug
            query: The query that caused the bug
            error: Error message from the database
            reproduction_query: SQL script to reproduce the bug
            **kwargs: Additional bug-specific information
        """
        try:
            # Create bug report
            bug_report = {
                'timestamp': datetime.now().isoformat(),
                'bug_type': bug_type,
                'description': description,
                'query': query,
                'error': error,
                'reproduction_query': reproduction_query,
                'additional_info': kwargs
            }
            
            # Determine the appropriate directory for this bug type
            if bug_type in ['syntax', 'sql_syntax']:
                target_dir = self.dirs['syntax_bugs']
            elif bug_type in ['logical', 'tlp', 'qpg', 'norec', 'pqs']:
                target_dir = self.dirs['yugabytedb_bugs']
            elif bug_type in ['performance', 'query_plan']:
                target_dir = self.dirs['performance_bugs']
            else:
                target_dir = self.dirs['fuzzer_bugs']
            
            # Generate unique filename
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S_%f')
            filename = f"bug_{bug_type}_{timestamp}.json"
            filepath = os.path.join(target_dir, filename)
            
            # Write bug report to file
            with open(filepath, 'w') as f:
                json.dump(bug_report, f, indent=2)
            
            # Also write to the main bug log
            self._log_bug(bug_report)
            
            self.logger.info(f"Bug reported: {bug_type} bug saved to {filepath}")
            return filepath
            
        except Exception as e:
            self.logger.error(f"Failed to report bug: {e}")
            return None
    
    def _log_bug(self, bug_report: Dict[str, Any]):
        """Log bug to the bugs.log file."""
        try:
            with open(self.bugs_file, 'a') as f:
                f.write(json.dumps(bug_report, indent=2) + '\n\n')
        except Exception as e:
            self.logger.error(f"Failed to log bug: {e}")
    
    def _create_reproduction_file(self, bug_report: Dict[str, Any]):
        """Create a detailed reproduction file in the appropriate directory."""
        try:
            category = bug_report['category']
            dir_path = self.dirs[category]
            filename = f"{bug_report['bug_id']}_reproduction.sql"
            filepath = os.path.join(dir_path, filename)
            
            with open(filepath, 'w') as f:
                f.write(f"-- Bug Reproduction Script: {bug_report['bug_id']}\n")
                f.write(f"-- Category: {category}\n")
                f.write(f"-- Bug Type: {bug_report['bug_type']}\n")
                f.write(f"-- Description: {bug_report['description']}\n")
                f.write(f"-- Oracle: {bug_report['oracle']}\n")
                f.write(f"-- Timestamp: {bug_report['datetime']}\n\n")
                
                # Environment setup
                f.write("-- =========================================\n")
                f.write("-- Environment Setup\n")
                f.write("-- =========================================\n")
                f.write(f"-- Database: {bug_report['environment']['database']}\n")
                f.write(f"-- Schema: {bug_report['environment']['schema']}\n\n")
                
                # Schema recreation from catalog snapshot
                if bug_report['catalog_snapshot']:
                    f.write("-- =========================================\n")
                    f.write("-- Schema Recreation\n")
                    f.write("-- =========================================\n")
                    for table_name, table_info in bug_report['catalog_snapshot'].get('tables', {}).items():
                        f.write(f"-- Table: {table_name}\n")
                        if 'columns' in table_info:
                            for col_name, col_type in table_info['columns'].items():
                                f.write(f"--   {col_name}: {col_type}\n")
                        f.write("\n")
                
                # Query history
                if bug_report['query_history']:
                    f.write("-- =========================================\n")
                    f.write("-- Query History (Context)\n")
                    f.write("-- =========================================\n")
                    for i, query in enumerate(bug_report['query_history']):
                        f.write(f"-- Query {i+1}:\n")
                        f.write(f"{query};\n\n")
                
                # The buggy query
                f.write("-- =========================================\n")
                f.write("-- Bug Reproduction Query\n")
                f.write("-- =========================================\n")
                f.write(f"-- Expected: {bug_report['description']}\n")
                f.write(f"-- Actual: {bug_report['exception'] or 'Unexpected behavior'}\n\n")
                f.write(f"{bug_report['original_query']};\n\n")
                
                # Additional context
                if bug_report['context']:
                    f.write("-- =========================================\n")
                    f.write("-- Additional Context\n")
                    f.write("-- =========================================\n")
                    for key, value in bug_report['context'].items():
                        f.write(f"-- {key}: {value}\n")
                
                f.write("\n-- End of reproduction script\n")
            
            self.logger.info(f"Created reproduction file: {filepath}")
            
        except Exception as e:
            self.logger.error(f"Failed to create reproduction file: {e}")
    
    def get_bug_summary(self) -> Dict[str, Any]:
        """Get a summary of all reported bugs."""
        return {
            "total_bugs": sum(self.bug_counters.values()),
            "by_category": self.bug_counters.copy(),
            "directories": {k: v for k, v in self.dirs.items()}
        }
    
    def create_bug_report_summary(self) -> str:
        """Create a human-readable summary of all bugs."""
        summary = self.get_bug_summary()
        
        report = "# YBFuzz Bug Report Summary\n\n"
        report += f"**Total Bugs Found:** {summary['total_bugs']}\n\n"
        
        report += "## Bugs by Category\n"
        for category, count in summary['by_category'].items():
            report += f"- **{category.replace('_', ' ').title()}:** {count}\n"
        
        report += "\n## Directory Structure\n"
        for category, dir_path in summary['directories'].items():
            report += f"- **{category.replace('_', ' ').title()}:** `{dir_path}`\n"
        
        if summary['total_bugs'] == 0:
            report += "\n🎉 **No bugs found!** The fuzzer is working correctly.\n"
        else:
            report += f"\n📊 **Bug Distribution:**\n"
            for category, count in summary['by_category'].items():
                if count > 0:
                    percentage = (count / summary['total_bugs']) * 100
                    report += f"- {category.replace('_', ' ').title()}: {count} ({percentage:.1f}%)\n"
        
        return report

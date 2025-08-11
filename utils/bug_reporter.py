import json
import logging
import os
import time
from datetime import datetime
from typing import Any, Dict, List, Optional
from config import FuzzerConfig

class BugReporter:
    """
    Enhanced bug reporter that provides comprehensive bug information
    including exact reproduction datasets and step-by-step instructions.
    """
    
    def __init__(self, config: FuzzerConfig):
        self.config = config
        self.logger = logging.getLogger(self.__class__.__name__)
        self.bugs_file = config.get('bug_reporting', {}).get('bugs_file', 'bugs.log')
        self.reproduction_dir = config.get('bug_reporting', {}).get('reproduction_dir', 'bug_reproductions')
        
        # Create reproduction directory
        os.makedirs(self.reproduction_dir, exist_ok=True)
        
        # Track bugs for summary
        self.bug_count = 0
        self.bug_types = {}
        
    def report_bug(self, oracle_name: str, bug_type: str, description: str, 
                   original_query: str = None, exception: Exception = None,
                   context: Dict[str, Any] = None, query_history: List[str] = None,
                   catalog_snapshot: Dict[str, Any] = None):
        """
        Reports a bug with comprehensive information for reproduction.
        """
        self.bug_count += 1
        bug_id = f"BUG_{self.bug_count:04d}_{int(time.time())}"
        
        # Update bug type statistics
        if bug_type not in self.bug_types:
            self.bug_types[bug_type] = 0
        self.bug_types[bug_type] += 1
        
        # Create comprehensive bug report
        bug_report = {
            "bug_id": bug_id,
            "timestamp": datetime.now().isoformat(),
            "oracle": oracle_name,
            "bug_type": bug_type,
            "description": description,
            "severity": self._assess_severity(bug_type, exception),
            "reproduction": {
                "original_query": original_query,
                "exception": str(exception) if exception else None,
                "context": context or {},
                "query_history": query_history or [],
                "catalog_snapshot": catalog_snapshot or {}
            },
                            "environment": {
                    "database": self.config.get_db_config().get('dbname', 'unknown'),
                    "schema": self.config.get_db_config().get('schema_name', 'unknown'),
                    "config_file": 'config.yaml'
                }
        }
        
        # Log to bugs.log
        self._log_bug(bug_report)
        
        # Create detailed reproduction file
        self._create_reproduction_file(bug_id, bug_report)
        
        # Log summary
        self.logger.error(f"!!! NEW BUG FOUND by {oracle_name}! Type: {bug_type}. See bugs.log for details. !!!")
        
        return bug_id
    
    def _assess_severity(self, bug_type: str, exception: Exception) -> str:
        """Assesses bug severity based on type and exception."""
        if "Critical Database Error" in bug_type:
            return "HIGH"
        elif "Cardinality Misestimation" in bug_type:
            return "MEDIUM"
        elif "Plan Instability" in bug_type:
            return "LOW"
        else:
            return "UNKNOWN"
    
    def _log_bug(self, bug_report: Dict[str, Any]):
        """Logs bug to the main bugs.log file."""
        try:
            with open(self.bugs_file, 'a') as f:
                f.write(json.dumps(bug_report) + '\n')
        except Exception as e:
            self.logger.error(f"Failed to write to bugs.log: {e}")
    
    def _create_reproduction_file(self, bug_id: str, bug_report: Dict[str, Any]):
        """Creates a detailed reproduction file for the bug."""
        try:
            repro_file = os.path.join(self.reproduction_dir, f"{bug_id}_reproduction.sql")
            
            with open(repro_file, 'w') as f:
                f.write(f"-- Bug Reproduction Script: {bug_id}\n")
                f.write(f"-- Type: {bug_report['bug_type']}\n")
                f.write(f"-- Severity: {bug_report['severity']}\n")
                f.write(f"-- Description: {bug_report['description']}\n")
                f.write(f"-- Timestamp: {bug_report['timestamp']}\n")
                f.write(f"-- Oracle: {bug_report['oracle']}\n\n")
                
                # Environment setup
                f.write("-- =========================================\n")
                f.write("-- ENVIRONMENT SETUP\n")
                f.write("-- =========================================\n")
                f.write(f"-- Database: {bug_report['environment']['database']}\n")
                f.write(f"-- Schema: {bug_report['environment']['schema']}\n")
                f.write(f"-- Config: {bug_report['environment']['config_file']}\n\n")
                
                # Schema recreation
                f.write("-- =========================================\n")
                f.write("-- SCHEMA RECREATION\n")
                f.write("-- =========================================\n")
                f.write("-- Drop and recreate schema\n")
                f.write(f"DROP SCHEMA IF EXISTS {bug_report['environment']['schema']} CASCADE;\n")
                f.write(f"CREATE SCHEMA {bug_report['environment']['schema']};\n\n")
                
                # Table creation (if catalog snapshot available)
                if bug_report['reproduction']['catalog_snapshot']:
                    f.write("-- =========================================\n")
                    f.write("-- TABLE CREATION\n")
                    f.write("-- =========================================\n")
                    tables = bug_report['reproduction']['catalog_snapshot'].get('tables', {})
                    for table_name, table_info in tables.items():
                        f.write(f"-- Table: {table_name}\n")
                        f.write(f"CREATE TABLE {bug_report['environment']['schema']}.{table_name} (\n")
                        columns = table_info.get('columns', [])
                        for i, col in enumerate(columns):
                            comma = "," if i < len(columns) - 1 else ""
                            f.write(f"    {col['name']} {col['type']}{comma}\n")
                        f.write(");\n\n")
                
                # Data insertion (if available)
                if bug_report['reproduction']['context'].get('sample_data'):
                    f.write("-- =========================================\n")
                    f.write("-- SAMPLE DATA INSERTION\n")
                    f.write("-- =========================================\n")
                    f.write(bug_report['reproduction']['context']['sample_data'])
                    f.write("\n\n")
                
                # Query history for context
                if bug_report['reproduction']['query_history']:
                    f.write("-- =========================================\n")
                    f.write("-- QUERY CONTEXT (executed before the bug)\n")
                    f.write("-- =========================================\n")
                    for i, query in enumerate(bug_report['reproduction']['query_history']):
                        f.write(f"-- Query {i+1}:\n")
                        f.write(f"{query};\n\n")
                
                # The buggy query
                f.write("-- =========================================\n")
                f.write("-- THE BUGGY QUERY\n")
                f.write("-- =========================================\n")
                f.write(f"-- This query triggers the bug: {bug_report['bug_type']}\n")
                if bug_report['reproduction']['original_query']:
                    f.write(f"{bug_report['reproduction']['original_query']};\n\n")
                
                # Exception details
                if bug_report['reproduction']['exception']:
                    f.write("-- =========================================\n")
                    f.write("-- EXPECTED ERROR\n")
                    f.write("-- =========================================\n")
                    f.write(f"-- Error: {bug_report['reproduction']['exception']}\n\n")
                
                # Additional context
                if bug_report['reproduction']['context']:
                    f.write("-- =========================================\n")
                    f.write("-- ADDITIONAL CONTEXT\n")
                    f.write("-- =========================================\n")
                    for key, value in bug_report['reproduction']['context'].items():
                        if key not in ['sample_data']:  # Already handled above
                            f.write(f"-- {key}: {value}\n")
                
                # Reproduction steps
                f.write("\n-- =========================================\n")
                f.write("-- REPRODUCTION STEPS\n")
                f.write("-- =========================================\n")
                f.write("-- 1. Run the schema recreation commands above\n")
                f.write("-- 2. Execute the query context (if any)\n")
                f.write("-- 3. Run the buggy query\n")
                f.write("-- 4. Observe the error/issue\n")
                f.write("-- 5. Verify the bug behavior matches the description\n\n")
                
                # Analysis notes
                f.write("-- =========================================\n")
                f.write("-- ANALYSIS NOTES\n")
                f.write("-- =========================================\n")
                f.write(f"-- Bug ID: {bug_id}\n")
                f.write(f"-- Severity: {bug_report['severity']}\n")
                f.write(f"-- Oracle: {bug_report['oracle']}\n")
                f.write(f"-- Timestamp: {bug_report['timestamp']}\n")
                
            self.logger.info(f"Created detailed reproduction file: {repro_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to create reproduction file: {e}")
    
    def get_bug_summary(self) -> Dict[str, Any]:
        """Returns a summary of all reported bugs."""
        return {
            "total_bugs": self.bug_count,
            "bug_types": self.bug_types,
            "bugs_file": self.bugs_file,
            "reproduction_dir": self.reproduction_dir
        }
    
    def create_bug_report_summary(self):
        """Creates a human-readable summary of all bugs found."""
        try:
            summary_file = os.path.join(self.reproduction_dir, "BUG_SUMMARY.md")
            
            with open(summary_file, 'w') as f:
                f.write("# YBFuzz Bug Report Summary\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                f.write(f"## Overview\n")
                f.write(f"- **Total Bugs Found**: {self.bug_count}\n")
                f.write(f"- **Bug Types**: {len(self.bug_types)}\n")
                f.write(f"- **Reproduction Files**: {self.reproduction_dir}/\n\n")
                
                if self.bug_types:
                    f.write("## Bug Type Breakdown\n")
                    for bug_type, count in self.bug_types.items():
                        f.write(f"- **{bug_type}**: {count} bugs\n")
                    f.write("\n")
                
                f.write("## Files\n")
                f.write(f"- **Main Bug Log**: `{self.bugs_file}`\n")
                f.write(f"- **Reproduction Scripts**: `{self.reproduction_dir}/`\n")
                f.write(f"- **Configuration**: `{self.config.config_file}`\n\n")
                
                f.write("## Next Steps\n")
                f.write("1. Review each bug reproduction file\n")
                f.write("2. Verify bugs in a clean environment\n")
                f.write("3. Report confirmed bugs to the database team\n")
                f.write("4. Track bug fixes and regressions\n")
                
            self.logger.info(f"Created bug summary: {summary_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to create bug summary: {e}")

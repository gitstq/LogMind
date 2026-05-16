#!/usr/bin/env python3
"""
🧠 LogMind - Lightweight Terminal Log Intelligent Analysis Engine
轻量级终端日志智能分析引擎

A zero-dependency, high-performance CLI tool for real-time log monitoring,
pattern recognition, and anomaly detection.

Author: gitstq
License: MIT
Version: 1.0.0
"""

import sys
import os
import re
import json
import time
import gzip
import zipfile
import tarfile
import argparse
import threading
import signal
import random
from datetime import datetime, timedelta
from collections import defaultdict, Counter
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any, Generator
from dataclasses import dataclass, field, asdict
from enum import Enum
import tempfile
import shutil

# Version info
__version__ = "1.0.0"
__author__ = "gitstq"


class LogLevel(Enum):
    """Log level enumeration"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"
    UNKNOWN = "UNKNOWN"


@dataclass
class LogEntry:
    """Represents a single log entry"""
    timestamp: Optional[datetime]
    level: LogLevel
    message: str
    source: str
    line_number: int
    raw_line: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PatternMatch:
    """Represents a pattern match in log"""
    pattern_name: str
    pattern: str
    count: int
    examples: List[str] = field(default_factory=list)


@dataclass
class Anomaly:
    """Represents an anomaly detection result"""
    anomaly_type: str
    description: str
    severity: str
    timestamp: Optional[datetime]
    evidence: str
    confidence: float


@dataclass
class LogStats:
    """Log analysis statistics"""
    total_lines: int = 0
    total_entries: int = 0
    level_counts: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    time_range: Tuple[Optional[datetime], Optional[datetime]] = (None, None)
    top_errors: List[Tuple[str, int]] = field(default_factory=list)
    patterns_found: List[PatternMatch] = field(default_factory=list)
    anomalies: List[Anomaly] = field(default_factory=list)


class LogParser:
    """Parse various log formats"""

    # Common timestamp patterns
    TIMESTAMP_PATTERNS = [
        (r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)', '%Y-%m-%dT%H:%M:%S'),
        (r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})', '%Y-%m-%d %H:%M:%S'),
        (r'(\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2})', '%m/%d/%Y %H:%M:%S'),
        (r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', '%d/%b/%Y:%H:%M:%S'),
        (r'(\w{3} \d{2} \d{2}:\d{2}:\d{2})', '%b %d %H:%M:%S'),
        (r'(\d{4}\d{2}\d{2} \d{2}\d{2}\d{2})', '%Y%m%d %H%M%S'),
    ]

    # Log level patterns
    LEVEL_PATTERNS = {
        LogLevel.DEBUG: [r'\bDEBUG\b', r'\bDBG\b', r'\[D\]'],
        LogLevel.INFO: [r'\bINFO\b', r'\bINF\b', r'\[I\]'],
        LogLevel.WARNING: [r'\bWARN(?:ING)?\b', r'\bWRN\b', r'\[W\]'],
        LogLevel.ERROR: [r'\bERROR\b', r'\bERR\b', r'\[E\]'],
        LogLevel.CRITICAL: [r'\bCRITICAL\b', r'\bFATAL\b', r'\bCRIT\b', r'\[C\]'],
    }

    def __init__(self):
        self.timestamp_regexes = [(re.compile(p), fmt) for p, fmt in self.TIMESTAMP_PATTERNS]
        self.level_regexes = {
            level: [re.compile(p, re.IGNORECASE) for p in patterns]
            for level, patterns in self.LEVEL_PATTERNS.items()
        }

    def parse_timestamp(self, line: str) -> Optional[datetime]:
        """Extract timestamp from log line"""
        for regex, fmt in self.timestamp_regexes:
            match = regex.search(line)
            if match:
                timestamp_str = match.group(1)
                try:
                    # Try full format first
                    if 'T' in timestamp_str:
                        return datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                    return datetime.strptime(timestamp_str, fmt)
                except ValueError:
                    continue
        return None

    def parse_level(self, line: str) -> LogLevel:
        """Extract log level from line"""
        for level, regexes in self.level_regexes.items():
            for regex in regexes:
                if regex.search(line):
                    return level
        return LogLevel.UNKNOWN

    def parse_line(self, line: str, line_number: int, source: str) -> LogEntry:
        """Parse a single log line"""
        timestamp = self.parse_timestamp(line)
        level = self.parse_level(line)

        # Try to extract message (after timestamp and level)
        message = line.strip()
        if timestamp:
            # Remove timestamp from message
            for regex, _ in self.timestamp_regexes:
                message = regex.sub('', message, count=1)
        # Remove level indicators
        for level_obj, regexes in self.level_regexes.items():
            for regex in regexes:
                message = regex.sub('', message)

        message = message.strip(' []-:')

        return LogEntry(
            timestamp=timestamp,
            level=level,
            message=message,
            source=source,
            line_number=line_number,
            raw_line=line.strip()
        )


class PatternDetector:
    """Detect patterns in logs"""

    # Built-in patterns
    BUILTIN_PATTERNS = {
        'ip_address': r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'url': r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?',
        'uuid': r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b',
        'exception': r'\b(?:Exception|Error|Traceback)\b',
        'http_status': r'\b(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b.*\b(\d{3})\b',
        'sql_query': r'\b(?:SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER)\b.*\b(?:FROM|INTO|TABLE)\b',
        'json_object': r'\{[^{}]*\}',
        'memory_address': r'0x[0-9a-fA-F]+',
        'stack_trace': r'File ".*", line \d+',
    }

    def __init__(self, custom_patterns: Optional[Dict[str, str]] = None):
        self.patterns = {**self.BUILTIN_PATTERNS}
        if custom_patterns:
            self.patterns.update(custom_patterns)
        self.compiled_patterns = {name: re.compile(pattern) for name, pattern in self.patterns.items()}

    def detect_patterns(self, entries: List[LogEntry]) -> List[PatternMatch]:
        """Detect patterns in log entries"""
        matches = defaultdict(lambda: {'count': 0, 'examples': []})

        for entry in entries:
            for name, regex in self.compiled_patterns.items():
                if regex.search(entry.raw_line):
                    matches[name]['count'] += 1
                    if len(matches[name]['examples']) < 3:
                        matches[name]['examples'].append(entry.raw_line[:200])

        return [
            PatternMatch(
                pattern_name=name,
                pattern=self.patterns[name],
                count=data['count'],
                examples=data['examples']
            )
            for name, data in sorted(matches.items(), key=lambda x: -x[1]['count'])
            if data['count'] > 0
        ]


class AnomalyDetector:
    """Detect anomalies in logs"""

    def __init__(self):
        self.error_keywords = ['error', 'exception', 'failed', 'failure', 'timeout', 'crash', 'fatal']
        self.suspicious_patterns = [
            (r'\b(?:password|passwd|pwd)\s*[=:]\s*\S+', 'Potential password exposure'),
            (r'\b(?:secret|token|key)\s*[=:]\s*["\']\S+["\']', 'Potential secret exposure'),
            (r'\b(?:SELECT|INSERT|UPDATE|DELETE).*\b(?:OR|AND)\s*\'\s*=\s*\'', 'Possible SQL injection'),
            (r'<script[^>]*>', 'Possible XSS attempt'),
            (r'\b(?:rm\s+-rf|del\s+/f|format\s+[a-z]:)', 'Dangerous command detected'),
        ]
        self.compiled_suspicious = [(re.compile(p, re.IGNORECASE), desc) for p, desc in self.suspicious_patterns]

    def detect_anomalies(self, entries: List[LogEntry]) -> List[Anomaly]:
        """Detect anomalies in log entries"""
        anomalies = []

        # Group entries by time windows for burst detection
        time_windows = defaultdict(list)
        for entry in entries:
            if entry.timestamp:
                window_key = entry.timestamp.replace(minute=0, second=0, microsecond=0)
                time_windows[window_key].append(entry)

        # Detect error bursts
        for window, window_entries in time_windows.items():
            error_count = sum(1 for e in window_entries if e.level in [LogLevel.ERROR, LogLevel.CRITICAL])
            if error_count > 10:
                anomalies.append(Anomaly(
                    anomaly_type='Error Burst',
                    description=f'High error rate detected: {error_count} errors in one hour',
                    severity='HIGH',
                    timestamp=window,
                    evidence=f'Sample: {window_entries[0].raw_line[:100]}...',
                    confidence=min(error_count / 50, 1.0)
                ))

        # Detect suspicious patterns
        for entry in entries:
            for regex, description in self.compiled_suspicious:
                if regex.search(entry.raw_line):
                    anomalies.append(Anomaly(
                        anomaly_type='Security Concern',
                        description=description,
                        severity='CRITICAL',
                        timestamp=entry.timestamp,
                        evidence=entry.raw_line[:200],
                        confidence=0.9
                    ))

        # Detect repeated errors
        error_messages = Counter(e.message for e in entries if e.level == LogLevel.ERROR)
        for msg, count in error_messages.most_common(5):
            if count > 5:
                anomalies.append(Anomaly(
                    anomaly_type='Repeated Error',
                    description=f'Error occurred {count} times: {msg[:50]}...',
                    severity='MEDIUM',
                    timestamp=None,
                    evidence=msg[:200],
                    confidence=min(count / 20, 1.0)
                ))

        return anomalies


class LogAnalyzer:
    """Main log analysis engine"""

    def __init__(self):
        self.parser = LogParser()
        self.pattern_detector = PatternDetector()
        self.anomaly_detector = AnomalyDetector()
        self.stats = LogStats()

    def read_log_file(self, filepath: str, follow: bool = False) -> Generator[str, None, None]:
        """Read log file, handling compressed files"""
        path = Path(filepath)

        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {filepath}")

        # Handle compressed files
        if filepath.endswith('.gz'):
            opener = lambda: gzip.open(filepath, 'rt', encoding='utf-8', errors='ignore')
        elif filepath.endswith('.zip'):
            with zipfile.ZipFile(filepath, 'r') as zf:
                # Read first file in archive
                first_file = zf.namelist()[0]
                with zf.open(first_file) as f:
                    for line in f:
                        yield line.decode('utf-8', errors='ignore')
            return
        elif filepath.endswith(('.tar', '.tar.gz', '.tgz')):
            mode = 'r:gz' if filepath.endswith(('.tar.gz', '.tgz')) else 'r'
            with tarfile.open(filepath, mode) as tf:
                for member in tf.getmembers():
                    if member.isfile():
                        f = tf.extractfile(member)
                        if f:
                            for line in f:
                                yield line.decode('utf-8', errors='ignore')
            return
        else:
            opener = lambda: open(filepath, 'r', encoding='utf-8', errors='ignore')

        with opener() as f:
            if follow:
                # Tail -f mode
                f.seek(0, 2)  # Seek to end
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)
                        continue
                    yield line
            else:
                for line in f:
                    yield line

    def analyze(self, filepath: str, follow: bool = False, max_lines: Optional[int] = None) -> LogStats:
        """Analyze a log file"""
        self.stats = LogStats()
        entries = []

        try:
            for line_number, line in enumerate(self.read_log_file(filepath, follow), 1):
                if max_lines and line_number > max_lines:
                    break

                self.stats.total_lines += 1

                # Parse line
                entry = self.parser.parse_line(line, line_number, filepath)

                if entry.level != LogLevel.UNKNOWN or entry.timestamp:
                    self.stats.total_entries += 1
                    self.stats.level_counts[entry.level.value] += 1
                    entries.append(entry)

                    # Update time range
                    if entry.timestamp:
                        if self.stats.time_range[0] is None or entry.timestamp < self.stats.time_range[0]:
                            self.stats.time_range = (entry.timestamp, self.stats.time_range[1])
                        if self.stats.time_range[1] is None or entry.timestamp > self.stats.time_range[1]:
                            self.stats.time_range = (self.stats.time_range[0], entry.timestamp)

                if follow and line_number % 100 == 0:
                    # In follow mode, process in batches
                    if len(entries) >= 100:
                        break

        except KeyboardInterrupt:
            if follow:
                print("\n👋 Stopping real-time monitoring...")
            else:
                raise

        # Detect patterns
        self.stats.patterns_found = self.pattern_detector.detect_patterns(entries)

        # Detect anomalies
        self.stats.anomalies = self.anomaly_detector.detect_anomalies(entries)

        # Get top errors
        error_entries = [e for e in entries if e.level in [LogLevel.ERROR, LogLevel.CRITICAL]]
        error_counter = Counter(e.message[:100] for e in error_entries)
        self.stats.top_errors = error_counter.most_common(10)

        return self.stats


class OutputFormatter:
    """Format and display analysis results"""

    COLORS = {
        'reset': '\033[0m',
        'bold': '\033[1m',
        'dim': '\033[2m',
        'red': '\033[91m',
        'green': '\033[92m',
        'yellow': '\033[93m',
        'blue': '\033[94m',
        'magenta': '\033[95m',
        'cyan': '\033[96m',
        'white': '\033[97m',
    }

    LEVEL_COLORS = {
        'DEBUG': 'dim',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
        'CRITICAL': 'magenta',
        'UNKNOWN': 'white',
    }

    def __init__(self, no_color: bool = False):
        self.no_color = no_color or not sys.stdout.isatty()

    def color(self, text: str, color: str) -> str:
        """Apply color to text"""
        if self.no_color:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def format_stats(self, stats: LogStats) -> str:
        """Format statistics for display"""
        lines = []
        lines.append(self.color("=" * 70, 'cyan'))
        lines.append(self.color("📊 LogMind Analysis Report", 'bold'))
        lines.append(self.color("=" * 70, 'cyan'))
        lines.append("")

        # Summary
        lines.append(self.color("📈 Summary", 'bold'))
        lines.append(f"  Total Lines:    {stats.total_lines:,}")
        lines.append(f"  Valid Entries:  {stats.total_entries:,}")

        if stats.time_range[0] and stats.time_range[1]:
            duration = stats.time_range[1] - stats.time_range[0]
            lines.append(f"  Time Range:     {stats.time_range[0]} to {stats.time_range[1]}")
            lines.append(f"  Duration:       {duration}")
        lines.append("")

        # Level distribution
        if stats.level_counts:
            lines.append(self.color("📊 Log Level Distribution", 'bold'))
            total = sum(stats.level_counts.values())
            for level, count in sorted(stats.level_counts.items(), key=lambda x: -x[1]):
                color = self.LEVEL_COLORS.get(level, 'white')
                percentage = (count / total) * 100 if total > 0 else 0
                bar = '█' * int(percentage / 5)
                lines.append(f"  {self.color(f'{level:10}', color)} {count:6,} ({percentage:5.1f}%) {self.color(bar, color)}")
            lines.append("")

        # Top errors
        if stats.top_errors:
            lines.append(self.color("🔥 Top Errors", 'bold'))
            for msg, count in stats.top_errors[:5]:
                lines.append(f"  ({count:3}x) {msg[:60]}...")
            lines.append("")

        # Patterns
        if stats.patterns_found:
            lines.append(self.color("🔍 Detected Patterns", 'bold'))
            for pattern in stats.patterns_found[:10]:
                lines.append(f"  • {pattern.pattern_name:20} {pattern.count:5,} matches")
            lines.append("")

        # Anomalies
        if stats.anomalies:
            lines.append(self.color("⚠️  Anomalies Detected", 'bold'))
            for anomaly in stats.anomalies[:10]:
                severity_color = {'LOW': 'green', 'MEDIUM': 'yellow', 'HIGH': 'red', 'CRITICAL': 'magenta'}.get(anomaly.severity, 'white')
                lines.append(f"  [{self.color(anomaly.severity, severity_color)}] {anomaly.anomaly_type}")
                lines.append(f"    {anomaly.description}")
                if anomaly.confidence > 0:
                    lines.append(f"    Confidence: {anomaly.confidence:.0%}")
            lines.append("")

        lines.append(self.color("=" * 70, 'cyan'))
        return '\n'.join(lines)

    def format_json(self, stats: LogStats) -> str:
        """Format statistics as JSON"""
        data = {
            'summary': {
                'total_lines': stats.total_lines,
                'total_entries': stats.total_entries,
                'time_range': {
                    'start': stats.time_range[0].isoformat() if stats.time_range[0] else None,
                    'end': stats.time_range[1].isoformat() if stats.time_range[1] else None,
                }
            },
            'level_counts': dict(stats.level_counts),
            'top_errors': stats.top_errors,
            'patterns': [
                {
                    'name': p.pattern_name,
                    'pattern': p.pattern,
                    'count': p.count,
                    'examples': p.examples
                }
                for p in stats.patterns_found
            ],
            'anomalies': [
                {
                    'type': a.anomaly_type,
                    'description': a.description,
                    'severity': a.severity,
                    'timestamp': a.timestamp.isoformat() if a.timestamp else None,
                    'evidence': a.evidence,
                    'confidence': a.confidence
                }
                for a in stats.anomalies
            ]
        }
        return json.dumps(data, indent=2)

    def format_csv(self, entries: List[LogEntry]) -> str:
        """Format entries as CSV"""
        lines = ['timestamp,level,source,line_number,message']
        for entry in entries:
            ts = entry.timestamp.isoformat() if entry.timestamp else ''
            msg = entry.message.replace(',', ' ').replace('\n', ' ')
            lines.append(f'"{ts}","{entry.level.value}","{entry.source}",{entry.line_number},"{msg}"')
        return '\n'.join(lines)


def create_demo_log(filepath: str, num_lines: int = 1000):
    """Create a demo log file for testing"""
    levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
    weights = [30, 50, 10, 8, 2]
    messages = [
        "User login successful",
        "Database connection established",
        "Request processed",
        "Cache miss for key: user:12345",
        "API call completed in 45ms",
        "Failed to connect to database: Connection timeout",
        "Exception in thread: NullPointerException",
        "Authentication failed for user: admin",
        "Memory usage: 85%",
        "Disk space low: /var/log",
    ]

    base_time = datetime.now() - timedelta(hours=24)

    with open(filepath, 'w') as f:
        for i in range(num_lines):
            timestamp = base_time + timedelta(minutes=i * 2)
            level = random.choices(levels, weights=weights)[0]
            message = random.choice(messages)
            f.write(f"{timestamp.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {message}\n")

    print(f"✅ Demo log created: {filepath} ({num_lines} lines)")


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='🧠 LogMind - Lightweight Terminal Log Intelligent Analysis Engine',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s analyze /var/log/syslog
  %(prog)s analyze app.log --follow
  %(prog)s analyze *.log --format json --output report.json
  %(prog)s demo --lines 1000
        """
    )

    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    parser.add_argument('--no-color', action='store_true', help='Disable colored output')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze log files')
    analyze_parser.add_argument('files', nargs='+', help='Log file(s) to analyze')
    analyze_parser.add_argument('-f', '--follow', action='store_true', help='Follow mode (tail -f)')
    analyze_parser.add_argument('-n', '--lines', type=int, help='Maximum lines to analyze')
    analyze_parser.add_argument('-o', '--output', help='Output file')
    analyze_parser.add_argument('--format', choices=['text', 'json', 'csv'], default='text',
                               help='Output format')
    analyze_parser.add_argument('--pattern', action='append', help='Custom pattern (name:regex)')

    # Demo command
    demo_parser = subparsers.add_parser('demo', help='Create demo log file')
    demo_parser.add_argument('-o', '--output', default='demo.log', help='Output file')
    demo_parser.add_argument('-l', '--lines', type=int, default=1000, help='Number of lines')

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    formatter = OutputFormatter(no_color=args.no_color)

    if args.command == 'demo':
        import random
        create_demo_log(args.output, args.lines)

    elif args.command == 'analyze':
        analyzer = LogAnalyzer()

        # Parse custom patterns
        if args.pattern:
            custom_patterns = {}
            for p in args.pattern:
                if ':' in p:
                    name, regex = p.split(':', 1)
                    custom_patterns[name] = regex
            analyzer.pattern_detector = PatternDetector(custom_patterns)

        all_stats = []
        for filepath in args.files:
            print(f"🔍 Analyzing: {filepath}")
            try:
                stats = analyzer.analyze(filepath, follow=args.follow, max_lines=args.lines)
                all_stats.append(stats)

                if args.format == 'json':
                    output = formatter.format_json(stats)
                elif args.format == 'csv':
                    # For CSV, we need to re-parse entries
                    output = "CSV format requires single file analysis"
                else:
                    output = formatter.format_stats(stats)

                if args.output:
                    with open(args.output, 'w') as f:
                        f.write(output)
                    print(f"✅ Report saved to: {args.output}")
                else:
                    print(output)

            except FileNotFoundError as e:
                print(f"❌ {e}")
                sys.exit(1)
            except Exception as e:
                print(f"❌ Error analyzing {filepath}: {e}")
                sys.exit(1)


if __name__ == '__main__':
    main()

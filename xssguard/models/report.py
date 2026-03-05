"""
Модели для отчетов
"""
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Optional
from .vulnerability import Vulnerability, Severity


@dataclass
class ScanSummary:
    """Сводка по сканированию"""
    total_files: int = 0
    scanned_files: int = 0
    skipped_files: int = 0
    errors: int = 0
    
    # Статистика по уязвимостям
    total_vulnerabilities: int = 0
    by_severity: Dict[Severity, int] = field(default_factory=dict)
    by_type: Dict[str, int] = field(default_factory=dict)
    
    def update(self, vulnerabilities: List[Vulnerability]):
        """Обновить статистику"""
        self.total_vulnerabilities += len(vulnerabilities)
        for v in vulnerabilities:
            # По severity
            self.by_severity[v.severity] = self.by_severity.get(v.severity, 0) + 1
            # По type
            self.by_type[v.type.value] = self.by_type.get(v.type.value, 0) + 1


@dataclass
class ScanReport:
    """Полный отчет о сканировании"""
    # Метаданные
    scan_id: str = field(default_factory=lambda: f"scan-{datetime.now():%Y%m%d-%H%M%S}")
    start_time: datetime = field(default_factory=datetime.now)
    end_time: Optional[datetime] = None
    
    # Результаты
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    summary: ScanSummary = field(default_factory=ScanSummary)
    
    # Информация о сканировании
    scanned_paths: List[Path] = field(default_factory=list)
    config_used: Dict[str, Any] = field(default_factory=dict)
    
    def add_vulnerabilities(self, vulns: List[Vulnerability]):
        """Добавить уязвимости и обновить статистику"""
        self.vulnerabilities.extend(vulns)
        self.summary.update(vulns)
    
    def complete(self):
        """Завершить отчет"""
        self.end_time = datetime.now()
    
    def to_dict(self) -> Dict[str, Any]:
        """Для JSON сериализации"""
        return {
            "scan_id": self.scan_id,
            "duration": (self.end_time - self.start_time).total_seconds() if self.end_time else None,
            "summary": {
                "total_files": self.summary.total_files,
                "scanned_files": self.summary.scanned_files,
                "vulnerabilities": self.summary.total_vulnerabilities,
                "by_severity": {k.value: v for k, v in self.summary.by_severity.items()},
                "by_type": self.summary.by_type
            },
            "vulnerabilities": [v.to_dict() for v in self.vulnerabilities],
            "scanned_paths": [str(p) for p in self.scanned_paths]
        }
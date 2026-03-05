"""
Модели для правил анализа
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class RuleType(Enum):
    """Тип правила"""
    SOURCE = "source"      # Источник данных
    SINK = "sink"          # Опасный вывод
    SANITIZER = "sanitizer"  # Функция очистки
    PATTERN = "pattern"    # Поиск по паттерну


@dataclass
class Rule:
    """
    Правило для поиска уязвимостей
    """
    name: str
    type: RuleType
    pattern: str  # Может быть строкой, регуляркой или именем функции
    language: str  # php, javascript, html
    description: str = ""
    severity: str = "medium"
    
    # Для более сложных правил
    regex: bool = False  # Использовать ли регулярное выражение
    case_sensitive: bool = True
    exclude_patterns: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type.value,
            "pattern": self.pattern,
            "language": self.language,
            "description": self.description,
            "severity": self.severity,
            "regex": self.regex
        }


@dataclass
class RuleSet:
    """Набор правил для языка"""
    language: str
    sources: List[Rule] = field(default_factory=list)
    sinks: List[Rule] = field(default_factory=list)
    sanitizers: List[Rule] = field(default_factory=list)
    patterns: List[Rule] = field(default_factory=list)
    
    def add_rule(self, rule: Rule):
        """Добавить правило в соответствующий список"""
        if rule.type == RuleType.SOURCE:
            self.sources.append(rule)
        elif rule.type == RuleType.SINK:
            self.sinks.append(rule)
        elif rule.type == RuleType.SANITIZER:
            self.sanitizers.append(rule)
        else:
            self.patterns.append(rule)
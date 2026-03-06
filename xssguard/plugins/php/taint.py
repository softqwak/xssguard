"""
Модель заражённых данных для PHP анализатора
"""

from dataclasses import dataclass, field
from typing import Set, Dict, Optional


@dataclass
class TaintInfo:
    """
    Информация о заражённой переменной.
    """
    variable_name: str
    source: str
    line: int
    sanitized: bool = False
    sanitizer: Optional[str] = None
    
    def __hash__(self):
        return hash((self.variable_name, self.line))
    
    def __eq__(self, other):
        if not isinstance(other, TaintInfo):
            return False
        return (self.variable_name == other.variable_name and 
                self.line == other.line)


@dataclass
class TaintState:
    """
    Состояние заражения на текущий момент анализа.
    """
    variables: Dict[str, Set[TaintInfo]] = field(default_factory=dict)
    call_stack: list = field(default_factory=list)
    
    def is_tainted(self, var_name: str) -> bool:
        """Проверяет, заражена ли переменная."""
        return var_name in self.variables and bool(self.variables[var_name])
    
    def get_taint(self, var_name: str) -> Set[TaintInfo]:
        """Возвращает информацию о заражении переменной."""
        return self.variables.get(var_name, set())
    
    def add_taint(self, var_name: str, taint_info: TaintInfo):
        """Добавляет заражение переменной."""
        if var_name not in self.variables:
            self.variables[var_name] = set()
        self.variables[var_name].add(taint_info)
    
    def remove_taint(self, var_name: str):
        """Удаляет заражение (например, после очистки)."""
        if var_name in self.variables:
            del self.variables[var_name]
    
    def copy(self) -> 'TaintState':
        """Создаёт копию состояния (для ветвлений)."""
        new_state = TaintState()
        for var, taints in self.variables.items():
            new_state.variables[var] = set(taints)
        return new_state
    
    def merge(self, other: 'TaintState'):
        """Объединяет два состояния (после ветвления)."""
        for var, taints in other.variables.items():
            if var not in self.variables:
                self.variables[var] = set()
            self.variables[var].update(taints)
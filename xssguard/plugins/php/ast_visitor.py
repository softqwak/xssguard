"""
Обходчик AST для PHP с использованием phply
"""

from phply.phpast import (
    Node, InlineHTML, Block, Assignment, ListAssignment,
    Echo, Print, FunctionCall, MethodCall, StaticMethodCall,
    Variable, ArrayOffset, StringOffset, ObjectProperty,
    StaticProperty, BinaryOp, UnaryOp, TernaryOp,
    If, ElseIf, Else, While, DoWhile, For, Foreach,
    Include, Require, Constant, MagicConstant
)
from typing import List, Optional, Any, Union
from pathlib import Path

from ...models.vulnerability import (
    Vulnerability, VulnerabilityType, Severity, 
    Confidence, CodeLocation
)
from .taint import TaintState, TaintInfo


class PHPVisitor:
    """
    Обходчик AST для поиска XSS-уязвимостей.
    """
    
    def __init__(self, config, logger):
        """
        Args:
            config: объект PHPConfig
            logger: экземпляр класса логирования
        """
        self.config = config
        self.logger = logger
        self.taint_state = TaintState()
        self.vulnerabilities: List[Vulnerability] = []
        
        # Источники заражения из конфига
        self.sources = config.sources
        
        # Опасные стоки из конфига
        self.sinks = config.sinks
        
        # Функции очистки из конфига
        self.sanitizers = config.sanitizers
        
        # Функции, возвращающие пользовательские данные
        self.user_input_functions = config.user_input_functions
        
        # Опции
        self.options = config.options
        self.max_call_depth = self.options.get('max_call_depth', 3)
        self.track_array_elements = self.options.get('track_array_elements', True)
    
    def visit(self, node: Node) -> Any:
        """
        Главный метод обхода. Вызывает соответствующий visit_* метод.
        """
        class_name = node.__class__.__name__
        method_name = f'visit_{class_name.lower()}'
        visitor = getattr(self, method_name, self.generic_visit)
        return visitor(node)
    
    def generic_visit(self, node: Node):
        """Обход всех детей узла."""
        for field in node.fields:
            value = getattr(node, field)
            if isinstance(value, Node):
                self.visit(value)
            elif isinstance(value, list):
                for item in value:
                    if isinstance(item, Node):
                        self.visit(item)
    
    def visit_variable(self, node: Variable):
        """Обработка переменной."""
        # Просто возвращаем имя переменной
        return node.name
    
    def visit_assignment(self, node: Assignment):
        """Обработка присваивания: $var = value;"""
        if isinstance(node.node, Variable):
            var_name = node.node.name
            print(f"DEBUG: Присваивание переменной ${var_name} на строке {getattr(node, 'lineno', 0)}")
            
            taint_info = self._get_taint_from_expr(node.expr)
            
            if taint_info:
                print(f"DEBUG: Прямое заражение ${var_name} из {taint_info.source}")
                self.taint_state.add_taint(var_name, taint_info)
            else:
                print(f"DEBUG: Косвенное заражение ${var_name}")
                self._propagate_taint_in_expr(var_name, node.expr)
        
        self.generic_visit(node)
    
    def _get_taint_from_expr(self, expr) -> Optional[TaintInfo]:
        """
        Проверяет, является ли выражение прямым источником заражения.
        """
        # Прямой доступ к суперглобалу: $_GET[...]
        if isinstance(expr, ArrayOffset) and isinstance(expr.node, Variable):
            var_name = expr.node.name
            if var_name in self.sources:
                return TaintInfo(
                    variable_name=var_name,
                    source=var_name,
                    line=getattr(expr, 'lineno', 0)
                )
        
        # Вызов функции, возвращающей пользовательские данные
        elif isinstance(expr, FunctionCall):
            if isinstance(expr.name, Variable):
                func_name = expr.name.name
                if func_name in self.user_input_functions:
                    return TaintInfo(
                        variable_name=func_name,
                        source=func_name,
                        line=getattr(expr, 'lineno', 0)
                    )
        
        # Константа (может быть магической)
        elif isinstance(expr, Constant):
            # TODO: обрабатывать константы
            pass
        
        return None
    
    def _propagate_taint_in_expr(self, target_var: str, expr):
        """
        Распространяет заражение через выражения.
        """
        # Присваивание переменной
        if isinstance(expr, Variable):
            source_var = expr.name
            if self.taint_state.is_tainted(source_var):
                for taint in self.taint_state.get_taint(source_var):
                    self.taint_state.add_taint(target_var, taint)
        
        # Бинарные операции (включая конкатенацию)
        elif isinstance(expr, BinaryOp):
            print(f"DEBUG: Бинарная операция {expr.op} на строке {getattr(expr, 'lineno', 0)}")
            # Проверяем левую часть
            if isinstance(expr.left, Variable):
                left_var = expr.left.name
                if self.taint_state.is_tainted(left_var):
                    for taint in self.taint_state.get_taint(left_var):
                        self.taint_state.add_taint(target_var, taint)
            
            # Проверяем правую часть
            if isinstance(expr.right, Variable):
                right_var = expr.right.name
                if self.taint_state.is_tainted(right_var):
                    for taint in self.taint_state.get_taint(right_var):
                        self.taint_state.add_taint(target_var, taint)
        
        # Унарные операции
        elif isinstance(expr, UnaryOp):
            self._propagate_taint_in_expr(target_var, expr.expr)
        
        # Тернарные операции
        elif isinstance(expr, TernaryOp):
            self._propagate_taint_in_expr(target_var, expr.iftrue)
            if expr.iffalse:
                self._propagate_taint_in_expr(target_var, expr.iffalse)
        
        # Доступ к элементу массива
        elif isinstance(expr, ArrayOffset) and isinstance(expr.node, Variable):
            source_var = expr.node.name
            if self.taint_state.is_tainted(source_var):
                for taint in self.taint_state.get_taint(source_var):
                    self.taint_state.add_taint(target_var, taint)
    
    def visit_echo(self, node: Echo):
        """Обработка echo - опасный сток."""
        if hasattr(node, 'nodes'):
            self._check_sink(node.nodes, 'echo')
        elif hasattr(node, 'node'):
            self._check_sink([node.node], 'echo')
        self.generic_visit(node)

    def visit_print(self, node: Print):
        """Обработка print - опасный сток."""
        if hasattr(node, 'nodes'):
            self._check_sink(node.nodes, 'print')
        elif hasattr(node, 'node'):
            self._check_sink([node.node], 'print')
        self.generic_visit(node)
    
    def _check_sink(self, exprs, sink_name: str):
        """Проверяет, не выводится ли заражённая переменная."""
        for expr in exprs:
            # Пытаемся получить номер строки разными способами
            line_no = 0
            if hasattr(expr, 'lineno') and expr.lineno:
                line_no = expr.lineno
            elif hasattr(expr, 'node') and hasattr(expr.node, 'lineno'):
                line_no = expr.node.lineno
            
            print(f"DEBUG: Проверка {expr} на строке {line_no}")
            
            if isinstance(expr, Variable):
                var_name = expr.name
                if self.taint_state.is_tainted(var_name):
                    print(f"DEBUG: Найдена заражённая переменная {var_name}")
                    for taint in self.taint_state.get_taint(var_name):
                        self._report_vulnerability(
                            line_no,
                            sink_name,
                            taint
                        )
            elif isinstance(expr, BinaryOp):
                # Рекурсивно проверяем части бинарной операции
                self._check_expr_for_taint(expr.left, sink_name)
                self._check_expr_for_taint(expr.right, sink_name)
                
    def _check_expr_for_taint(self, expr, sink_name: str):
        """Проверяет выражение на наличие заражённых переменных."""
        if isinstance(expr, Variable):
            var_name = expr.name
            if self.taint_state.is_tainted(var_name):
                line_no = getattr(expr, 'lineno', 0)
                for taint in self.taint_state.get_taint(var_name):
                    self._report_vulnerability(line_no, sink_name, taint)
        elif isinstance(expr, BinaryOp):
            self._check_expr_for_taint(expr.left, sink_name)
            self._check_expr_for_taint(expr.right, sink_name)
    
    def _report_vulnerability(self, line: int, sink: str, taint: TaintInfo):
        """Создаёт запись об уязвимости."""
        self.logger.debug("Обнаружена уязвимость",
                         line=line,
                         sink=sink,
                         source=taint.source,
                         variable=taint.variable_name)
        vuln = Vulnerability(
            type=VulnerabilityType.REFLECTED_XSS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            location=CodeLocation(
                file_path=None,
                line=line,
                line_content="",  # Пока пусто, заполним позже
            ),
            title=f"XSS: данные из {taint.source} выводятся через {sink}",
            description=(
                f"Переменная, содержащая данные из {taint.source}, "
                f"выводится через {sink} без фильтрации."
            ),
            tags=['php', 'reflected', 'xss'],
            analyzer_name='php_analyzer'
        )
        self.vulnerabilities.append(vuln)
    
    def visit_functioncall(self, node: FunctionCall):
        """Обработка вызова функции."""
        # Получаем имя функции
        func_name = None
        if isinstance(node.name, Variable):
            func_name = node.name.name
        
        if func_name and func_name in self.sanitizers and node.params:
            self._handle_sanitizer(node, func_name)
        
        self.generic_visit(node)
    
    def _handle_sanitizer(self, node: FunctionCall, func_name: str):
        """Обрабатывает вызов функции очистки."""
        if not node.params:
            return
        
        # Берём первый параметр (обычно)
        param = node.params[0]
        if isinstance(param, Variable):
            var_name = param.name
            if self.taint_state.is_tainted(var_name):
                # Снимаем заражение
                self.taint_state.remove_taint(var_name)
    
    def visit_include(self, node: Include):
        """Обработка include - пока игнорируем."""
        # TODO: добавить анализ включённых файлов
        self.generic_visit(node)
    
    def visit_require(self, node: Require):
        """Обработка require - пока игнорируем."""
        self.generic_visit(node)
    
    def visit_if(self, node: If):
        """Обработка условного оператора."""
        # Сохраняем текущее состояние
        old_state = self.taint_state.copy()
        
        # Анализируем условие
        self.visit(node.expr)
        
        # Анализируем тело if
        if node.node:
            self.visit(node.node)
        
        # Сохраняем состояние после if
        if_state = self.taint_state.copy()
        
        # Восстанавливаем состояние для анализа else
        self.taint_state = old_state
        
        # Анализируем elseif
        for elseif in node.elseifs:
            self.visit(elseif)
        
        # Анализируем else
        if node.else_:
            self.visit(node.else_)
        
        # Объединяем состояния
        self.taint_state.merge(if_state)
    
    def visit_elseif(self, node: ElseIf):
        """Обработка elseif."""
        self.visit(node.expr)
        if node.node:
            self.visit(node.node)
    
    def visit_else(self, node: Else):
        """Обработка else."""
        if node.node:
            self.visit(node.node)
    
    def analyze(self, ast: List[Node], file_path: Optional[Path] = None, content: Optional[str] = None) -> List[Vulnerability]:
        """
        Запускает анализ AST.
        
        Args:
            ast: абстрактное синтаксическое дерево
            file_path: путь к файлу
            content: исходное содержимое файла для нормализации строк
        """
        self.vulnerabilities = []
        self.taint_state = TaintState()
        self.content_lines = content.split('\n') if content else None
        
        for node in ast:
            self.visit(node)
        
        # Добавляем информацию о файле и нормализуем строки
        for v in self.vulnerabilities:
            if file_path:
                v.location.file_path = file_path
            if self.content_lines and v.location.line > 0:
                # Нормализация: phply может давать строки с 0 или со смещением
                # Пробуем найти правильную строку по содержимому
                self._normalize_line_number(v)
        
        return self.vulnerabilities
    
    def _normalize_line_number(self, vuln: Vulnerability):
        """
        Нормализует номер строки, сопоставляя с реальным содержимым.
        """
        if not self.content_lines or vuln.location.line <= 0:
            return
        
        original_line = vuln.location.line
        
        # Стратегия 1: если строка содержит наш код (без комментариев)
        for i, line in enumerate(self.content_lines, 1):
            if vuln.location.line_content and vuln.location.line_content in line:
                # Нашли точное совпадение содержимого
                vuln.location.line = i
                vuln.location.line_content = line.strip()
                print(f"DEBUG: Нормализация строки {original_line} -> {i} (по содержимому)")
                return
        
        # Стратегия 2: если phply даёт строки с 0 (прибавляем 1)
        if original_line == 0:
            vuln.location.line = 1
            print(f"DEBUG: Нормализация строки 0 -> 1")
            return
        
        # Стратегия 3: пробуем смещение, которое мы наблюдаем (-2)
        # Но сделаем это умно - проверим, попадает ли строка в диапазон
        candidate = original_line - 2
        if 1 <= candidate <= len(self.content_lines):
            # Проверим, похоже ли содержимое
            if candidate <= len(self.content_lines):
                line_content = self.content_lines[candidate - 1].strip()
                # Если строка не пустая и содержит PHP-код
                if line_content and ('$' in line_content or 'echo' in line_content or 'print' in line_content):
                    vuln.location.line = candidate
                    vuln.location.line_content = line_content
                    print(f"DEBUG: Нормализация строки {original_line} -> {candidate} (по смещению -2)")
                    return
        
        print(f"DEBUG: Не удалось нормализовать строку {original_line}, оставляем как есть")
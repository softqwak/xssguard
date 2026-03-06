"""
PHP анализатор для XSSGuard
"""

from pathlib import Path
from typing import List, Optional
import phply.phpparse as phpparse
from phply.phplex import lexer

from ...models.vulnerability import Vulnerability
from ...models.config import PHPConfig
from .ast_visitor import PHPVisitor

class PHPAnalyzer:
    """
    Анализатор PHP файлов с использованием phply.
    """
    
    def __init__(self, config: Optional[PHPConfig], logger):
        """
        Args:
            config: объект PHPConfig, если None - используются настройки по умолчанию
        """
        self.config = config or PHPConfig()
        self.name = 'php_analyzer'
        self.logger = logger
        self.file_extensions = ['.php', '.phtml', '.php5', '.php7']
    
    def can_analyze(self, file_path: Path) -> bool:
        """Проверяет, может ли анализатор обработать файл."""
        return file_path.suffix in self.file_extensions
    
    def analyze(self, file_path: Path, logger) -> List[Vulnerability]:
        """
        Анализирует PHP файл и возвращает список уязвимостей.
        """
        logger.debug(f"Начало анализа", file=str(file_path))
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
            
            # Проверка размера файла
            if len(content) > 10 * 1024 * 1024:  # 10MB
                return []
            
            # Создаём парсер и парсим код
            parser = phpparse.make_parser()
            ast = parser.parse(content, lexer=lexer)
            
            # Если ast None, значит ошибка парсинга
            if ast is None:
                logger.warning("Ошибка парсинга", file=str(file_path))
                return []
            
            visitor = PHPVisitor(self.config, logger)
            vulnerabilities = visitor.analyze(ast, file_path, content)
            logger.info(f"Найдено уязвимостей: {len(vulnerabilities)}", 
                       file=str(file_path))
            # Добавляем содержимое строк для отчёта
            lines = content.split('\n')
            for v in vulnerabilities:
                if 0 < v.location.line <= len(lines):
                    v.location.line_content = lines[v.location.line - 1].strip()
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Ошибка: {e}", file=str(file_path), exc_info=True)
            return []
    
    def get_supported_extensions(self) -> List[str]:
        """Возвращает список поддерживаемых расширений."""
        return self.file_extensions
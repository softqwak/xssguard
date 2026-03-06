"""
Менеджер плагинов - определяет подходящий анализатор для файла.
"""

from pathlib import Path
from typing import Optional, List
from ..models.vulnerability import Vulnerability
from ..models.config import XSSGuardConfig, PHPConfig
from ..utils.logger_factory import LoggerFactory
# Импортируем доступные анализаторы
from .php import PHPAnalyzer
# from .js import JSAnalyzer      # для будущего
# from .html import HTMLAnalyzer   # для будущего


class PluginManager:
    """
    Менеджер плагинов.
    Определяет подходящий анализатор для файла и управляет их конфигурацией.
    """
    
    def __init__(self, config: XSSGuardConfig, logger_factory: LoggerFactory):
        """
        Args:
            config: главная конфигурация приложения
        """
        self.config = config
        self.analyzers = []
        
        
        # PHP анализатор
        php_config = config.get_language_config('php')
        if php_config:
            php_logger = logger_factory.create_logger("php_plugin")
            self.analyzers.append(PHPAnalyzer(config=php_config, logger=php_logger))
        # TODO: добавить JavaScript анализатор
        # TODO: добавить HTML анализатор
    
    def get_analyzer_for_file(self, file_path: Path) -> Optional:
        """
        Возвращает подходящий анализатор для файла или None.
        """
        for analyzer in self.analyzers:
            if analyzer.can_analyze(file_path):
                return analyzer
        return None
    
    def analyze_file(self, file_path: Path, logger) -> List[Vulnerability]:
        """Анализирует файл с переданным логгером"""
        for analyzer in self.analyzers:
            if analyzer.can_analyze(file_path):
                return analyzer.analyze(file_path, logger)
        return []
    
    def get_supported_extensions(self) -> List[str]:
        """
        Собирает все поддерживаемые расширения от всех анализаторов.
        """
        extensions = []
        for analyzer in self.analyzers:
            if hasattr(analyzer, 'get_supported_extensions'):
                extensions.extend(analyzer.get_supported_extensions())
        return list(set(extensions))
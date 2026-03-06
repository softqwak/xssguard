# xssguard/utils/logger.py

import logging
from pathlib import Path
from datetime import datetime
from logging.handlers import RotatingFileHandler
from typing import Optional, Dict, Any
from ..models.config import LoggingConfig


class XSSLogger:
    """
    Инстанс логгера для конкретного компонента.
    Не глобальный - передаётся через конструкторы.
    """
    
    def __init__(self, 
                 name: str,
                 config: LoggingConfig,
                 component: str):
        """
        Args:
            name: уникальное имя логгера (обычно с timestamp)
            config: конфигурация логирования
            component: имя компонента (core, php_plugin, scanner и т.д.)
        """
        self.component = component
        self.config = config
        self.logger = self._setup_logger(name)
    
    def _setup_logger(self, name: str) -> Optional[logging.Logger]:
        """Создаёт и настраивает логгер"""
        if not self.config.enabled:
            return None
        
        # Создаём директорию для логов
        self.config.directory.mkdir(parents=True, exist_ok=True)
        
        # Имя файла с датой запуска
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = self.config.directory / f"xssguard_{timestamp}.log"
        
        # Создаём логгер
        logger = logging.getLogger(f"{name}_{self.component}")
        logger.setLevel(getattr(logging, self.config.level.upper()))
        
        # Хендлер с ротацией
        handler = RotatingFileHandler(
            log_file,
            maxBytes=self.config.max_file_size,
            backupCount=self.config.backup_count,
            encoding='utf-8'
        )
        
        # Формат
        if self.config.format == 'simple':
            formatter = logging.Formatter(
                '%(asctime)s | %(message)s',
                datefmt='%H:%M:%S'
            )
        else:
            formatter = logging.Formatter(
                '%(asctime)s | %(levelname)-8s | [%(name)s] | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
        
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        logger.info(f"=== Логгер инициализирован для {self.component} ===")
        
        return logger
    
    def debug(self, msg: str, **kwargs):
        if self.logger:
            extra = f" | {kwargs}" if kwargs else ""
            self.logger.debug(f"[{self.component}] {msg}{extra}")
    
    def info(self, msg: str, **kwargs):
        if self.logger:
            extra = f" | {kwargs}" if kwargs else ""
            self.logger.info(f"[{self.component}] {msg}{extra}")
    
    def warning(self, msg: str, **kwargs):
        if self.logger:
            extra = f" | {kwargs}" if kwargs else ""
            self.logger.warning(f"[{self.component}] {msg}{extra}")
    
    def error(self, msg: str, **kwargs):
        if self.logger:
            extra = f" | {kwargs}" if kwargs else ""
            self.logger.error(f"[{self.component}] {msg}{extra}", 
                             exc_info=kwargs.get('exc_info', False))
    
    def child(self, subcomponent: str) -> 'XSSLogger':
        """
        Создаёт дочерний логгер для подкомпонента.
        Полезно для плагинов и многопоточности.
        """
        if self.logger:
            child_name = f"{self.logger.name}.{subcomponent}"
        else:
            child_name = f"disabled.{subcomponent}"
        
        return XSSLogger(
            name=child_name,
            config=self.config,
            component=f"{self.component}.{subcomponent}"
        )
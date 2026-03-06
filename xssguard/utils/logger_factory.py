# xssguard/utils/logger_factory.py

from typing import Dict
import threading
from .logger import XSSLogger
from ..models.config import LoggingConfig


class LoggerFactory:
    """
    Фабрика для создания логгеров в разных потоках.
    Не хранит глобальное состояние, только конфиг.
    """
    
    def __init__(self, config: LoggingConfig):
        self.config = config
        self._base_name = f"xssguard_{threading.get_native_id()}"
    
    def create_logger(self, component: str) -> XSSLogger:
        """
        Создаёт новый логгер для компонента.
        Безопасно вызывать из любого потока.
        """
        return XSSLogger(
            name=f"{self._base_name}_{threading.current_thread().name}",
            config=self.config,
            component=component
        )
    
    def create_thread_logger(self, thread_name: str, component: str) -> XSSLogger:
        """
        Создаёт логгер для конкретного потока.
        """
        return XSSLogger(
            name=f"thread_{thread_name}",
            config=self.config,
            component=component
        )
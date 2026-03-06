"""
Главный сканер - управляет процессом анализа.
"""

from pathlib import Path
from typing import List, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed

from ..models.vulnerability import Vulnerability
from ..models.report import ScanReport
from ..models.config import XSSGuardConfig
from ..plugins import PluginManager
from ..utils.logger_factory import LoggerFactory 

class Scanner:
    """
    Главный сканер - управляет процессом анализа.
    """
    
    def __init__(self, config: XSSGuardConfig, logger_factory: LoggerFactory):
        """
        Args:
            config: главная конфигурация приложения
        """
        self.config = config
        self.logger_factory = logger_factory
        self.logger = logger_factory.create_logger("scanner")
        self.plugin_manager = PluginManager(config, logger_factory)
    
    def scan_path(self, path: Path) -> ScanReport:
        """
        Сканирует файл или директорию.
        
        Args:
            path: путь к файлу или директории
            
        Returns:
            ScanReport: отчёт о сканировании
        """
        report = ScanReport()
        report.scanned_paths = [path]
        report.config_used = self.config.to_dict()
        
        self.logger.info(f"Начало сканирования: {path}")
        
        files = self._collect_files(path)
        
        self.logger.info(f"Найдено файлов: {len(files)}")        
        report.summary.total_files = len(files)
        
        # Анализируем файлы
        vulnerabilities = []
        
        # Многопоточный анализ
        with ThreadPoolExecutor(max_workers=self.config.scan.threads) as executor:
            future_to_file = {}
            
            for file_path in files:
                # Для каждого потока создаём свой логгер
                thread_logger = self.logger_factory.create_thread_logger(
                    thread_name=f"worker-{file_path.name}",
                    component="scanner.worker"
                )
                
                future = executor.submit(
                    self._analyze_file,
                    file_path,
                    thread_logger
                )
                future_to_file[future] = file_path
            
            # Собираем результаты
            for future in as_completed(future_to_file):
                file_path = future_to_file[future]
                try:
                    vulns = future.result()
                    if vulns:
                        self.logger.warning(f"Найдено уязвимостей в {file_path.name}: {len(vulns)}")
                        vulnerabilities.extend(vulns)
                    report.summary.scanned_files += 1
                except Exception as e:
                    self.logger.error(f"Ошибка при анализе {file_path}: {e}", exc_info=True)
        
        
        
        report.add_vulnerabilities(vulnerabilities)
        report.complete()
        
        return report
    
    def _analyze_file(self, file_path: Path, logger) -> List[Vulnerability]:
        """
        Анализирует один файл в потоке.
        
        Args:
            file_path: путь к файлу
            logger: логгер для этого потока
            
        Returns:
            список уязвимостей
        """
        logger.debug(f"Анализ файла", file=str(file_path))
        return self.plugin_manager.analyze_file(file_path, logger)
    
    def _collect_files(self, directory: Path) -> List[Path]:
        """
        Рекурсивно собирает все файлы с поддерживаемыми расширениями.
        """
        supported_extensions = self.plugin_manager.get_supported_extensions()
        exclude_patterns = self.config.scan.exclude_paths
        
        print(f"🔧 Отладка: ищем файлы с расширениями {supported_extensions}")
        print(f"🔧 Отладка: исключаем паттерны {exclude_patterns}")
        
        files = []
        
        for ext in supported_extensions:
            for file_path in directory.rglob(f'*{ext}'):
                print(f"🔧 Найден файл: {file_path}")
                if not self._is_excluded(file_path, exclude_patterns):
                    if file_path.stat().st_size <= self.config.scan.max_file_size:
                        files.append(file_path)
                        print(f"🔧 Файл добавлен: {file_path}")
                    else:
                        print(f"🔧 Файл слишком большой: {file_path}")
                else:
                    print(f"🔧 Файл исключён: {file_path}")
        
        print(f"🔧 Всего найдено файлов: {len(files)}")
        return files
    
    def _is_excluded(self, file_path: Path, exclude_patterns: List[str]) -> bool:
        """
        Проверяет, исключён ли файл по паттернам.
        Простая реализация - проверяет вхождение подстроки.
        TODO: использовать fnmatch для полноценных паттернов
        """
        str_path = str(file_path).replace('\\', '/')
        for pattern in exclude_patterns:
            pattern = pattern.replace('\\', '/')
            # Простейшая проверка
            if pattern in str_path or pattern.rstrip('/*') in str_path:
                return True
        return False
"""
Модели для конфигурации анализатора.
Поддерживает расширение за счёт регистрации конфигов для разных языков.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Type
from pathlib import Path
import yaml
from abc import ABC, abstractmethod


class LanguageConfig(ABC):
    """
    Базовый абстрактный класс для конфигурации языка.
    Все конфиги языков должны наследоваться от него.
    """
    
    @abstractmethod
    def get_language_name(self) -> str:
        """Возвращает название языка (php, javascript, html)"""
        pass
    
    @abstractmethod
    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует конфиг в словарь для сериализации"""
        pass
    
    @classmethod
    @abstractmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'LanguageConfig':
        """Создаёт конфиг из словаря"""
        pass


@dataclass
class PHPConfig(LanguageConfig):
    """Конфигурация PHP анализатора"""
    
    sources: List[str] = field(default_factory=lambda: [
        '$_GET', '$_POST', '$_REQUEST', '$_COOKIE', '$_FILES'
    ])
    sinks: List[str] = field(default_factory=lambda: [
        'echo', 'print', 'printf', 'vprintf', '<?='
    ])
    sanitizers: List[str] = field(default_factory=lambda: [
        'htmlspecialchars', 'htmlentities', 'strip_tags', 'filter_var'
    ])
    user_input_functions: List[str] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=lambda: {
        'track_array_elements': True,
        'track_object_properties': False,
        'max_call_depth': 3,
        'analyze_includes': False,
        'case_sensitive': True
    })
    
    def get_language_name(self) -> str:
        return 'php'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'sources': self.sources,
            'sinks': self.sinks,
            'sanitizers': self.sanitizers,
            'user_input_functions': self.user_input_functions,
            'options': self.options
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'PHPConfig':
        return cls(
            sources=data.get('sources', cls.sources),
            sinks=data.get('sinks', cls.sinks),
            sanitizers=data.get('sanitizers', cls.sanitizers),
            user_input_functions=data.get('user_input_functions', []),
            options=data.get('options', cls.options)
        )


@dataclass
class JavaScriptConfig(LanguageConfig):
    """Конфигурация JavaScript анализатора (заготовка)"""
    
    sources: List[str] = field(default_factory=lambda: [
        'window.location', 'document.URL', 'location.hash', 
        'document.referrer', 'localStorage', 'sessionStorage'
    ])
    sinks: List[str] = field(default_factory=lambda: [
        'innerHTML', 'outerHTML', 'document.write', 'eval'
    ])
    sanitizers: List[str] = field(default_factory=lambda: [
        'textContent', 'encodeURI', 'encodeURIComponent'
    ])
    options: Dict[str, Any] = field(default_factory=dict)
    
    def get_language_name(self) -> str:
        return 'javascript'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'sources': self.sources,
            'sinks': self.sinks,
            'sanitizers': self.sanitizers,
            'options': self.options
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'JavaScriptConfig':
        return cls(
            sources=data.get('sources', cls.sources),
            sinks=data.get('sinks', cls.sinks),
            sanitizers=data.get('sanitizers', cls.sanitizers),
            options=data.get('options', cls.options)
        )


@dataclass
class HTMLConfig(LanguageConfig):
    """Конфигурация HTML анализатора (заготовка)"""
    
    dangerous_attributes: List[str] = field(default_factory=lambda: [
        'onload', 'onerror', 'onclick', 'onmouseover', 'onfocus'
    ])
    dangerous_tags: List[str] = field(default_factory=lambda: [
        'script', 'iframe', 'object', 'embed'
    ])
    options: Dict[str, Any] = field(default_factory=dict)
    
    def get_language_name(self) -> str:
        return 'html'
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'dangerous_attributes': self.dangerous_attributes,
            'dangerous_tags': self.dangerous_tags,
            'options': self.options
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'HTMLConfig':
        return cls(
            dangerous_attributes=data.get('dangerous_attributes', cls.dangerous_attributes),
            dangerous_tags=data.get('dangerous_tags', cls.dangerous_tags),
            options=data.get('options', cls.options)
        )


class ConfigRegistry:
    """
    Реестр конфигураций языков.
    Позволяет регистрировать новые языки без изменения кода.
    """
    
    def __init__(self):
        self._config_classes: Dict[str, Type[LanguageConfig]] = {}
    
    def register(self, language: str, config_class: Type[LanguageConfig]):
        """
        Регистрирует класс конфигурации для языка.
        
        Args:
            language: название языка (php, javascript, html)
            config_class: класс конфигурации, наследник LanguageConfig
        """
        self._config_classes[language] = config_class
    
    def get_config_class(self, language: str) -> Optional[Type[LanguageConfig]]:
        """Возвращает класс конфигурации для языка"""
        return self._config_classes.get(language)
    
    def get_all_languages(self) -> List[str]:
        """Возвращает список всех зарегистрированных языков"""
        return list(self._config_classes.keys())
    
    def create_config(self, language: str, data: Dict[str, Any]) -> Optional[LanguageConfig]:
        """
        Создаёт экземпляр конфигурации для языка из словаря.
        """
        config_class = self.get_config_class(language)
        if config_class:
            return config_class.from_dict(data)
        return None


# Создаём глобальный экземпляр реестра
config_registry = ConfigRegistry()

# Регистрируем встроенные языки
config_registry.register('php', PHPConfig)
config_registry.register('javascript', JavaScriptConfig)
config_registry.register('html', HTMLConfig)


@dataclass
class ScanConfig:
    """Настройки сканирования"""
    exclude_paths: List[str] = field(default_factory=lambda: [
        'vendor/**', 'node_modules/**', 'tests/**', '*.min.js', '*.min.css'
    ])
    file_extensions: List[str] = field(default_factory=lambda: [
        '.php', '.js', '.html', '.phtml'
    ])
    max_file_size: int = 5 * 1024 * 1024  # 5MB
    threads: int = 4
    follow_symlinks: bool = False
    timeout: int = 30  # секунд на файл


@dataclass
class OutputConfig:
    """Настройки вывода"""
    format: str = 'console'  # console, json, html
    verbose: bool = False
    show_info: bool = True
    show_warnings: bool = True
    show_progress: bool = True
    color: bool = True
    output_file: Optional[Path] = None

@dataclass
class LoggingConfig:
    """Настройки логирования"""
    enabled: bool = True
    directory: Path = field(default_factory=lambda: Path("logs"))
    level: str = "INFO"  # DEBUG, INFO, WARNING, ERROR
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    backup_count: int = 5
    format: str = "detailed"  # simple, detailed

    def __post_init__(self):
        if isinstance(self.directory, str):
            self.directory = Path(self.directory)

@dataclass
class XSSGuardConfig:
    """
    Главная конфигурация всего приложения.
    Содержит настройки для всех языков и общие настройки.
    """
    
    languages: Dict[str, LanguageConfig] = field(default_factory=dict)
    scan: ScanConfig = field(default_factory=ScanConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    logging: LoggingConfig = field(default_factory=LoggingConfig)
    
    def __post_init__(self):
        """Инициализация с настройками по умолчанию для зарегистрированных языков"""
        if not self.languages:
            for lang in config_registry.get_all_languages():
                config_class = config_registry.get_config_class(lang)
                if config_class:
                    self.languages[lang] = config_class()
    
    def get_language_config(self, language: str) -> Optional[LanguageConfig]:
        """Возвращает конфигурацию для указанного языка"""
        return self.languages.get(language)
    
    def register_language_config(self, language: str, config: LanguageConfig):
        """Регистрирует конфигурацию для языка"""
        self.languages[language] = config
    
    def to_dict(self) -> Dict[str, Any]:
        """Конвертирует всю конфигурацию в словарь"""
        result = {
            'scan': {
                'exclude_paths': self.scan.exclude_paths,
                'file_extensions': self.scan.file_extensions,
                'max_file_size': self.scan.max_file_size,
                'threads': self.scan.threads,
                'follow_symlinks': self.scan.follow_symlinks,
                'timeout': self.scan.timeout
            },
            'output': {
                'format': self.output.format,
                'verbose': self.output.verbose,
                'show_info': self.output.show_info,
                'show_warnings': self.output.show_warnings,
                'show_progress': self.output.show_progress,
                'color': self.output.color
            }
        }
        
        for lang, config in self.languages.items():
            result[lang] = config.to_dict()
        
        return result
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'XSSGuardConfig':
        """Создаёт конфигурацию из словаря"""
        config = cls()
        
        if 'scan' in data:
            scan_data = data['scan']
            if 'exclude_paths' in scan_data:
                config.scan.exclude_paths = scan_data['exclude_paths']
            if 'file_extensions' in scan_data:
                config.scan.file_extensions = scan_data['file_extensions']
            if 'max_file_size' in scan_data:
                config.scan.max_file_size = scan_data['max_file_size']
            if 'threads' in scan_data:
                config.scan.threads = scan_data['threads']
            if 'follow_symlinks' in scan_data:
                config.scan.follow_symlinks = scan_data['follow_symlinks']
            if 'timeout' in scan_data:
                config.scan.timeout = scan_data['timeout']
        
        if 'output' in data:
            output_data = data['output']
            if 'format' in output_data:
                config.output.format = output_data['format']
            if 'verbose' in output_data:
                config.output.verbose = output_data['verbose']
            if 'show_info' in output_data:
                config.output.show_info = output_data['show_info']
            if 'show_warnings' in output_data:
                config.output.show_warnings = output_data['show_warnings']
            if 'show_progress' in output_data:
                config.output.show_progress = output_data['show_progress']
            if 'color' in output_data:
                config.output.color = output_data['color']
        
        # Загрузка логирования
        if 'logging' in data:
            log_data = data['logging']
            if 'enabled' in log_data:
                config.logging.enabled = log_data['enabled']
            if 'directory' in log_data:
                config.logging.directory = Path(log_data['directory'])
            if 'level' in log_data:
                config.logging.level = log_data['level']
            if 'max_file_size' in log_data:
                config.logging.max_file_size = log_data['max_file_size']
            if 'backup_count' in log_data:
                config.logging.backup_count = log_data['backup_count']
            if 'format' in log_data:
                config.logging.format = log_data['format']
        
        for lang in config_registry.get_all_languages():
            if lang in data:
                config_class = config_registry.get_config_class(lang)
                if config_class:
                    config.languages[lang] = config_class.from_dict(data[lang])
        
        return config
    
    @classmethod
    def from_yaml(cls, yaml_path: Path) -> 'XSSGuardConfig':
        """Загружает конфигурацию из YAML файла"""
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        return cls.from_dict(data or {})
    
    def to_yaml(self, path: Path):
        """Сохраняет конфигурацию в YAML файл"""
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(self.to_dict(), f, default_flow_style=False, allow_unicode=True)
    
    @property
    def custom_rules(self) -> Dict[str, Any]:
        """
        Для обратной совместимости с плагинами, ожидающими словарь.
        Возвращает правила в старом формате.
        """
        result = {}
        for lang, config in self.languages.items():
            result[lang] = config.to_dict()
        return result
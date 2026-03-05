"""
Модели для конфигурации анализатора
"""
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Dict, Any
import yaml


@dataclass
class OutputConfig:
    """Настройки вывода"""
    format: str = "console"  # console, json, html
    verbose: bool = False
    show_info: bool = True
    show_warnings: bool = True
    output_file: Optional[Path] = None
    color: bool = True


@dataclass
class ScanConfig:
    """Настройки сканирования"""
    paths: List[Path] = field(default_factory=list)
    exclude_paths: List[str] = field(default_factory=lambda: ["vendor/**", "node_modules/**"])
    follow_symlinks: bool = False
    max_file_size: int = 10 * 1024 * 1024  # 10MB
    file_extensions: List[str] = field(default_factory=lambda: [".php", ".js", ".html", ".phtml"])
    threads: int = 4
    
    # Лимиты
    timeout: int = 30  # секунд на файл
    max_files: int = 10000  # максимальное количество файлов


@dataclass
class XSSGuardConfig:
    """Главная конфигурация"""
    scan: ScanConfig = field(default_factory=ScanConfig)
    output: OutputConfig = field(default_factory=OutputConfig)
    rules_path: Optional[Path] = None
    custom_rules: Dict[str, Any] = field(default_factory=dict)
    
    @classmethod
    def from_yaml(cls, yaml_path: Path) -> "XSSGuardConfig":
        """Загрузить конфигурацию из YAML файла"""
        with open(yaml_path, 'r', encoding='utf-8') as f:
            data = yaml.safe_load(f)
        
        config = cls()
        
        # Обновляем конфиг из данных
        if data:
            if 'scan' in data:
                for key, value in data['scan'].items():
                    if hasattr(config.scan, key):
                        setattr(config.scan, key, value)
            if 'output' in data:
                for key, value in data['output'].items():
                    if hasattr(config.output, key):
                        setattr(config.output, key, value)
        
        return config
    
    def to_yaml(self, path: Path):
        """Сохранить конфигурацию в YAML"""
        data = {
            'scan': {
                'exclude_paths': self.scan.exclude_paths,
                'file_extensions': self.scan.file_extensions,
                'threads': self.scan.threads
            },
            'output': {
                'format': self.output.format,
                'verbose': self.output.verbose,
                'color': self.output.color
            }
        }
        with open(path, 'w', encoding='utf-8') as f:
            yaml.dump(data, f, default_flow_style=False)
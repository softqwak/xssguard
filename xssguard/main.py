#!/usr/bin/env python
"""
XSSGuard - Главный модуль запуска
"""

import sys
import click
from pathlib import Path
from datetime import datetime

from xssguard.models.vulnerability import Vulnerability, Severity
from xssguard.models.config import XSSGuardConfig
from xssguard.models.report import ScanReport
from xssguard.core.scanner import Scanner
from xssguard.utils.logger_factory import LoggerFactory

__version__ = "0.1.0"


@click.group()
def cli():
    """XSSGuard - статический анализатор для обнаружения XSS уязвимостей"""
    pass


@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--config', '-c', type=click.Path(), help='Путь к конфигурационному файлу .yml')
@click.option('--output', '-o', type=click.Path(), help='Путь для сохранения отчета')
@click.option('--format', '-f', type=click.Choice(['console', 'json', 'html']), default='console')
@click.option('--verbose', '-v', is_flag=True, help='Подробный вывод')
def scan(path, config, output, format, verbose):
    """Запустить сканирование директории или файла"""
    
    # Загружаем конфигурацию
    config_obj = XSSGuardConfig()
    if config:
        config_path = Path(config)
        if config_path.exists():
            config_obj = XSSGuardConfig.from_yaml(config_path)
    
    # Создаём фабрику логгеров
    logger_factory = LoggerFactory(config_obj.logging)
    
    # Создаём основной логгер
    main_logger = logger_factory.create_logger("main")
    main_logger.info(f"Запуск сканирования: {path}")
    main_logger.info(f"Конфиг: {config or 'default'}")
    
    
    # Создаём сканер и запускаем анализ
    scanner = Scanner(config_obj, logger_factory=logger_factory)
    report = scanner.scan_path(Path(path))
    
    main_logger.info(f"Сканирование завершено. Найдено уязвимостей: {report.summary.total_vulnerabilities}")
    
    # Вывод результатов
    click.echo(f"🔍 XSSGuard Scan v{__version__}")
    click.echo(f"📁 Path: {path}")
    click.echo(f"⚙️  Config: {config or 'default'}")
    click.echo(f"{'='*50}")
    
    click.echo(f"\n📊 Scan Summary:")
    click.echo(f"   Files scanned: {report.summary.scanned_files}")
    click.echo(f"   Vulnerabilities found: {report.summary.total_vulnerabilities}")
    
    for severity, count in report.summary.by_severity.items():
        color = {
            Severity.CRITICAL: 'red',
            Severity.HIGH: 'red',
            Severity.MEDIUM: 'yellow',
            Severity.LOW: 'blue',
            Severity.INFO: 'green'
        }.get(severity, 'white')
        
        click.secho(f"     {severity.value.capitalize()}: {count}", fg=color)
    
    # Показываем уязвимости
    if report.vulnerabilities and (verbose or report.summary.total_vulnerabilities > 0):
        click.echo(f"\n⚠️  Vulnerabilities:")
        for v in report.vulnerabilities[:10]:  # Покажем первые 10
            click.secho(f"  [{v.severity.value.upper()}] ", nl=False, fg='red')
            click.echo(f"{v.location}")
            if verbose:
                click.echo(f"     → {v.title}")
                if v.location.line_content:
                    click.echo(f"     `{v.location.line_content}`")
    
    # Сохраняем отчет
    if output:
        output_path = Path(output)
        if format == 'json':
            import json
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report.to_dict(), f, indent=2, ensure_ascii=False)
            click.echo(f"\n✅ Report saved to: {output_path}")
    
    # Возвращаем код ошибки если есть уязвимости
    if report.summary.total_vulnerabilities > 0:
        sys.exit(1)


@cli.command()
def version():
    """Показать версию"""
    click.echo(f"XSSGuard version {__version__}")


@cli.command()
def init_config():
    """Создать пример конфигурационного файла"""
    config = XSSGuardConfig()
    config_path = Path("xssguard.yml")
    config.to_yaml(config_path)
    click.echo(f"✅ Пример конфигурации создан: {config_path}")
    click.echo(f"📄 Отредактируйте {config_path} под свои нужды")


if __name__ == '__main__':
    cli()
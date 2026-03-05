#!/usr/bin/env python
"""
XSSGuard - Главный модуль запуска
"""

import sys
import click
from pathlib import Path
from typing import Optional
from datetime import datetime

from xssguard.models.vulnerability import Vulnerability, Severity, VulnerabilityType, Confidence
from xssguard.models.config import XSSGuardConfig
from xssguard.models.report import ScanReport


@click.group()
def cli():
    """XSSGuard - статический анализатор для обнаружения XSS уязвимостей"""
    pass

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--config', '-c', type=click.Path(), help='Путь к конфигурационному файлу c расширением .yml')
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
    
    # Создаем отчет
    report = ScanReport()
    report.scanned_paths = [Path(path)]
    
    click.echo(f"🔍 XSSGuard Scan v0.1.0")
    click.echo(f"📁 Path: {path}")
    click.echo(f"⚙️  Config: {config or 'default'}")
    click.echo(f"{'='*50}")
    
    # TODO: Здесь будет логика сканирования
    
    # Для демонстрации создадим тестовую уязвимость
    if verbose:
        from xssguard.models.vulnerability import CodeLocation
        
        vuln = Vulnerability(
            type=VulnerabilityType.REFLECTED_XSS,
            severity=Severity.HIGH,
            confidence=Confidence.MEDIUM,
            location=CodeLocation(
                file_path=Path(path) / "test.php",
                line=42,
                line_content='echo $_GET["user"];',
                column=5
            ),
            title="Reflected XSS vulnerability",
            description="User input from $_GET is directly echoed without sanitization",
            tags=["reflected", "php"],
            analyzer_name="demo"
        )
        report.add_vulnerabilities([vuln])
    
    # Завершаем отчет
    report.complete()
    
    # Выводим результаты
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
    if report.vulnerabilities and verbose:
        click.echo(f"\n⚠️  Vulnerabilities:")
        for v in report.vulnerabilities[:5]:  # Покажем первые 5
            click.secho(f"  [{v.severity.value.upper()}] ", nl=False, fg='red')
            click.echo(f"{v.location}")
            click.echo(f"     → {v.title}")
    
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
    from xssguard import __version__
    click.echo(f"XSSGuard version {__version__}")

@cli.command()
def init_config():
    """Создать пример конфигурационного файла"""
    config = XSSGuardConfig()
    config_path = Path("xssguard.yml")
    config.to_yaml(config_path)
    click.echo(f"✅ Пример конфигурации создан: {config_path}")

if __name__ == '__main__':
    cli()
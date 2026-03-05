
import pytest
from pathlib import Path
from xssguard.main import cli
from click.testing import CliRunner

def test_cli_version():
    """Тест команды version"""
    runner = CliRunner()
    result = runner.invoke(cli, ['version'])
    assert result.exit_code == 0
    assert 'XSSGuard версия' in result.output

def test_cli_scan_nonexistent():
    """Тест сканирования несуществующего пути"""
    runner = CliRunner()
    result = runner.invoke(cli, ['scan', '/nonexistent/path'])
    assert result.exit_code != 0  # Должна быть ошибка
# Быстрый старт

## Первый запуск

Создайте тестовый файл с уязвимостью:

```php
<?php
// test.php
$name = $_GET['name'];
echo "Привет, " . $name . "!";
?>
```

Запустите анализ:

```bash
xssguard scan test.php
```

Ожидаемый вывод:

```text
🔍 Сканирование: test.php
⚠️  Найдена уязвимость: Reflected XSS в строке 3
   Данные из $_GET выводятся через echo без фильтрации
```

## Сканирование проекта
```bash
# Сканировать текущую папку
xssguard scan .

# Сканировать конкретную папку
xssguard scan /var/www/html

# С подробным выводом
xssguard scan ./project --verbose
```

## Сохранение результатов
```bash
# В JSON файл
xssguard scan . --output report.json --format json

# В HTML отчет
xssguard scan . --output report.html --format html
```

## Что дальше?
* <a id="./user-guide/commands.md">Изучить все команды</a>
* <a id="./user-guide/configuration.md">Настроить конфигурацию</a>
* <a id="./user-guide/results.md">Понять результаты анализа</a>
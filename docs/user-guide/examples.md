# Примеры использования

## Пример 1: Сканирование небольшого сайта

```bash
# Проект: интернет-магазин на PHP
xssguard scan ./shop --verbose
```

**Результат:**
```text
Найдено 5 уязвимостей:
1. [HIGH] cart.php:42 - Прямой вывод $_POST['product_id']
2. [MEDIUM] search.php:15 - Поисковый запрос без фильтрации
3. [LOW] profile.php:89 - Вывод имени пользователя
```
## Пример 2: Интеграция с CI/CD (GitHub Actions)
Создайте файл `.github/workflows/security.yml`:

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  xss-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.10'
      
      - name: Install XSSGuard
        run: |
          pip install -e .
      
      - name: Run XSS Scan
        run: |
          xssguard scan ./src --format json --output report.json
          
      - name: Upload Report
        uses: actions/upload-artifact@v2
        with:
          name: xss-report
          path: report.json
```
## Пример 3: Кастомные правила для фреймворка
Для Laravel создайте `laravel-rules.yml`:

```yaml
rules:
  php:
    sources:
      - "$request->input()"
      - "$request->get()"
      - "$request->all()"
    sinks:
      - "echo"
      - "{{ }}"
      - "{!! !!}"
    sanitizers:
      - "e()"
      - "htmlentities"
      - "strip_tags"

scan:
  file_extensions: [".php", ".blade.php"]
```
Запуск:
```bash
xssguard scan ./laravel-project --config laravel-rules.yml
```
## Пример 4: Сравнение с другими инструментами
|Инструмент	|XSSGuard	|SonarQube	|ESLint|
|-----------|-----------|-----------|------|
|XSS анализ|	    +++|            ++|     +|
Автономность|	    ✅|	        ❌|     ✅|
PHP поддержка|	    ✅|	        ✅|     ❌|
Настройка правил|	YAML|	    GUI|	JSON|
Скорость|	~1000 файлов/сек|	~100 файлов/сек|	~500 файлов/сек|

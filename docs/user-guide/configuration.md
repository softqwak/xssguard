# Конфигурация

## Файл конфигурации

XSSGuard использует YAML файлы для настройки. Создайте файл `xssguard.yml`:

```bash
xssguard init-config
```

## Базовая структура
```yaml
# Настройки сканирования
scan:
  exclude_paths:              # Папки для исключения
    - "vendor/**"
    - "node_modules/**"
    - "tests/**"
  file_extensions:            # Какие файлы проверять
    - ".php"
    - ".js"
    - ".html"
    - ".phtml"
  threads: 4                   # Количество потоков
  max_file_size: 10485760      # 10MB - файлы больше пропускаем

# Настройки вывода
output:
  format: console              # console, json, html
  verbose: false               # Подробный вывод
  color: true                  # Цветной вывод
  show_info: true              # Показывать информационные сообщения
  show_warnings: true          # Показывать предупреждения

# Правила для языков
rules:
  php:
    enabled: true
    dangerous_functions:       # Опасные функции вывода
      - "echo"
      - "print"
      - "printf"
      - "<?="
    sources:                    # Источники данных
      - "$_GET"
      - "$_POST"
      - "$_REQUEST"
      - "$_COOKIE"
  
  javascript:
    enabled: true
    dangerous_methods:          # Опасные методы
      - "innerHTML"
      - "document.write"
      - "eval"
  
  html:
    enabled: true
    dangerous_attributes:       # Опасные атрибуты
      - "onload"
      - "onerror"
      - "onclick"
```
## Примеры конфигураций
### Для WordPress проекта
```yaml
scan:
  exclude_paths:
    - "wp-admin/**"
    - "wp-includes/**"
    - "wp-content/plugins/**/tests/**"
  file_extensions: [".php"]

rules:
  php:
    sources:
      - "$_GET"
      - "$_POST"
      - "$_REQUEST"
    sinks:
      - "echo"
      - "print"
      - "the_content"
      - "the_title"
```
### Для React проекта
```yaml
scan:
  file_extensions: [".js", ".jsx"]
  
rules:
  javascript:
    dangerous_methods:
      - "innerHTML"
      - "dangerouslySetInnerHTML"
    sources:
      - "window.location"
      - "document.URL"
```
### Использование конфигурации
```bash
xssguard scan ./project --config xssguard.yml
```
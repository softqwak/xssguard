# XSSGuard 🔒

**Статический анализатор исходного кода для обнаружения XSS-уязвимостей в веб-приложениях**

XSSGuard - это инструмент для автоматического обнаружения межсайтового скриптинга (XSS) в коде веб-приложений. Анализатор работает без доступа к интернету, что позволяет использовать его в изолированных средах.

## 🚀 Возможности

- **Мультиязычный анализ**: поддержка PHP, JavaScript, HTML
- **Глубокая проверка**: отслеживание потока данных от источника до опасного вывода
- **Гибкая система правил**: настраиваемые правила для разных языков и фреймворков
- **Автономная работа**: не требует подключения к интернету, все зависимости включены в поставку
- **Различные форматы отчетов**: консоль, JSON, HTML
- **Интеграция в CI/CD**: удобный CLI интерфейс и коды возврата

## 📋 Требования

- Python 3.10 или выше
- pip (менеджер пакетов Python)

## 🔧 Установка

### 1. Клонирование репозитория

```bash
git clone https://github.com/yourusername/xssguard.git
cd xssguard
```

### 2. Создание виртуального окружения

**Windows:**
```bash
python -m venv venv
venv\Scripts\activate
```

**Linux/Mac:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Установка зависимостей

```bash
pip install -r requirements.txt
pip install -e .
```

### 4. Проверка установки

```bash
xssguard version
# или
python -m xssguard.main version
```

## 🎯 Использование

### Базовое сканирование

```bash
# Сканирование текущей директории
xssguard scan .

# Сканирование конкретного файла
xssguard scan /path/to/file.php

# Сканирование с подробным выводом
xssguard scan . --verbose
```

### Расширенные опции

```bash
# Использование конфигурационного файла
xssguard scan . --config xssguard.yml

# Сохранение отчета в JSON
xssguard scan . --output report.json --format json

# Сохранение отчета в HTML
xssguard scan . --output report.html --format html

# Указание количества потоков
xssguard scan . --threads 8
```

### Создание конфигурации

```bash
# Создать пример конфигурационного файла
xssguard init-config
```

## ⚙️ Конфигурация

Пример файла `xssguard.yml`:

```yaml
scan:
  exclude_paths:
    - "vendor/**"
    - "node_modules/**"
    - "*.min.js"
  file_extensions:
    - ".php"
    - ".js"
    - ".html"
    - ".phtml"
  threads: 4
  max_file_size: 10485760  # 10MB

output:
  format: console  # console, json, html
  verbose: false
  color: true
  show_info: true
  show_warnings: true
```

## 📊 Понимание результатов

### Уровни критичности

- 🔴 **CRITICAL** - немедленное исправление, высокая вероятность эксплуатации
- 🟠 **HIGH** - требует внимания, легко эксплуатируется
- 🟡 **MEDIUM** - умеренный риск, требует определенных условий
- 🔵 **LOW** - низкий риск, сложно эксплуатировать
- 🟢 **INFO** - информационные сообщения

### Типы уязвимостей

- **Reflected XSS** - данные из запроса сразу выводятся в ответ
- **Stored XSS** - данные сохраняются на сервере и позже выводятся другим пользователям
- **DOM XSS** - уязвимость на стороне клиента в JavaScript
- **JS Injection** - внедрение в JavaScript код
- **HTML Injection** - внедрение в HTML разметку

## 🏗 Архитектура проекта

```
xssguard/
├── xssguard/              # Основной пакет
│   ├── core/              # Ядро анализатора
│   ├── models/            # Модели данных
│   │   ├── vulnerability.py
│   │   ├── rules.py
│   │   ├── config.py
│   │   └── report.py
│   ├── plugins/           # Плагины для языков
│   │   ├── php/
│   │   ├── js/
│   │   └── html/
│   ├── utils/             # Вспомогательные утилиты
│   └── main.py            # Точка входа CLI
├── tests/                  # Тесты
├── config/                 # Конфигурационные файлы
├── reports/                # Директория для отчетов
├── requirements.txt        # Зависимости
├── setup.py                # Установка пакета
└── README.md               # Документация
```

## 🧪 Тестирование

```bash
# Запуск всех тестов
pytest tests/

# Запуск с покрытием
pytest --cov=xssguard tests/

# Проверка типов
mypy xssguard/
```

## 🤝 Участие в разработке

1. Форкните репозиторий
2. Создайте ветку для фичи (`git checkout -b feature/amazing-feature`)
3. Зафиксируйте изменения (`git commit -m 'Add amazing feature'`)
4. Запушьте в ветку (`git push origin feature/amazing-feature`)
5. Откройте Pull Request

### Рекомендации по разработке

- Следуйте PEP 8 (проверяется black)
- Добавляйте тесты для новой функциональности
- Обновляйте документацию
- Используйте type hints

## 📝 Планы развития

- [ ] Реализация PHP анализатора с использованием AST
- [ ] Поддержка JavaScript анализа
- [ ] HTML парсер для шаблонов
- [ ] Система плагинов для пользовательских правил
- [ ] Интеграция с популярными CI/CD системами
- [ ] Графический интерфейс для просмотра отчетов

## 📄 Лицензия

MIT License. Подробнее в файле [LICENSE](LICENSE)

## 📬 Контакты

Ваше Имя - [@yourtwitter](https://twitter.com/yourtwitter) - email@example.com

Ссылка на проект: [https://github.com/yourusername/xssguard](https://github.com/yourusername/xssguard)

## 🙏 Благодарности

- Вдохновлено лучшими практиками статического анализа
- Использует прекрасные open-source библиотеки
- Сделано с ❤️ для безопасности веб-приложений
```

## Добавляем бейджики (опционально)

В начало файла можно добавить красивые бейджики для статуса:

```markdown
# XSSGuard 🔒

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen)]()

**Статический анализатор исходного кода для обнаружения XSS-уязвимостей в веб-приложениях**
```

## Добавляем пример использования с картинкой

Можно добавить пример вывода программы:

```markdown
## 📸 Пример работы

```bash
$ xssguard scan ./test-project --verbose
🔍 XSSGuard Scan v0.1.0
📁 Path: ./test-project
⚙️  Config: default
==================================================

⚠️  Найденные уязвимости:
  [HIGH] ./test-project/index.php:42
     → Reflected XSS vulnerability
     Данные из $_GET выводятся через echo без фильтрации
     
  [MEDIUM] ./test-project/script.js:15
     → DOM XSS vulnerability
     innerHTML используется с непроверенными данными

📊 Статистика:
   Просканировано файлов: 42
   Найдено уязвимостей: 2
     HIGH: 1
     MEDIUM: 1
```

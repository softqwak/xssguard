# XSSGuard

Статический анализатор кода для поиска XSS-уязвимостей в веб-приложениях.

## О проекте

XSSGuard автоматически находит места в коде, где возможны атаки межсайтового скриптинга (XSS). 
Анализатор работает без доступа к интернету, что позволяет использовать его в изолированных средах.

**Поддерживаемые языки:**
- PHP (в разработке)
- JavaScript (в разработке)
- HTML (в разработке)

## Быстрый старт

```bash
# Установка
git clone https://github.com/softqwak/xssguard.git
cd xssguard
python -m venv venv
source venv/bin/activate  # или venv\Scripts\activate на Windows
pip install -e .

# Запуск анализа
xssguard scan /путь/к/проекту
```

## Содержание документации
<table>
    <tr> 
        <th>Раздел</th>	
        <th>Описание</th>
    </tr>
    <tr>
        <td>Начало работы</td>
        <td><a href="./getting-started/installation">Установка и первый запуск</a></td>
    </tr>
    <tr>
        <td>Руководство пользователя</td>
        <td><a href="./user-guide/commands">Как пользоваться анализатором</a></td>
    </tr>
    <tr>
        <td>Разработчикам</td>
        <td><a href="./development/architecture">Архитектура и создание плагинов</a></td>
    </tr>
    <tr>
        <td>API Reference</td>
        <td><a href="./api/core">Документация по коду</a></td>
    </tr>
    <tr>
        <td>О проекте</td>
        <td><a href="./about/about">Лицензия, участие, история</a></td>
    </tr>
</table>
	
## Возможности
* Автономность - не требует интернета
* Мультиязычность - PHP, JavaScript, HTML в одном анализаторе
* Гибкость - настраиваемые правила под любой фреймворк
* Расширяемость - плагинная архитектура
* Отчеты - консоль, JSON, HTML
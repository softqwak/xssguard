# Первый запуск

## Проверка установки

```bash
xssguard version
```

Должны увидеть:

```text
XSSGuard версия 0.1.0
```
## Тестовый проект
Создайте папку с тестовыми файлами:

```bash
mkdir test-project
cd test-project
```
## Пример 1: PHP с уязвимостью
Создайте `test-project/index.php`:

```php
<?php
// Простая уязвимость - прямой вывод GET параметра
$user_input = $_GET['q'];
echo "Вы искали: " . $user_input;

// Безопасный вариант (для сравнения)
$safe_input = htmlspecialchars($_GET['q']);
echo "Безопасно: " . $safe_input;
?>
```

## Пример 2: JavaScript с уязвимостью
Создайте `test-project/script.js`:

```javascript
// Уязвимый код
function showMessage() {
    let user = location.hash.substring(1);
    document.getElementById('msg').innerHTML = user;
}

// Безопасный вариант
function safeShowMessage() {
    let user = location.hash.substring(1);
    document.getElementById('msg').textContent = user;
}
```
## Запуск анализа
```bash
# Вернуться в корень проекта
cd ..

# Запустить анализ тестовой папки
xssguard scan test-project --verbose
```

## Разбор результатов
Анализатор покажет:
1. **Тип уязвимости** - Reflected XSS, Stored XSS, DOM XSS
2. **Местоположение** - файл и строка
3. **Уровень опасности** - HIGH, MEDIUM, LOW
4. **Описание** - почему это уязвимость
5. **Рекомендацию** - как исправить

## Пример отчета
```json
{
  "vulnerabilities": [
    {
      "type": "reflected_xss",
      "severity": "high",
      "location": {
        "file": "test-project/index.php",
        "line": 3,
        "content": "echo \"Вы искали: \" . $user_input;"
      },
      "recommendation": "Используйте htmlspecialchars() перед выводом"
    }
  ]
}
```
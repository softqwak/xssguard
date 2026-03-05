# Установка

## Системные требования

- **Python**: версия 3.10 или выше
- **ОС**: Windows 10/11, Linux, macOS
- **Память**: от 512 МБ свободной RAM
- **Диск**: от 100 МБ свободного места

## Установка из репозитория

### 1. Клонирование

```bash
git clone https://github.com/softqwak/xssguard.git
cd xssguard
```

### 2. Виртуальное окружение
**Windows (Command Prompt):**
```bash
python -m venv venv
venv/Scripts/activate
```

**Windows (PowerShell):**
```powershell
python -m venv venv
venv/Scripts/Activate.ps1
```

**Linux/macOS:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Установка зависимостей
```bash
pip install -r requirements.txt
pip install -e .
```

### 4. Проверка
```bash
xssguard version
# Ожидаемый вывод: XSSGuard версия 0.1.0
```

## Установка без интернета
1. На машине с интернетом:
```bash
git clone https://github.com/softqwak/xssguard.git
cd xssguard
pip download -r requirements.txt -d ./packages
```
2. Скопируйте папку xssguard на целевую машину
3. На целевой машине:
```bash
python -m venv venv
source venv/bin/activate
pip install --no-index --find-links ./packages -r requirements.txt
pip install -e .
```

## Частые проблемы
**Ошибка: xssguard не найдена**

* Решение: активируйте виртуальное окружение

**Ошибка: No module named 'xssguard'**

* Решение: выполните pip install -e .
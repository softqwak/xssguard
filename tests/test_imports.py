#!/usr/bin/env python
"""Проверка импортов во всех моделях"""

import sys
from pathlib import Path

# Добавляем корневую директорию в путь
sys.path.insert(0, str(Path(__file__).parent))

models_to_check = [
    "xssguard.models.vulnerability",
    "xssguard.models.rules",
    "xssguard.models.config",
    "xssguard.models.report"
]

print("🔍 Проверка импортов моделей:")
print("=" * 50)

for model in models_to_check:
    try:
        __import__(model)
        print(f"✅ {model} - OK")
    except ImportError as e:
        print(f"❌ {model} - {e}")
    except Exception as e:
        print(f"⚠️  {model} - {e}")

print("=" * 50)
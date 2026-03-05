from setuptools import setup, find_packages

setup(
    name="xssguard",
    version="0.1.0",
    description="Статический анализатор для обнаружения XSS уязвимостей",
    author="Валентин Кузичев",
    author_email="valentin.kuzichev@yandex.ru",
    packages=find_packages(),
    install_requires=[
        "beautifulsoup4>=4.12.0",
        "lxml>=5.0.0",
        "click>=8.0.0",
        "colorama>=0.4.0",
        "pyyaml>=6.0.0",
        "pydantic>=2.0.0",
    ],
    entry_points={
        "console_scripts": [
            "xssguard=xssguard.main:cli",
        ],
    },
    python_requires=">=3.10",
)
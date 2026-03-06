# Неправильно (не работает в некоторых версиях):
# from phply.phpparse import parser

# Правильно:
from phply.phplex import lexer
from phply.phpparse import yacc  # импортируем yacc, а не parser

# Создаём парсер вручную
parser = yacc.yacc()

# Теперь можно парсить
php_code = "<?php echo 'test'; ?>"
ast = parser.parse(php_code, lexer=lexer)
print(ast)
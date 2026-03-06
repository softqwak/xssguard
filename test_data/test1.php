<?php
// Простая уязвимость - прямой вывод GET параметра
$name = $_GET['name'];
echo "Hello, " . $name;

// Безопасный вариант (не должен сработать)
$safe = htmlspecialchars($_GET['text']);
echo $safe;

// Уязвимость через присваивание
$data = $_POST['message'];
$output = $data;
print $output;

// Сложный случай - через конкатенацию
$part1 = $_GET['a'];
$part2 = "text";
$result = $part1 . $part2;
echo $result;
?>
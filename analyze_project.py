import os
import argparse

def should_ignore(name, is_dir):
    """Определяет, нужно ли игнорировать файл или директорию"""
    ignored_dirs = {'venv', '__pycache__', '.git', '.idea', '.mypy_cache', 'go-build', 'gopath', 'go-cache', 'gocache', 'CMakeFiles', 'x64', 'buildtrees', '.github', 'downloads', 'installed', 'packages', 'ports', 'scripts', 'versions' }
    ignored_extensions = {'.pyc', '.pyo', '.pyd', '.cpp', '.tlog', '.vcxproj', '.cmake', '.h' }
    
    if is_dir:
        return name in ignored_dirs
    return any(name.endswith(ext) for ext in ignored_extensions)

def get_entries(path):
    """Возвращает отфильтрованный и отсортированный список элементов директории"""
    entries = []
    try:
        for entry in os.scandir(path):
            if should_ignore(entry.name, entry.is_dir()):
                continue
            entries.append(entry)
    except PermissionError:
        pass
    
    entries.sort(key=lambda x: (not x.is_dir(), x.name.lower()))
    return entries

def generate_tree(directory, file, prefix=''):
    """Рекурсивно генерирует дерево директорий и записывает в файл"""
    entries = get_entries(directory)
    for index, entry in enumerate(entries):
        is_last = index == len(entries) - 1
        connector = '└── ' if is_last else '├── '
        file.write(f"{prefix}{connector}{entry.name}\n")
        
        if entry.is_dir():
            extension = '    ' if is_last else '│   '
            generate_tree(entry.path, file, prefix + extension)

def main():
    parser = argparse.ArgumentParser(description='Генератор структуры проекта')
    parser.add_argument('directory', help='Целевая директория для анализа')
    args = parser.parse_args()
    
    target_dir = os.path.abspath(args.directory)
    if not os.path.isdir(target_dir):
        print(f"Ошибка: {target_dir} не является директорией")
        return
    
    with open('analyze.txt', 'w', encoding='utf-8') as f:
        f.write("Структура проекта:\n")
        generate_tree(target_dir, f)
    
    print("Результат сохранён в analyze.txt")

if __name__ == "__main__":
    main()
# Руководство по вкладу в проект

## 🚀 Начало работы

1. **Форкаем репозиторий**
   Нажмите "Fork" в правом верхнем углу страницы репозитория.

2. **Клонируем локально**

```bash
git clone https://github.com/stocktaking-inc/docs.git
cd docs
```

## 🔧 Процесс разработки

### Создание веток

- Формат: `{тип}/{краткое-описание}`
  Примеры:

  ```plaintext
    feat/add-service-endpoint
    fix/authentication-bug
  ```

### Типы веток

| Префикс     | Назначение              |
| ----------- | ----------------------- |
| `feat/`     | Новая функциональность  |
| `fix/`      | Исправление ошибок      |
| `docs/`     | Обновление документации |
| `refactor/` | Обновление документации |

## 💻 Отправка изменений

1. Делаем коммит

```bash
cz
```

2. Заполняем форму Commitizen
3. Пушим в свою fork-версию:

```bash
git push origin feat/your-feature
```

## ⏫ Создание Pull Request

1. На GitHub откройте PR из своей ветки в `main` исходного репозитория
2. Используйте [шаблон PR](../.github/pull_request_template.md)
3. Дождитесь review

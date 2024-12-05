from peewee import (
    Model, CharField, DateTimeField, IntegerField, BooleanField,
    ForeignKeyField, SqliteDatabase, TextField, OperationalError, IntegrityError
)
from flask import Flask, jsonify, request, g
from werkzeug.security import generate_password_hash, check_password_hash
import json
from copy import deepcopy
from datetime import datetime, timedelta
import random
from dotenv import load_dotenv
import os


# Загружаем переменные окружения из файла .env
load_dotenv()
# Логирование запросов для каждого устройства (в памяти)
request_logs = {}
# Инициализация базы данных SQLite
db = SqliteDatabase('roles_permissions.db')


# Исключение для случаев отсутствия авторизации
class UnauthorizedError(Exception):
    pass

expiry_time = int(os.getenv("2FA_EXPIRY_TIME"))  # Время действия кода, по умолчанию 1 минута
request_delay_time = int(os.getenv("2FA_REQUEST_DELAY_TIME"))  # Задержка, по умолчанию 30 секунд

# Базовая модель, от которой наследуются все остальные модели
class BaseModel(Model):
    # Время создания записи, по умолчанию текущая дата и время
    created_at = DateTimeField(default=datetime.now)
    # Идентификатор пользователя, создавшего запись (обязательное поле)
    created_by = IntegerField()
    # Время мягкого удаления записи (null, если запись не удалена)
    deleted_at = DateTimeField(null=True)
    # Идентификатор пользователя, удалившего запись (null, если запись не удалена)
    deleted_by = IntegerField(null=True)
    # Флаг мягкого удаления (False по умолчанию)

    is_deleted = BooleanField(default=False)
    is_2fa_enabled = BooleanField(default=False)  # Флаг для включения 2FA
    two_factor_code = CharField(null=True)  # Код 2FA
    two_factor_expiry = DateTimeField(null=True)  # Время истечения действия кода 2FA
    device_id = CharField(null=True)
    two_factor_request_count = IntegerField(default=0)  # Счётчик запросов
    last_2fa_requests = DateTimeField(null=True)  # Время последнего запроса 2FA

    def generate_two_factor_code(self, device_id):
        if not self.is_2fa_enabled:
            raise ValueError("2FA не включен для этого пользователя")

        if device_id is None:
            raise ValueError("Не предоставлен идентификатор устройства")


        # Генерация нового кода 2FA
        new_code = str(random.randint(100000, 999999))
        self.two_factor_code = new_code
        self.two_factor_expiry = datetime.now() + timedelta(minutes=int(os.getenv('TWO_FA_EXPIRATION_TIME', 5)))  # Срок действия из env

        # Привязка к устройству
        self.device_id = device_id
        self.save()

        return new_code

    def reset_2fa_request_count(self):
        """Сбрасывает счетчик запросов и обновляет время последнего запроса"""
        self.two_factor_request_count = 0
        self.last_2fa_request_time = datetime.now()
        self.save()

    def increment_2fa_request_count(self):
        """Увеличивает счетчик запросов и обновляет время последнего запроса"""
        self.two_factor_request_count += 1
        self.last_2fa_request_time = datetime.now()
        self.save()

    def is_request_allowed(self):
        """Проверка, можно ли делать запрос на новый код"""
        if self.two_factor_request_count >= 3:
            # Если запросов больше 3, проверяем время последнего запроса
            time_diff = datetime.now() - self.last_2fa_request_time
            if time_diff.total_seconds() < 30:
                return False  # Подождите 30 секунд
            else:
                # Сбрасываем счётчик запросов, если прошло более 30 секунд
                self.reset_2fa_request_count()
        return True

    def verify_two_factor_code(self, code, device_id):
        """Проверяет код 2FA и идентификатор устройства"""
        if self.two_factor_code != code:
            raise ValueError("Неверный код 2FA")

        if self.two_factor_expiry < datetime.now():
            raise ValueError("Срок действия кода 2FA истёк")

        if self.device_id != device_id:
            raise ValueError("Неверный идентификатор устройства")

        # Успешная проверка
        self.two_factor_code = None  # Стираем код после успешной проверки
        self.two_factor_expiry = None
        self.save()
        return True

    def check_request_limit(self):
        """Проверка на ограничение количества запросов на 2FA"""
        if self.two_factor_request_count >= 3:
            if self.last_2fa_requests and (datetime.now() - self.last_2fa_requests).total_seconds() < 60:
                raise ValueError("Слишком много запросов. Попробуйте позже.")

        self.two_factor_request_count += 1
        self.last_2fa_requests = datetime.now()
        self.save()

    class Meta:
        # Указание используемой базы данных
        database = db

    # Метод сохранения с логированием изменений
    def save(self, *args, **kwargs):
        # Проверяем, не является ли текущая модель ChangeLog, чтобы избежать рекурсии
        if self.__class__.__name__ != 'ChangeLog':
            # Определяем, создается ли новая запись или обновляется существующая
            if self._pk is None:
                # Сохранение новой записи
                super().save(*args, **kwargs)
                # Логируем создание
                log_change(
                    entity_name=self.__class__.__name__,
                    entity_id=self.id,
                    before=None,
                    after=model_to_dict(self),
                    user_id=self.created_by
                )
            else:
                # Получаем предыдущее состояние записи
                try:
                    previous = self.__class__.get_by_id(self.id)
                    before = model_to_dict(previous)
                except self.__class__.DoesNotExist:
                    before = None
                # Создаем глубокую копию текущего состояния для сравнения
                current = deepcopy(model_to_dict(self))
                # Сохраняем изменения
                super().save(*args, **kwargs)
                # Получаем текущее состояние записи после сохранения
                after = model_to_dict(self)
                # Проверяем, изменилось ли что-либо
                if before != after:
                    # Логируем обновление только если есть изменения
                    log_change(
                        entity_name=self.__class__.__name__,
                        entity_id=self.id,
                        before=before,
                        after=after,
                        user_id=self.created_by
                    )
                else:
                    # Если изменений нет, не логируем
                    pass
        else:
            # Для ChangeLog просто сохраняем без дополнительного логирования
            super().save(*args, **kwargs)

    # Метод удаления с логированием изменений
    def delete_instance(self, *args, **kwargs):
        # Проверяем, не является ли текущая модель ChangeLog, чтобы избежать рекурсии
        if self.__class__.__name__ != 'ChangeLog':
            # Получаем предыдущее состояние записи
            before = model_to_dict(self)
            # Выполняем удаление
            super().delete_instance(*args, **kwargs)
            # Логируем удаление
            log_change(
                entity_name=self.__class__.__name__,
                entity_id=self.id,
                before=before,
                after=None,
                user_id=self.deleted_by if self.deleted_by else 0
            )
        else:
            # Для ChangeLog просто удаляем без дополнительного логирования
            super().delete_instance(*args, **kwargs)


def model_to_dict(model_instance):
    """
    Преобразует экземпляр модели в словарь, конвертируя datetime объекты в строки
    и ForeignKey поля в их идентификаторы.
    """
    result = {}
    for field in model_instance._meta.fields.values():
        value = getattr(model_instance, field.name)
        if isinstance(value, datetime):
            result[field.name] = value.isoformat()
        elif isinstance(field, ForeignKeyField):
            # Сериализуем ForeignKeyField как идентификатор связанного объекта
            related_object = getattr(model_instance, field.name)
            result[field.name] = related_object.id if related_object else None
        else:
            result[field.name] = value
    return result


# Функция логирования изменений
def log_change(entity_name, entity_id, before, after, user_id):
    """
    Записывает изменения в таблицу ChangeLog.
    """
    ChangeLog.create(
        entity=entity_name,
        entity_id=entity_id,
        before=json.dumps(before) if before else None,
        after=json.dumps(after) if after else None,
        created_by=user_id
    )


# Модель ChangeLogs – таблица со списком мутаций сущностей
class ChangeLog(BaseModel):
    # Имя сущности (User, Role, Permission)
    entity = CharField(null=False)
    # Идентификатор записи в сущности
    entity_id = IntegerField(null=False)
    # Значение записи до мутации
    before = TextField(null=True)  # Сделано null=True, так как при создании может быть None
    # Значение записи после мутации
    after = TextField(null=True)   # Сделано null=True, так как при удалении может быть None

    class Meta:
        # Указание используемой базы данных
        database = db


# Модель Роли
class Role(BaseModel):
    # Наименование роли (уникальное и обязательное)
    name = CharField(unique=True, null=False)
    # Описание роли (может быть null)
    description = CharField(null=True)
    # Шифр роли (уникальный и обязательный)
    code = CharField(unique=True, null=False)

    # Метод для получения разрешений, связанных с ролью
    def permissions(self):
        # Возвращает список разрешений, исключая мягко удаленные
        return [rp.permission for rp in self.role_permissions.where(RolePermission.is_deleted == False)]


# Модель Разрешения
class Permission(BaseModel):
    # Наименование разрешения (уникальное и обязательное)
    name = CharField(unique=True, null=False)
    # Описание разрешения (может быть null)
    description = CharField(null=True)
    # Шифр разрешения (уникальный и обязательный)
    code = CharField(unique=True, null=False)


# Модель пользователя
class User(BaseModel):
    username = CharField(unique=True)
    password_hash = CharField()

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        self.save()

    @classmethod
    def create_user(username, password, created_by):
        password_hash = generate_password_hash(password)  # Генерация хеша пароля
        return User.create(username=username, password_hash=password_hash, created_by=created_by)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


    # Метод для получения ролей пользователя
    def roles(self):
        return [ur.role for ur in self.user_roles.where(UserRole.is_deleted == False)]



# Модель связки Пользователь-Роль
class UserRole(BaseModel):
    # Ссылка на пользователя
    user = ForeignKeyField(User, backref='user_roles')
    # Ссылка на роль
    role = ForeignKeyField(Role, backref='user_roles')


# Модель связки Роль-Разрешение
class RolePermission(BaseModel):
    # Ссылка на роль
    role = ForeignKeyField(Role, backref='role_permissions')
    # Ссылка на разрешение
    permission = ForeignKeyField(Permission, backref='role_permissions')


# DTO (Data Transfer Object) для передачи данных о роли
class RoleDTO:
    def __init__(self, role):
        self.id = role.id
        self.name = role.name
        self.description = role.description
        self.code = role.code
        # Список шифров разрешений, связанных с ролью
        self.permissions = [perm.code for perm in role.permissions()]


# DTO для передачи данных о пользователе
class UserDTO:
    def __init__(self, user):
        self.id = user.id
        self.username = user.username
        # Список шифров ролей, связанных с пользователем
        self.roles = [role.code for role in user.roles()]


# DTO для передачи данных о разрешении
class PermissionDTO:
    def __init__(self, permission):
        self.id = permission.id
        self.name = permission.name
        self.description = permission.description
        self.code = permission.code


# DTO для передачи коллекции ролей
class RoleCollectionDTO:
    def __init__(self, roles):
        # Создаем список DTO для каждой роли, исключая мягко удаленные
        self.roles = [RoleDTO(role).__dict__ for role in roles if not role.is_deleted]


# DTO для передачи коллекции разрешений
class PermissionCollectionDTO:
    def __init__(self, permissions):
        # Создаем список DTO для каждого разрешения, исключая мягко удаленные
        self.permissions = [PermissionDTO(permission).__dict__ for permission in permissions if not permission.is_deleted]


# DTO для передачи данных о логах изменений
class ChangeLogDTO:
    def __init__(self, changelog):
        self.id = changelog.id
        self.entity = changelog.entity
        self.entity_id = changelog.entity_id
        self.before = json.loads(changelog.before) if changelog.before else None
        self.after = json.loads(changelog.after) if changelog.after else None
        self.timestamp = changelog.created_at.isoformat()
        self.created_by = changelog.created_by


# DTO для передачи коллекции логов
class ChangeLogCollectionDTO:
    def __init__(self, changelogs):
        self.change_logs = [ChangeLogDTO(log).__dict__ for log in changelogs]


# Функция для мягкого удаления записи
def soft_delete(instance, user_id):
    """
    Выполняет мягкое удаление записи.
    """
    instance.is_deleted = True
    instance.deleted_at = datetime.now()
    instance.deleted_by = user_id
    instance.save()


# Функция для проверки авторизации пользователя
def require_authorization(user_id):
    """
    Проверяет, предоставлен ли user_id.
    """
    if not user_id:
        raise UnauthorizedError("Требуется авторизация.")


# Функция для проверки наличия у пользователя необходимого разрешения
def check_permission(user_id, permission_code):
    """
    Проверяет, имеет ли пользователь с user_id разрешение с кодом permission_code.
    """
    user = User.get_or_none(User.id == user_id)
    if not user:
        raise UnauthorizedError("Пользователь не найден.")
    # Проходим по ролям пользователя и их разрешениям
    for role in user.roles():
        for permission in role.permissions():
            if permission.code == permission_code:
                return True
    return False


# Класс запроса на создание роли
class CreateRoleRequest:
    def __init__(self, name, description, code, created_by):
        require_authorization(created_by)  # Проверка авторизации
        self.name = name
        self.description = description
        self.code = code
        self.created_by = created_by

    def validate(self):
        # Проверяем уникальность имени и шифра роли
        if Role.select().where(Role.name == self.name).exists():
            raise ValueError("Наименование роли должно быть уникальным.")
        if Role.select().where(Role.code == self.code).exists():
            raise ValueError("Шифр роли должен быть уникальным.")

    def execute(self):
        # Создаем новую роль и возвращаем ее DTO
        with db.atomic():
            role = Role.create(
                name=self.name,
                description=self.description,
                code=self.code,
                created_by=self.created_by
            )
            return RoleDTO(role)


# Класс запроса на обновление роли
class UpdateRoleRequest:
    def __init__(self, role_id, name, description, code, updated_by):
        require_authorization(updated_by)  # Проверка авторизации
        self.role_id = role_id
        self.name = name
        self.description = description
        self.code = code
        self.updated_by = updated_by

    def validate(self):
        # Проверяем, существует ли роль и уникальность новых данных
        if not Role.select().where(Role.id == self.role_id).exists():
            raise ValueError("Роль не найдена.")
        if Role.select().where((Role.name == self.name) & (Role.id != self.role_id)).exists():
            raise ValueError("Наименование роли должно быть уникальным.")
        if Role.select().where((Role.code == self.code) & (Role.id != self.role_id)).exists():
            raise ValueError("Шифр роли должен быть уникальным.")

    def execute(self):
        # Обновляем роль и возвращаем ее DTO
        with db.atomic():
            role = Role.get_by_id(self.role_id)
            role.name = self.name
            role.description = self.description
            role.code = self.code
            role.created_by = self.updated_by  # Обновляем поле created_by для логирования
            role.save()
            return RoleDTO(role)


# Класс запроса на создание разрешения
class CreatePermissionRequest:
    def __init__(self, name, description, code, created_by):
        require_authorization(created_by)  # Проверка авторизации
        self.name = name
        self.description = description
        self.code = code
        self.created_by = created_by

    def validate(self):
        # Проверяем уникальность имени и шифра разрешения
        if Permission.select().where(Permission.name == self.name).exists():
            raise ValueError("Наименование разрешения должно быть уникальным.")
        if Permission.select().where(Permission.code == self.code).exists():
            raise ValueError("Шифр разрешения должен быть уникальным.")

    def execute(self):
        # Создаем новое разрешение и возвращаем его DTO
        with db.atomic():
            permission = Permission.create(
                name=self.name,
                description=self.description,
                code=self.code,
                created_by=self.created_by
            )
            return PermissionDTO(permission)


# Класс запроса на обновление разрешения
class UpdatePermissionRequest:
    def __init__(self, permission_id, name, description, code, updated_by):
        require_authorization(updated_by)  # Проверка авторизации
        self.permission_id = permission_id
        self.name = name
        self.description = description
        self.code = code
        self.updated_by = updated_by

    def validate(self):
        # Проверяем, существует ли разрешение и уникальность новых данных
        if not Permission.select().where(Permission.id == self.permission_id).exists():
            raise ValueError("Разрешение не найдено.")
        if Permission.select().where((Permission.name == self.name) & (Permission.id != self.permission_id)).exists():
            raise ValueError("Наименование разрешения должно быть уникальным.")
        if Permission.select().where((Permission.code == self.code) & (Permission.id != self.permission_id)).exists():
            raise ValueError("Шифр разрешения должен быть уникальным.")

    def execute(self):
        # Обновляем разрешение и возвращаем его DTO
        with db.atomic():
            permission = Permission.get_by_id(self.permission_id)
            permission.name = self.name
            permission.description = self.description
            permission.code = self.code
            permission.created_by = self.updated_by  # Обновляем поле created_by для логирования
            permission.save()
            return PermissionDTO(permission)


# Контроллер для управления ролями
class RoleController:
    def get_roles(self, user_id):
        require_authorization(user_id)
        # Проверка наличия разрешения на получение списка ролей
        if not check_permission(user_id, 'get-list-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: get-list-role"}), 403
        # Получение списка ролей, исключая мягко удаленные
        roles = Role.select().where(Role.is_deleted == False)
        roles_dto = [RoleDTO(role).__dict__ for role in roles]
        return jsonify(roles_dto), 200

    def get_role(self, role_id, user_id):
        require_authorization(user_id)
        # Проверка наличия разрешения на чтение роли
        if not check_permission(user_id, 'read-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: read-role"}), 403
        # Получение конкретной роли
        role = Role.get_or_none(Role.id == role_id, Role.is_deleted == False)
        if not role:
            return jsonify({"error": "Роль не найдена"}), 404
        return jsonify(RoleDTO(role).__dict__), 200

    def create_role(self, create_request):
        try:
            create_request.validate()
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        # Проверка наличия разрешения на создание роли
        if not check_permission(create_request.created_by, 'create-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: create-role"}), 403
        # Создание роли
        try:
            role_dto = create_request.execute()
            return jsonify(role_dto.__dict__), 201
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при создании роли."}), 500

    def update_role(self, update_request):
        try:
            update_request.validate()
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        # Проверка наличия разрешения на обновление роли
        if not check_permission(update_request.updated_by, 'update-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: update-role"}), 403
        # Обновление роли
        try:
            role_dto = update_request.execute()
            return jsonify(role_dto.__dict__), 200
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при обновлении роли."}), 500

    def delete_role(self, role_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на удаление роли
        if not check_permission(deleted_by, 'delete-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: delete-role"}), 403
        # Жесткое удаление роли
        role = Role.get_or_none(Role.id == role_id)
        if not role:
            return jsonify({"error": "Роль не найдена"}), 404
        try:
            role.delete_instance()
            return jsonify({"message": "Роль удалена"}), 204
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при удалении роли."}), 500

    def soft_delete_role(self, role_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на мягкое удаление роли
        if not check_permission(deleted_by, 'delete-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: delete-role"}), 403
        # Мягкое удаление роли
        role = Role.get_or_none(Role.id == role_id, Role.is_deleted == False)
        if not role:
            return jsonify({"error": "Роль не найдена"}), 404
        try:
            soft_delete(role, deleted_by)
            return jsonify({"message": "Роль мягко удалена"}), 200
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при мягком удалении роли."}), 500

    def restore_role(self, role_id, user_id):
        require_authorization(user_id)
        # Проверка наличия разрешения на восстановление роли
        if not check_permission(user_id, 'restore-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: restore-role"}), 403
        # Восстановление мягко удаленной роли
        role = Role.get_or_none(Role.id == role_id, Role.is_deleted == True)
        if not role:
            return jsonify({"error": "Роль не найдена или не была мягко удалена"}), 404
        try:
            role.is_deleted = False
            role.deleted_at = None
            role.deleted_by = None
            role.created_by = user_id  # Обновляем поле created_by для логирования
            role.save()
            return jsonify({"message": "Роль восстановлена"}), 200
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при восстановлении роли."}), 500


# Контроллер для управления разрешениями
class PermissionController:
    def get_permissions(self, user_id):
        require_authorization(user_id)
        # Проверка наличия разрешения на получение списка разрешений
        if not check_permission(user_id, 'get-list-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: get-list-permission"}), 403
        # Получение списка разрешений, исключая мягко удаленные
        permissions = Permission.select().where(Permission.is_deleted == False)
        permissions_dto = [PermissionDTO(perm).__dict__ for perm in permissions]
        return jsonify(permissions_dto), 200

    def get_permission(self, permission_id, user_id):
        require_authorization(user_id)
        # Проверка наличия разрешения на чтение разрешения
        if not check_permission(user_id, 'read-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: read-permission"}), 403
        # Получение конкретного разрешения
        permission = Permission.get_or_none(Permission.id == permission_id, Permission.is_deleted == False)
        if not permission:
            return jsonify({"error": "Разрешение не найдено"}), 404
        return jsonify(PermissionDTO(permission).__dict__), 200

    def create_permission(self, create_request):
        try:
            create_request.validate()
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        # Проверка наличия разрешения на создание разрешения
        if not check_permission(create_request.created_by, 'create-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: create-permission"}), 403
        # Создание разрешения
        try:
            permission_dto = create_request.execute()
            return jsonify(permission_dto.__dict__), 201
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при создании разрешения."}), 500

    def update_permission(self, update_request):
        try:
            update_request.validate()
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        # Проверка наличия разрешения на обновление разрешения
        if not check_permission(update_request.updated_by, 'update-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: update-permission"}), 403
        # Обновление разрешения
        try:
            permission_dto = update_request.execute()
            return jsonify(permission_dto.__dict__), 200
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при обновлении разрешения."}), 500

    def delete_permission(self, permission_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на удаление разрешения
        if not check_permission(deleted_by, 'delete-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: delete-permission"}), 403
        # Жесткое удаление разрешения
        permission = Permission.get_or_none(Permission.id == permission_id)
        if not permission:
            return jsonify({"error": "Разрешение не найдено"}), 404
        try:
            permission.delete_instance()
            return jsonify({"message": "Разрешение удалено"}), 204
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при удалении разрешения."}), 500

    def soft_delete_permission(self, permission_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на мягкое удаление разрешения
        if not check_permission(deleted_by, 'delete-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: delete-permission"}), 403
        # Мягкое удаление разрешения
        permission = Permission.get_or_none(Permission.id == permission_id, Permission.is_deleted == False)
        if not permission:
            return jsonify({"error": "Разрешение не найдено"}), 404
        try:
            soft_delete(permission, deleted_by)
            return jsonify({"message": "Разрешение мягко удалено"}), 200
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при мягком удалении разрешения."}), 500

    def restore_permission(self, permission_id, user_id):
        require_authorization(user_id)
        # Проверка наличия разрешения на восстановление разрешения
        if not check_permission(user_id, 'restore-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: restore-permission"}), 403
        # Восстановление мягко удаленного разрешения
        permission = Permission.get_or_none(Permission.id == permission_id, Permission.is_deleted == True)
        if not permission:
            return jsonify({"error": "Разрешение не найдено или не было мягко удалено"}), 404
        try:
            permission.is_deleted = False
            permission.deleted_at = None
            permission.deleted_by = None
            permission.created_by = user_id  # Обновляем поле created_by для логирования
            permission.save()
            return jsonify({"message": "Разрешение восстановлено"}), 200
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при восстановлении разрешения."}), 500


# Контроллер для управления связями Роль-Разрешение
class RolePermissionController:
    def assign_permission_to_role(self, role_id, permission_id, created_by):
        require_authorization(created_by)
        # Проверка наличия разрешения на присвоение разрешения роли
        if not check_permission(created_by, 'assign-permission-to-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: assign-permission-to-role"}), 403
        # Проверка существования роли и разрешения
        role = Role.get_or_none(Role.id == role_id, Role.is_deleted == False)
        if not role:
            return jsonify({"error": "Роль не найдена"}), 404
        permission = Permission.get_or_none(Permission.id == permission_id, Permission.is_deleted == False)
        if not permission:
            return jsonify({"error": "Разрешение не найдено"}), 404
        # Проверка, не назначено ли разрешение уже роли
        if RolePermission.select().where(
            RolePermission.role == role,
            RolePermission.permission == permission,
            RolePermission.is_deleted == False
        ).exists():
            return jsonify({"error": "Разрешение уже назначено роли"}), 400
        # Присвоение разрешения роли
        try:
            with db.atomic():
                RolePermission.create(
                    role=role,
                    permission=permission,
                    created_by=created_by
                )
            return jsonify({"message": "Разрешение назначено роли"}), 201
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при назначении разрешения роли."}), 500

    def remove_permission_from_role(self, role_id, permission_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на удаление разрешения у роли
        if not check_permission(deleted_by, 'remove-permission-from-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: remove-permission-from-role"}), 403
        # Проверка существования связи роль-разрешение
        role_permission = RolePermission.get_or_none(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id,
            RolePermission.is_deleted == False
        )
        if not role_permission:
            return jsonify({"error": "Разрешение не назначено роли"}), 404
        # Жесткое удаление связи
        try:
            with db.atomic():
                role_permission.delete_instance()
            return jsonify({"message": "Разрешение удалено у роли"}), 204
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при удалении разрешения у роли."}), 500

    def soft_delete_role_permission(self, role_id, permission_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на мягкое удаление разрешения у роли
        if not check_permission(deleted_by, 'remove-permission-from-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: remove-permission-from-role"}), 403
        # Проверка существования связи роль-разрешение
        role_permission = RolePermission.get_or_none(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id,
            RolePermission.is_deleted == False
        )
        if not role_permission:
            return jsonify({"error": "Разрешение не назначено роли"}), 404
        # Мягкое удаление связи
        try:
            with db.atomic():
                soft_delete(role_permission, deleted_by)
            return jsonify({"message": "Разрешение мягко удалено у роли"}), 200
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при мягком удалении разрешения у роли."}), 500

    def restore_role_permission(self, role_id, permission_id, user_id):
        require_authorization(user_id)
        # Проверка наличия разрешения на восстановление связи роль-разрешение
        if not check_permission(user_id, 'restore-role-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: restore-role-permission"}), 403
        # Проверка существования мягко удаленной связи роль-разрешение
        role_permission = RolePermission.get_or_none(
            RolePermission.role_id == role_id,
            RolePermission.permission_id == permission_id,
            RolePermission.is_deleted == True
        )
        if not role_permission:
            return jsonify({"error": "Связь роль-разрешение не найдена или не была мягко удалена"}), 404
        # Восстановление связи
        try:
            with db.atomic():
                role_permission.is_deleted = False
                role_permission.deleted_at = None
                role_permission.deleted_by = None
                role_permission.created_by = user_id  # Обновляем поле created_by для логирования
                role_permission.save()
            return jsonify({"message": "Разрешение восстановлено у роли"}), 200
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при восстановлении разрешения у роли."}), 500


# Контроллер для управления логами изменений
class ChangeLogController:
    def get_logs_for_entity(self, entity_name, entity_id, user_id):
        require_authorization(user_id)
        # Формируем разрешение на просмотр логов
        permission_code = f"get-story-{entity_name.lower()}"
        if not check_permission(user_id, permission_code):
            return jsonify({"error": f"Доступ запрещен. Требуется: {permission_code}"}), 403
        # Получение логов для конкретной сущности и записи
        changelogs = ChangeLog.select().where(
            ChangeLog.entity == entity_name,
            ChangeLog.entity_id == entity_id
        ).order_by(ChangeLog.created_at.desc())
        changelogs_dto = ChangeLogCollectionDTO(changelogs)
        return jsonify(changelogs_dto.__dict__), 200

    def restore_from_log(self, entity_name, entity_id, log_id, user_id):
        require_authorization(user_id)
        permission_code = f"restore-{entity_name.lower()}"
        if not check_permission(user_id, permission_code):
            return jsonify({"error": f"Доступ запрещен. Требуется: {permission_code}"}), 403

        changelog = ChangeLog.get_or_none(ChangeLog.id == log_id)
        if not changelog:
            return jsonify({"error": "Лог не найден"}), 404
        if changelog.entity != entity_name or changelog.entity_id != entity_id:
            return jsonify({"error": "Лог не соответствует указанной сущности и записи"}), 400

        try:
            with db.atomic():
                entity = None
                if entity_name == 'User':
                    entity = User.get_or_none(User.id == entity_id)
                elif entity_name == 'Role':
                    entity = Role.get_or_none(Role.id == entity_id)
                elif entity_name == 'Permission':
                    entity = Permission.get_or_none(Permission.id == entity_id)
                else:
                    return jsonify({"error": "Неизвестная сущность"}), 400

                before_state = json.loads(changelog.before) if changelog.before else {}

                if not entity:
                    # Запись отсутствует, создаём её заново
                    before_state.pop('created_by', None)  # Удаляем 'created_by' из before_state

                    if entity_name == 'User':
                        entity = User.create(**before_state, created_by=user_id)
                    elif entity_name == 'Role':
                        entity = Role.create(**before_state, created_by=user_id)
                    elif entity_name == 'Permission':
                        entity = Permission.create(**before_state, created_by=user_id)

                    # Устанавливаем флаги для восстановления
                    entity.is_deleted = False
                    entity.deleted_at = None
                    entity.deleted_by = None
                    entity.save()
                else:
                    # Запись существует, обновляем её
                    for key, value in before_state.items():
                        setattr(entity, key, value)
                    # Устанавливаем флаги для восстановления
                    entity.is_deleted = False
                    entity.deleted_at = None
                    entity.deleted_by = None
                    # Предполагается, что есть поле 'updated_by' для отслеживания изменений
                    if hasattr(entity, 'updated_by'):
                        entity.updated_by = user_id
                    entity.save()

            return jsonify({"message": f"{entity_name} восстановлен до состояния из лога {log_id}."}), 200
        except OperationalError as oe:
            return jsonify({"error": "Ошибка при восстановлении сущности."}), 500
        except Exception as e:
            return jsonify({"error": f"Не удалось восстановить сущность: {str(e)}"}), 500


# Контроллер для управления логами изменений
change_log_controller = ChangeLogController()


# Контроллеры для ролей и разрешений
role_controller = RoleController()
permission_controller = PermissionController()
role_permission_controller = RolePermissionController()


# Инициализация приложения Flask
app = Flask(__name__)

# Маршруты управления ролями
@app.route('/api/ref/policy/role', methods=['GET'])
def get_roles_route():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id не предоставлен"}), 400
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат user_id"}), 400
    return role_controller.get_roles(user_id)


@app.route('/api/ref/policy/role/<int:role_id>', methods=['GET'])
def get_role_route(role_id):
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id не предоставлен"}), 400
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат user_id"}), 400
    return role_controller.get_role(role_id, user_id)


@app.route('/api/ref/policy/role', methods=['POST'])
def create_role_route():
    name = request.form.get('name')
    description = request.form.get('description')
    code = request.form.get('code')
    created_by = request.form.get('created_by')

    # Проверка наличия обязательных полей
    if not all([name, code, created_by]):
        return jsonify({"error": "name, code и created_by являются обязательными полями."}), 400
    try:
        created_by = int(created_by)
    except ValueError:
        return jsonify({"error": "Неверный формат created_by"}), 400

    create_request = CreateRoleRequest(name, description, code, created_by)
    return role_controller.create_role(create_request)


@app.route('/api/ref/policy/role/<int:role_id>', methods=['PUT'])
def update_role_route(role_id):
    name = request.form.get('name')
    description = request.form.get('description')
    code = request.form.get('code')
    updated_by = request.form.get('updated_by')

    # Проверка наличия обязательных полей
    if not all([name, code, updated_by]):
        return jsonify({"error": "name, code и updated_by являются обязательными полями."}), 400
    try:
        updated_by = int(updated_by)
    except ValueError:
        return jsonify({"error": "Неверный формат updated_by"}), 400

    update_request = UpdateRoleRequest(role_id, name, description, code, updated_by)
    return role_controller.update_role(update_request)


@app.route('/api/ref/policy/role/<int:role_id>', methods=['DELETE'])
def delete_role_route(role_id):
    deleted_by = request.form.get('deleted_by')
    if not deleted_by:
        return jsonify({"error": "deleted_by не предоставлен"}), 400
    try:
        deleted_by = int(deleted_by)
    except ValueError:
        return jsonify({"error": "Неверный формат deleted_by"}), 400
    return role_controller.delete_role(role_id, deleted_by)


@app.route('/api/ref/policy/role/<int:role_id>/soft', methods=['DELETE'])
def soft_delete_role_route(role_id):
    deleted_by = request.form.get('deleted_by')
    if not deleted_by:
        return jsonify({"error": "deleted_by не предоставлен"}), 400
    try:
        deleted_by = int(deleted_by)
    except ValueError:
        return jsonify({"error": "Неверный формат deleted_by"}), 400
    return role_controller.soft_delete_role(role_id, deleted_by)


@app.route('/api/ref/policy/role/<int:role_id>/restore', methods=['POST'])
def restore_role_route(role_id):
    user_id = request.form.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id не предоставлен"}), 400
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат user_id"}), 400
    return role_controller.restore_role(role_id, user_id)


# Маршруты управления разрешениями
@app.route('/api/ref/policy/permission', methods=['GET'])
def get_permissions_route():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id не предоставлен"}), 400
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат user_id"}), 400
    return permission_controller.get_permissions(user_id)


@app.route('/api/ref/policy/permission/<int:permission_id>', methods=['GET'])
def get_permission_route(permission_id):
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id не предоставлен"}), 400
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат user_id"}), 400
    return permission_controller.get_permission(permission_id, user_id)


@app.route('/api/ref/policy/permission', methods=['POST'])
def create_permission_route():
    name = request.form.get('name')
    description = request.form.get('description')
    code = request.form.get('code')
    created_by = request.form.get('created_by')

    # Проверка наличия обязательных полей
    if not all([name, code, created_by]):
        return jsonify({"error": "name, code и created_by являются обязательными полями."}), 400
    try:
        created_by = int(created_by)
    except ValueError:
        return jsonify({"error": "Неверный формат created_by"}), 400

    create_request = CreatePermissionRequest(name, description, code, created_by)
    return permission_controller.create_permission(create_request)


@app.route('/api/ref/policy/permission/<int:permission_id>', methods=['PUT'])
def update_permission_route(permission_id):
    name = request.form.get('name')
    description = request.form.get('description')
    code = request.form.get('code')
    updated_by = request.form.get('updated_by')

    # Проверка наличия обязательных полей
    if not all([name, code, updated_by]):
        return jsonify({"error": "name, code и updated_by являются обязательными полями."}), 400
    try:
        updated_by = int(updated_by)
    except ValueError:
        return jsonify({"error": "Неверный формат updated_by"}), 400

    update_request = UpdatePermissionRequest(permission_id, name, description, code, updated_by)
    return permission_controller.update_permission(update_request)


@app.route('/api/ref/policy/permission/<int:permission_id>', methods=['DELETE'])
def delete_permission_route(permission_id):
    deleted_by = request.form.get('deleted_by')
    if not deleted_by:
        return jsonify({"error": "deleted_by не предоставлен"}), 400
    try:
        deleted_by = int(deleted_by)
    except ValueError:
        return jsonify({"error": "Неверный формат deleted_by"}), 400
    return permission_controller.delete_permission(permission_id, deleted_by)


@app.route('/api/ref/policy/permission/<int:permission_id>/soft', methods=['DELETE'])
def soft_delete_permission_route(permission_id):
    deleted_by = request.form.get('deleted_by')
    if not deleted_by:
        return jsonify({"error": "deleted_by не предоставлен"}), 400
    try:
        deleted_by = int(deleted_by)
    except ValueError:
        return jsonify({"error": "Неверный формат deleted_by"}), 400
    return permission_controller.soft_delete_permission(permission_id, deleted_by)


@app.route('/api/ref/policy/permission/<int:permission_id>/restore', methods=['POST'])
def restore_permission_route(permission_id):
    user_id = request.form.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id не предоставлен"}), 400
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат user_id"}), 400
    return permission_controller.restore_permission(permission_id, user_id)


# Маршруты управления связями Роль-Разрешение
@app.route('/api/ref/policy/role/<int:role_id>/permission', methods=['POST'])
def assign_permission_to_role_route(role_id):
    permission_id = request.form.get('permission_id')
    created_by = request.form.get('created_by')

    # Проверка наличия обязательных полей
    if not all([permission_id, created_by]):
        return jsonify({"error": "permission_id и created_by являются обязательными полями."}), 400
    try:
        permission_id = int(permission_id)
        created_by = int(created_by)
    except ValueError:
        return jsonify({"error": "Неверный формат permission_id или created_by"}), 400

    return role_permission_controller.assign_permission_to_role(role_id, permission_id, created_by)


@app.route('/api/ref/policy/role/<int:role_id>/permission/<int:permission_id>', methods=['DELETE'])
def remove_permission_from_role_route(role_id, permission_id):
    deleted_by = request.form.get('deleted_by')
    if not deleted_by:
        return jsonify({"error": "deleted_by не предоставлен"}), 400
    try:
        deleted_by = int(deleted_by)
    except ValueError:
        return jsonify({"error": "Неверный формат deleted_by"}), 400
    return role_permission_controller.remove_permission_from_role(role_id, permission_id, deleted_by)


@app.route('/api/ref/policy/role/<int:role_id>/permission/<int:permission_id>/soft', methods=['DELETE'])
def soft_delete_role_permission_route(role_id, permission_id):
    deleted_by = request.form.get('deleted_by')
    if not deleted_by:
        return jsonify({"error": "deleted_by не предоставлен"}), 400
    try:
        deleted_by = int(deleted_by)
    except ValueError:
        return jsonify({"error": "Неверный формат deleted_by"}), 400
    return role_permission_controller.soft_delete_role_permission(role_id, permission_id, deleted_by)


@app.route('/api/ref/policy/role/<int:role_id>/permission/<int:permission_id>/restore', methods=['POST'])
def restore_role_permission_route(role_id, permission_id):
    user_id = request.form.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id не предоставлен"}), 400
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат user_id"}), 400
    return role_permission_controller.restore_role_permission(role_id, permission_id, user_id)


# Маршруты управления пользователями
@app.route('/api/ref/user', methods=['GET'])
def get_users_route():
    user_id = request.args.get('user_id')
    if not user_id:
        return jsonify({"error": "user_id не предоставлен"}), 400
    try:
        user_id = int(user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат user_id"}), 400
    require_authorization(user_id)
    # Проверка наличия разрешения на получение списка пользователей
    if not check_permission(user_id, 'get-list-user'):
        return jsonify({"error": "Доступ запрещен. Требуется: get-list-user"}), 403
    # Получение списка пользователей, исключая мягко удаленные
    users = User.select().where(User.is_deleted == False)
    users_dto = [UserDTO(user).__dict__ for user in users]
    return jsonify(users_dto), 200


@app.route('/api/ref/user/<int:user_id>/story', methods=['GET'])
def get_user_story(user_id):
    """
    Получение истории изменений пользователя.
    """
    current_user_id = request.args.get('current_user_id')
    if not current_user_id:
        return jsonify({"error": "current_user_id не предоставлен"}), 400
    try:
        current_user_id = int(current_user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат current_user_id"}), 400
    return change_log_controller.get_logs_for_entity('User', user_id, current_user_id)


@app.route('/api/ref/user/<int:user_id>/story/restore', methods=['POST'])
def restore_user_from_log(user_id):
    """
    Восстановление состояния пользователя из лога.
    """
    log_id = request.form.get('log_id')
    user_id_request = request.form.get('user_id')
    if not all([log_id, user_id_request]):
        return jsonify({"error": "log_id и user_id являются обязательными полями."}), 400
    try:
        log_id = int(log_id)
        user_id_request = int(user_id_request)
    except ValueError:
        return jsonify({"error": "Неверный формат log_id или user_id"}), 400
    return change_log_controller.restore_from_log('User', user_id, log_id, user_id_request)


@app.route('/api/ref/user/<int:user_id>/role', methods=['GET'])
def get_user_roles_route(user_id):
    current_user_id = request.args.get('current_user_id')
    if not current_user_id:
        return jsonify({"error": "current_user_id не предоставлен"}), 400
    try:
        current_user_id = int(current_user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат current_user_id"}), 400
    require_authorization(current_user_id)
    # Проверка наличия разрешения на чтение пользователя
    if not check_permission(current_user_id, 'read-user'):
        return jsonify({"error": "Доступ запрещен. Требуется: read-user"}), 403
    user = User.get_or_none(User.id == user_id, User.is_deleted == False)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    # Возвращаем список шифров ролей пользователя
    roles = [role.code for role in user.roles()]
    return jsonify({"roles": roles}), 200


@app.route('/api/ref/user/<int:user_id>/role', methods=['POST'])
def assign_role_to_user_route(user_id):
    role_id = request.form.get('role_id')
    created_by = request.form.get('created_by')

    # Проверка наличия обязательных полей
    if not all([role_id, created_by]):
        return jsonify({"error": "role_id и created_by являются обязательными полями."}), 400
    try:
        role_id = int(role_id)
        created_by = int(created_by)
    except ValueError:
        return jsonify({"error": "Неверный формат role_id или created_by"}), 400

    return assign_role_to_user(user_id, role_id, created_by)


def assign_role_to_user(user_id, role_id, created_by):
    """
    Функция для присвоения роли пользователю с логированием и транзакцией.
    """
    require_authorization(created_by)
    # Проверка наличия разрешения на присвоение роли пользователю
    if not check_permission(created_by, 'assign-role-to-user'):
        return jsonify({"error": "Доступ запрещен. Требуется: assign-role-to-user"}), 403
    # Проверка существования пользователя и роли
    role = Role.get_or_none(Role.id == role_id, Role.is_deleted == False)
    if not role:
        return jsonify({"error": "Роль не найдена"}), 404
    user = User.get_or_none(User.id == user_id, User.is_deleted == False)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    # Проверка, не назначена ли роль уже пользователю
    if UserRole.select().where(
        UserRole.user == user,
        UserRole.role == role,
        UserRole.is_deleted == False
    ).exists():
        return jsonify({"error": "Роль уже назначена пользователю"}), 400
    # Присвоение роли пользователю
    try:
        with db.atomic():
            UserRole.create(user=user, role=role, created_by=created_by)
        return jsonify({"message": "Роль назначена пользователю"}), 201
    except OperationalError as oe:
        return jsonify({"error": "Ошибка при назначении роли пользователю."}), 500


@app.route('/api/ref/user/<int:user_id>/role/<int:role_id>', methods=['DELETE'])
def remove_role_from_user_route(user_id, role_id):
    deleted_by = request.form.get('deleted_by')
    if not deleted_by:
        return jsonify({"error": "deleted_by не предоставлен"}), 400
    try:
        deleted_by = int(deleted_by)
    except ValueError:
        return jsonify({"error": "Неверный формат deleted_by"}), 400
    return remove_role_from_user(user_id, role_id, deleted_by)


def remove_role_from_user(user_id, role_id, deleted_by):
    """
    Функция для удаления роли у пользователя с логированием и транзакцией.
    """
    require_authorization(deleted_by)
    # Проверка наличия разрешения на удаление роли у пользователя
    if not check_permission(deleted_by, 'remove-role-from-user'):
        return jsonify({"error": "Доступ запрещен. Требуется: remove-role-from-user"}), 403
    # Проверка существования связи пользователь-роль
    user_role = UserRole.get_or_none(
        UserRole.user_id == user_id,
        UserRole.role_id == role_id,
        UserRole.is_deleted == False
    )
    if not user_role:
        return jsonify({"error": "Роль не назначена пользователю"}), 404
    # Жесткое удаление связи
    try:
        with db.atomic():
            user_role.delete_instance()
        return jsonify({"message": "Роль удалена у пользователя"}), 204
    except OperationalError as oe:
        return jsonify({"error": "Ошибка при удалении роли у пользователя."}), 500


@app.route('/api/ref/user/<int:user_id>/role/<int:role_id>/soft', methods=['DELETE'])
def soft_delete_user_role_route(user_id, role_id):
    deleted_by = request.form.get('deleted_by')
    if not deleted_by:
        return jsonify({"error": "deleted_by не предоставлен"}), 400
    try:
        deleted_by = int(deleted_by)
    except ValueError:
        return jsonify({"error": "Неверный формат deleted_by"}), 400
    return soft_delete_user_role(user_id, role_id, deleted_by)


def soft_delete_user_role(user_id, role_id, deleted_by):
    """
    Функция для мягкого удаления роли у пользователя с логированием и транзакцией.
    """
    require_authorization(deleted_by)
    # Проверка наличия разрешения на мягкое удаление роли у пользователя
    if not check_permission(deleted_by, 'remove-role-from-user'):
        return jsonify({"error": "Доступ запрещен. Требуется: remove-role-from-user"}), 403
    # Проверка существования связи пользователь-роль
    user_role = UserRole.get_or_none(
        UserRole.user_id == user_id,
        UserRole.role_id == role_id,
        UserRole.is_deleted == False
    )
    if not user_role:
        return jsonify({"error": "Связь пользователь-роль не найдена"}), 404
    # Мягкое удаление связи
    try:
        with db.atomic():
            soft_delete(user_role, deleted_by)
        return jsonify({"message": "Роль мягко удалена у пользователя"}), 200
    except OperationalError as oe:
        return jsonify({"error": "Ошибка при мягком удалении роли у пользователя."}), 500


@app.route('/api/ref/user/<int:user_id>/role/<int:role_id>/restore', methods=['POST'])
def restore_user_role_route(user_id, role_id):
    log_id = request.form.get('log_id')
    user_id_request = request.form.get('user_id')
    if not all([log_id, user_id_request]):
        return jsonify({"error": "log_id и user_id являются обязательными полями."}), 400
    try:
        log_id = int(log_id)
        user_id_request = int(user_id_request)
    except ValueError:
        return jsonify({"error": "Неверный формат log_id или user_id"}), 400
    return change_log_controller.restore_from_log('User', user_id, log_id, user_id_request)


# Функция для заполнения базы данных начальными данными (сидами)
def seed_roles():
    roles = [
        {"name": "Admin", "description": "Administrator", "code": "admin"},
        {"name": "User", "description": "Regular user", "code": "user"},
        {"name": "Guest", "description": "Guest user", "code": "guest"}
    ]
    with db.atomic():
        for role_data in roles:
            if not Role.select().where(Role.code == role_data["code"]).exists():
                Role.create(
                    name=role_data["name"],
                    description=role_data["description"],
                    code=role_data["code"],
                    created_by=1
                )
    print("Роли успешно добавлены.")


def seed_permissions():
    entities = ["user", "role", "permission"]
    actions = ["get-list", "read", "create", "update", "delete", "restore"]
    with db.atomic():
        for entity in entities:
            for action in actions:
                code = f"{action}-{entity}"
                if not Permission.select().where(Permission.code == code).exists():
                    Permission.create(
                        name=f"{action.capitalize()} {entity}",
                        description=f"{action} access to {entity}",
                        code=code,
                        created_by=1
                    )
        # Дополнительные разрешения для управления связями и логами
        extra_permissions = [
            {"code": "assign-role-to-user", "name": "Assign role to user", "description": "Assign role to user"},
            {"code": "remove-role-from-user", "name": "Remove role from user", "description": "Remove role from user"},
            {"code": "assign-permission-to-role", "name": "Assign permission to role", "description": "Assign permission to role"},
            {"code": "remove-permission-from-role", "name": "Remove permission from role", "description": "Remove permission from role"},
            {"code": "restore-user-role", "name": "Restore user role", "description": "Restore user role"},
            {"code": "restore-role-permission", "name": "Restore role permission", "description": "Restore role permission"},
            # Разрешения для логов
            {"code": "get-story-user", "name": "Get story user", "description": "Get change history for user"},
            {"code": "get-story-role", "name": "Get story role", "description": "Get change history for role"},
            {"code": "get-story-permission", "name": "Get story permission", "description": "Get change history for permission"},
            {"code": "restore-user", "name": "Restore user", "description": "Restore user from history"},
            {"code": "restore-role", "name": "Restore role", "description": "Restore role from history"},
            {"code": "restore-permission", "name": "Restore permission", "description": "Restore permission from history"},
        ]
        for perm in extra_permissions:
            if not Permission.select().where(Permission.code == perm["code"]).exists():
                Permission.create(
                    name=perm["name"],
                    description=perm["description"],
                    code=perm["code"],
                    created_by=1
                )
    print("Разрешения успешно добавлены.")


def assign_permissions_to_roles():
    admin_role = Role.get(Role.code == "admin")
    user_role = Role.get(Role.code == "user")
    guest_role = Role.get(Role.code == "guest")
    permissions = {perm.code: perm for perm in Permission.select()}

    # Назначаем администратору все разрешения
    for permission in permissions.values():
        if not RolePermission.select().where(
                (RolePermission.role == admin_role) & (RolePermission.permission == permission)
        ).exists():
            RolePermission.create(role=admin_role, permission=permission, created_by=1)

    # Назначаем пользователю только ограниченные разрешения
    user_permissions = ["get-list-user", "read-user", "update-user"]
    for code in user_permissions:
        if code in permissions and not RolePermission.select().where(
                (RolePermission.role == user_role) & (RolePermission.permission == permissions[code])
        ).exists():
            RolePermission.create(role=user_role, permission=permissions[code], created_by=1)  # Исправлено здесь

    # Назначаем гостю только разрешение на просмотр списка пользователей
    guest_permissions = ["get-list-user"]
    for code in guest_permissions:
        if code in permissions and not RolePermission.select().where(
                (RolePermission.role == guest_role) & (RolePermission.permission == permissions[code])
        ).exists():
            RolePermission.create(role=guest_role, permission=permissions[code], created_by=1)

    print("Роли и разрешения назначены согласно ТЗ.")


def seed_users():
    # Создаем тестового пользователя и назначаем ему роль Admin
    if not User.select().where(User.id == 1).exists():
        with db.atomic():
            # Хешируем пароль для тестового пользователя
            password_hash = generate_password_hash("test_password")

            # Создаем пользователя с хешированным паролем
            test_user = User.create(id=1, username="test_user", password_hash=password_hash, created_by=1)

            # Получаем роль Admin
            admin_role = Role.get(Role.code == "admin")

            # Назначаем роль Admin пользователю
            UserRole.create(user=test_user, role=admin_role, created_by=1)

    print("Тестовый пользователь с ролью Admin успешно добавлен.")


# Функция для создания таблиц и выполнения миграций
def initialize_database():
    db.connect()  # Открываем соединение с базой данных
    db.create_tables([Role, Permission, User, UserRole, RolePermission, ChangeLog], safe=True)  # Создаем таблицы
    print("Таблицы базы данных созданы.")
    db.close()  # Закрываем соединение после выполнения миграции



# Функция для заполнения базы данных начальными данными (сидами)
def seed_database():
    seed_roles()
    seed_permissions()
    assign_permissions_to_roles()
    seed_users()


# Маршруты для работы с логами изменений
@app.route('/api/ref/log/<string:entity>/<int:entity_id>/story', methods=['GET'])
def get_entity_logs(entity, entity_id):
    """
    Получение истории изменений для конкретной сущности и записи.
    """
    current_user_id = request.args.get('current_user_id')
    if not current_user_id:
        return jsonify({"error": "current_user_id не предоставлен"}), 400
    try:
        current_user_id = int(current_user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат current_user_id"}), 400
    # Проверка существования сущности
    if entity not in ['user', 'role', 'permission']:
        return jsonify({"error": "Неверное наименование сущности."}), 400
    # Преобразуем первую букву в верхний регистр для соответствия именам моделей
    entity_name = entity.capitalize()
    return change_log_controller.get_logs_for_entity(entity_name, entity_id, current_user_id)


@app.route('/api/ref/log/<string:entity>/<int:entity_id>/restore', methods=['POST'])
def restore_entity_from_log(entity, entity_id):
    """
    Восстановление состояния сущности из лога.
    """
    log_id = request.form.get('log_id')
    user_id_request = request.form.get('user_id')
    if not all([log_id, user_id_request]):
        return jsonify({"error": "log_id и user_id являются обязательными полями."}), 400
    try:
        log_id = int(log_id)
        user_id_request = int(user_id_request)
    except ValueError:
        return jsonify({"error": "Неверный формат log_id или user_id"}), 400
    # Проверка существования сущности
    if entity not in ['user', 'role', 'permission']:
        return jsonify({"error": "Неверное наименование сущности."}), 400
    # Преобразуем первую букву в верхний регистр для соответствия именам моделей
    entity_name = entity.capitalize()
    return change_log_controller.restore_from_log(entity_name, entity_id, log_id, user_id_request)


# Маршрут для получения истории изменений роли
@app.route('/api/ref/policy/role/<int:role_id>/story', methods=['GET'])
def get_role_story(role_id):
    """
    Получение истории изменений конкретной роли.
    """
    current_user_id = request.args.get('current_user_id')
    if not current_user_id:
        return jsonify({"error": "current_user_id не предоставлен"}), 400
    try:
        current_user_id = int(current_user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат current_user_id"}), 400
    return change_log_controller.get_logs_for_entity('Role', role_id, current_user_id)


# Маршрут для получения истории изменений разрешения
@app.route('/api/ref/policy/permission/<int:permission_id>/story', methods=['GET'])
def get_permission_story(permission_id):
    """
    Получение истории изменений конкретного разрешения.
    """
    current_user_id = request.args.get('current_user_id')
    if not current_user_id:
        return jsonify({"error": "current_user_id не предоставлен"}), 400
    try:
        current_user_id = int(current_user_id)
    except ValueError:
        return jsonify({"error": "Неверный формат current_user_id"}), 400
    return change_log_controller.get_logs_for_entity('Permission', permission_id, current_user_id)


# Маршрут для восстановления роли из лога
@app.route('/api/ref/policy/role/<int:role_id>/story/restore', methods=['POST'])
def restore_role_from_log(role_id):
    """
    Восстановление состояния роли из лога.
    """
    log_id = request.form.get('log_id')
    user_id_request = request.form.get('user_id')
    if not all([log_id, user_id_request]):
        return jsonify({"error": "log_id и user_id являются обязательными полями."}), 400
    try:
        log_id = int(log_id)
        user_id_request = int(user_id_request)
    except ValueError:
        return jsonify({"error": "Неверный формат log_id или user_id"}), 400
    return change_log_controller.restore_from_log('Role', role_id, log_id, user_id_request)


# Маршрут для восстановления разрешения из лога
@app.route('/api/ref/policy/permission/<int:permission_id>/story/restore', methods=['POST'])
def restore_permission_from_log(permission_id):
    """
    Восстановление состояния разрешения из лога.
    """
    log_id = request.form.get('log_id')
    user_id_request = request.form.get('user_id')
    if not all([log_id, user_id_request]):
        return jsonify({"error": "log_id и user_id являются обязательными полями."}), 400
    try:
        log_id = int(log_id)
        user_id_request = int(user_id_request)
    except ValueError:
        return jsonify({"error": "Неверный формат log_id или user_id"}), 400
    return change_log_controller.restore_from_log('Permission', permission_id, log_id, user_id_request)


# Маршрут для включения/выключения 2FA
@app.route('/api/user/<int:user_id>/2fa/toggle', methods=['POST'])
def toggle_2fa(user_id):
    user = User.get_or_none(User.id == user_id)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    password = request.form.get('password')
    if not password:
        return jsonify({"error": "Не указан пароль"}), 400

    # Проверяем правильность пароля
    if not user.check_password(password):
        return jsonify({"error": "Неверный пароль"}), 400

    # Переключаем режим 2FA
    user.is_2fa_enabled = not user.is_2fa_enabled
    user.save()

    if user.is_2fa_enabled:
        return jsonify({"message": "2FA включен для пользователя"}), 200
    else:
        return jsonify({"message": "2FA отключен для пользователя"}), 200


# Логика для получения нового 2FA кода
@app.route('/api/user/<int:user_id>/2fa/code', methods=['POST'])
def request_new_2fa_code(user_id):
    user = User.get_or_none(User.id == user_id)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    if not user.is_2fa_enabled:
        return jsonify({"error": "Двухфакторная аутентификация не включена для этого пользователя"}), 400

    device_id = request.form.get('device_id')
    if not device_id:
        return jsonify({"error": "Не указан ID устройства"}), 400

    app.logger.debug(f"Запрос на получение кода 2FA для пользователя {user_id} с device_id: {device_id}")

    now = datetime.now()

    # Инициализация логов запросов для пользователя и устройства
    if user_id not in request_logs:
        request_logs[user_id] = {}
    if device_id not in request_logs[user_id]:
        request_logs[user_id][device_id] = []

    # Очистка запросов старше 30 секунд
    recent_requests = [req_time for req_time in request_logs[user_id][device_id] if now - req_time < timedelta(seconds=30)]
    request_logs[user_id][device_id] = recent_requests

    if len(recent_requests) >= 3:
        last_request_time = recent_requests[-1]
        time_since_last_request = (now - last_request_time).seconds
        if time_since_last_request < 30:
            wait_time = 30 - time_since_last_request
            return jsonify({"error": f"Превышен лимит запросов. Пожалуйста, подождите {wait_time} секунд."}), 429

    try:
        new_code = user.generate_two_factor_code(device_id)
        # Логируем время запроса
        request_logs[user_id][device_id].append(now)
        return jsonify({"message": "Новый код для двухфакторной аутентификации сгенерирован", "code": new_code}), 200
    except ValueError as ve:
        app.logger.error(f"Ошибка при генерации кода 2FA: {ve}")
        return jsonify({"error": str(ve)}), 400
    except Exception as e:
        app.logger.error(f"Ошибка при генерации кода 2FA: {e}")
        return jsonify({"error": "Ошибка при генерации кода 2FA"}), 500





@app.route('/api/user/<int:user_id>/2fa/verify', methods=['POST'])
def verify_2fa_code(user_id):
    user = User.get_or_none(User.id == user_id)  # Использование Peewee для поиска пользователя
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    entered_code = request.form.get('code')
    device_id = request.form.get('device_id')

    if not entered_code:
        return jsonify({"error": "Не указан код 2FA"}), 400

    # Проверка, совпадает ли код и не истёк ли срок действия
    if user.two_factor_code != entered_code:
        return jsonify({"error": "Неверный код 2FA"}), 400

    if user.two_factor_expiry < datetime.now():
        return jsonify({"error": "Срок действия кода 2FA истёк"}), 400

    # Проверка, что код был запрашиваем с того же устройства
    if user.device_id != device_id:
        return jsonify({"error": "Код 2FA может быть использован только с устройства, которое его запросило"}), 400

    # Код подтверждён
    user.two_factor_code = None  # Стираем код после подтверждения
    user.two_factor_expiry = None
    user.device_id = None  # Убираем привязку устройства
    user.save()

    return jsonify({"message": "Код 2FA подтверждён успешно"}), 200



@app.errorhandler(Exception)
def handle_exception(e):
    # Логируем полную информацию об ошибке
    app.logger.error(f"Ошибка: {e}")
    return jsonify({"error": "Произошла непредвиденная ошибка"}), 500


@app.route('/api/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.get_or_none(User.username == username)

    if not user or user.password != password:
        return jsonify({"error": "Неверное имя пользователя или пароль"}), 400

    # Если включен 2FA, запрашиваем код
    if user.is_2fa_enabled:
        return jsonify({"message": "Введите код 2FA"}), 200

    # Пользователь прошёл стандартную аутентификацию
    return jsonify({"message": "Авторизация успешна"}), 200

@app.route('/api/user/<int:user_id>/set_password', methods=['POST'])
def set_user_password(user_id):
    user = User.get_or_none(User.id == user_id)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    password = request.form.get('password')
    if not password:
        return jsonify({"error": "Не указан пароль"}), 400

    # Устанавливаем новый пароль для пользователя
    user.set_password(password)

    return jsonify({"message": "Пароль успешно установлен"}), 200

@app.route('/api/user/create', methods=['POST'])
def create_user():
    data = request.get_json()  # Получаем данные в формате JSON
    username = data.get('username')
    password = data.get('password')
    created_by = 1  # Например, ID администратора, который создает пользователя

    if not username or not password:
        return jsonify({"error": "Необходимо указать имя пользователя и пароль"}), 400

    # Проверяем, существует ли уже пользователь с таким именем
    if User.select().where(User.username == username).exists():
        return jsonify({"error": "Пользователь с таким именем уже существует"}), 400

    try:
        user = User.create_user(username, password, created_by)
        return jsonify({"message": "Пользователь успешно создан", "username": user.username}), 201
    except Exception as e:
        app.logger.error(f"Ошибка при создании пользователя: {e}")
        return jsonify({"error": "Произошла ошибка при создании пользователя"}), 500


@app.route('/api/user/login', methods=['POST'])
def login_user():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = User.get_or_none(User.username == username)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404

    if not user.check_password(password):
        return jsonify({"error": "Неверный пароль"}), 400

    return jsonify({"message": "Успешная авторизация"}), 200

@app.route('/api/user/register', methods=['POST'])
def register_user():
    username = request.form.get('username')
    password = request.form.get('password')
    created_by = request.form.get('created_by')
    is_2fa_enabled = request.form.get('is_2fa_enabled')

    # Проверка на существующего пользователя
    if User.select().where(User.username == username).exists():
        return jsonify({"error": "Пользователь с таким именем уже существует."}), 400

    try:
        password_hash = generate_password_hash(password)
        new_user = User.create(username=username, password_hash=password_hash, created_by=created_by, is_2fa_enabled=is_2fa_enabled)
        return jsonify({"message": "Пользователь успешно зарегистрирован."}), 201
    except IntegrityError as e:
        return jsonify({"error": "Ошибка при создании пользователя."}), 500



# Инициализация базы данных и создание таблиц
initialize_database()

# Выполнение функций для начальной настройки базы данных
seed_database()

# Запуск приложения
if __name__ == "__main__":
    app.run(debug=True)

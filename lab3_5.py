# Импорт необходимых модулей из библиотеки peewee для работы с базой данных
from peewee import Model, CharField, DateTimeField, IntegerField, BooleanField, ForeignKeyField, SqliteDatabase
# Импорт модулей Flask для создания веб-приложения
from flask import Flask, jsonify, request
# Импорт модуля datetime для работы с датой и временем
from datetime import datetime

# Инициализация базы данных SQLite
db = SqliteDatabase('roles_permissions.db')


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


# Модель Пользователя
class User(BaseModel):
    # Имя пользователя (уникальное и обязательное)
    username = CharField(unique=True, null=False)

    # Метод для получения ролей пользователя
    def roles(self):
        # Возвращает список ролей, исключая мягко удаленные
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
        self.roles = [RoleDTO(role) for role in roles if not role.is_deleted]


# DTO для передачи коллекции разрешений
class PermissionCollectionDTO:
    def __init__(self, permissions):
        # Создаем список DTO для каждого разрешения, исключая мягко удаленные
        self.permissions = [PermissionDTO(permission) for permission in permissions if not permission.is_deleted]


# Функция для мягкого удаления записи
def soft_delete(instance, user_id):
    # Устанавливаем флаг is_deleted и заполняем служебные поля
    instance.is_deleted = True
    instance.deleted_at = datetime.now()
    instance.deleted_by = user_id
    instance.save()


# Функция для проверки авторизации пользователя
def require_authorization(user_id):
    if not user_id:
        raise UnauthorizedError("Требуется авторизация.")


# Исключение для случаев отсутствия авторизации
class UnauthorizedError(Exception):
    pass


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
        role = Role.create(name=self.name, description=self.description, code=self.code, created_by=self.created_by)
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
        role = Role.get_by_id(self.role_id)
        role.name = self.name
        role.description = self.description
        role.code = self.code
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
        permission = Permission.create(name=self.name, description=self.description, code=self.code,
                                       created_by=self.created_by)
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
        permission = Permission.get_by_id(self.permission_id)
        permission.name = self.name
        permission.description = self.description
        permission.code = self.code
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
        role_dto = create_request.execute()
        return jsonify(role_dto.__dict__), 201

    def update_role(self, update_request):
        try:
            update_request.validate()
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        # Проверка наличия разрешения на обновление роли
        if not check_permission(update_request.updated_by, 'update-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: update-role"}), 403
        # Обновление роли
        role_dto = update_request.execute()
        return jsonify(role_dto.__dict__), 200

    def delete_role(self, role_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на удаление роли
        if not check_permission(deleted_by, 'delete-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: delete-role"}), 403
        # Жесткое удаление роли
        role = Role.get_or_none(Role.id == role_id)
        if not role:
            return jsonify({"error": "Роль не найдена"}), 404
        role.delete_instance()
        return jsonify({"message": "Роль удалена"}), 204

    def soft_delete_role(self, role_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на мягкое удаление роли
        if not check_permission(deleted_by, 'delete-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: delete-role"}), 403
        # Мягкое удаление роли
        role = Role.get_or_none(Role.id == role_id, Role.is_deleted == False)
        if not role:
            return jsonify({"error": "Роль не найдена"}), 404
        soft_delete(role, deleted_by)
        return jsonify({"message": "Роль мягко удалена"}), 200

    def restore_role(self, role_id, user_id):
        require_authorization(user_id)
        # Проверка наличия разрешения на восстановление роли
        if not check_permission(user_id, 'restore-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: restore-role"}), 403
        # Восстановление мягко удаленной роли
        role = Role.get_or_none(Role.id == role_id, Role.is_deleted == True)
        if not role:
            return jsonify({"error": "Роль не найдена или не была мягко удалена"}), 404
        role.is_deleted = False
        role.deleted_at = None
        role.deleted_by = None
        role.save()
        return jsonify({"message": "Роль восстановлена"}), 200


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
        permission_dto = create_request.execute()
        return jsonify(permission_dto.__dict__), 201

    def update_permission(self, update_request):
        try:
            update_request.validate()
        except ValueError as ve:
            return jsonify({"error": str(ve)}), 400
        # Проверка наличия разрешения на обновление разрешения
        if not check_permission(update_request.updated_by, 'update-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: update-permission"}), 403
        # Обновление разрешения
        permission_dto = update_request.execute()
        return jsonify(permission_dto.__dict__), 200

    def delete_permission(self, permission_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на удаление разрешения
        if not check_permission(deleted_by, 'delete-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: delete-permission"}), 403
        # Жесткое удаление разрешения
        permission = Permission.get_or_none(Permission.id == permission_id)
        if not permission:
            return jsonify({"error": "Разрешение не найдено"}), 404
        permission.delete_instance()
        return jsonify({"message": "Разрешение удалено"}), 204

    def soft_delete_permission(self, permission_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на мягкое удаление разрешения
        if not check_permission(deleted_by, 'delete-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: delete-permission"}), 403
        # Мягкое удаление разрешения
        permission = Permission.get_or_none(Permission.id == permission_id, Permission.is_deleted == False)
        if not permission:
            return jsonify({"error": "Разрешение не найдено"}), 404
        soft_delete(permission, deleted_by)
        return jsonify({"message": "Разрешение мягко удалено"}), 200

    def restore_permission(self, permission_id, user_id):
        require_authorization(user_id)
        # Проверка наличия разрешения на восстановление разрешения
        if not check_permission(user_id, 'restore-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: restore-permission"}), 403
        # Восстановление мягко удаленного разрешения
        permission = Permission.get_or_none(Permission.id == permission_id, Permission.is_deleted == True)
        if not permission:
            return jsonify({"error": "Разрешение не найдено или не было мягко удалено"}), 404
        permission.is_deleted = False
        permission.deleted_at = None
        permission.deleted_by = None
        permission.save()
        return jsonify({"message": "Разрешение восстановлено"}), 200


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
        if RolePermission.select().where(RolePermission.role == role, RolePermission.permission == permission,
                                         RolePermission.is_deleted == False).exists():
            return jsonify({"error": "Разрешение уже назначено роли"}), 400
        # Присвоение разрешения роли
        RolePermission.create(role=role, permission=permission, created_by=created_by)
        return jsonify({"message": "Разрешение назначено роли"}), 201

    def remove_permission_from_role(self, role_id, permission_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на удаление разрешения у роли
        if not check_permission(deleted_by, 'remove-permission-from-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: remove-permission-from-role"}), 403
        # Проверка существования связи роль-разрешение
        role_permission = RolePermission.get_or_none(RolePermission.role_id == role_id,
                                                     RolePermission.permission_id == permission_id,
                                                     RolePermission.is_deleted == False)
        if not role_permission:
            return jsonify({"error": "Разрешение не назначено роли"}), 404
        # Жесткое удаление связи
        role_permission.delete_instance()
        return jsonify({"message": "Разрешение удалено у роли"}), 204

    def soft_delete_role_permission(self, role_id, permission_id, deleted_by):
        require_authorization(deleted_by)
        # Проверка наличия разрешения на мягкое удаление разрешения у роли
        if not check_permission(deleted_by, 'remove-permission-from-role'):
            return jsonify({"error": "Доступ запрещен. Требуется: remove-permission-from-role"}), 403
        # Проверка существования связи роль-разрешение
        role_permission = RolePermission.get_or_none(RolePermission.role_id == role_id,
                                                     RolePermission.permission_id == permission_id,
                                                     RolePermission.is_deleted == False)
        if not role_permission:
            return jsonify({"error": "Разрешение не назначено роли"}), 404
        # Мягкое удаление связи
        soft_delete(role_permission, deleted_by)
        return jsonify({"message": "Разрешение мягко удалено у роли"}), 200

    def restore_role_permission(self, role_id, permission_id, user_id):
        require_authorization(user_id)
        # Проверка наличия разрешения на восстановление связи роль-разрешение
        if not check_permission(user_id, 'restore-role-permission'):
            return jsonify({"error": "Доступ запрещен. Требуется: restore-role-permission"}), 403
        # Проверка существования мягко удаленной связи роль-разрешение
        role_permission = RolePermission.get_or_none(RolePermission.role_id == role_id,
                                                     RolePermission.permission_id == permission_id,
                                                     RolePermission.is_deleted == True)
        if not role_permission:
            return jsonify({"error": "Связь роль-разрешение не найдена или не была мягко удалена"}), 404
        # Восстановление связи
        role_permission.is_deleted = False
        role_permission.deleted_at = None
        role_permission.deleted_by = None
        role_permission.save()
        return jsonify({"message": "Разрешение восстановлено у роли"}), 200


# Функция для проверки наличия у пользователя необходимого разрешения
def check_permission(user_id, permission_code):
    user = User.get_or_none(User.id == user_id)
    if not user:
        raise UnauthorizedError("Пользователь не найден.")
    # Проходим по ролям пользователя и их разрешениям
    for role in user.roles():
        for permission in role.permissions():
            if permission.code == permission_code:
                return True
    return False


# Инициализация приложения Flask
app = Flask(__name__)

# Инициализация контроллеров
role_controller = RoleController()
permission_controller = PermissionController()
role_permission_controller = RolePermissionController()

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
@app.route('/api/ref/user/', methods=['GET'])
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
    # Получение списка пользователей
    users = User.select()
    return jsonify([UserDTO(user).__dict__ for user in users]), 200

@app.route('/api/ref/user/<int:user_id>/role', methods=['GET'])
def get_user_roles_route(user_id):
    user_id_request = request.args.get('user_id')
    if not user_id_request:
        return jsonify({"error": "user_id не предоставлен"}), 400
    try:
        user_id_request = int(user_id_request)
    except ValueError:
        return jsonify({"error": "Неверный формат user_id"}), 400
    require_authorization(user_id_request)
    # Проверка наличия разрешения на чтение пользователя
    if not check_permission(user_id_request, 'read-user'):
        return jsonify({"error": "Доступ запрещен. Требуется: read-user"}), 403
    user = User.get_or_none(User.id == user_id)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    # Возвращаем список шифров ролей пользователя
    return jsonify([role.code for role in user.roles()]), 200


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

    require_authorization(created_by)
    # Проверка наличия разрешения на присвоение роли пользователю
    if not check_permission(created_by, 'assign-role-to-user'):
        return jsonify({"error": "Доступ запрещен. Требуется: assign-role-to-user"}), 403
    # Проверка существования пользователя и роли
    role = Role.get_or_none(Role.id == role_id, Role.is_deleted == False)
    if not role:
        return jsonify({"error": "Роль не найдена"}), 404
    user = User.get_or_none(User.id == user_id)
    if not user:
        return jsonify({"error": "Пользователь не найден"}), 404
    # Проверка, не назначена ли роль уже пользователю
    if UserRole.select().where(UserRole.user == user, UserRole.role == role, UserRole.is_deleted == False).exists():
        return jsonify({"error": "Роль уже назначена пользователю"}), 400
    # Присвоение роли пользователю
    UserRole.create(user=user, role=role, created_by=created_by)
    return jsonify({"message": "Роль назначена пользователю"}), 201

@app.route('/api/ref/user/<int:user_id>/role/<int:role_id>', methods=['DELETE'])
def remove_role_from_user_route(user_id, role_id):
    deleted_by = request.form.get('deleted_by')
    if not deleted_by:
        return jsonify({"error": "deleted_by не предоставлен"}), 400
    try:
        deleted_by = int(deleted_by)
    except ValueError:
        return jsonify({"error": "Неверный формат deleted_by"}), 400
    require_authorization(deleted_by)
    # Проверка наличия разрешения на удаление роли у пользователя
    if not check_permission(deleted_by, 'remove-role-from-user'):
        return jsonify({"error": "Доступ запрещен. Требуется: remove-role-from-user"}), 403
    # Проверка существования связи пользователь-роль
    user_role = UserRole.get_or_none(UserRole.user_id == user_id, UserRole.role_id == role_id, UserRole.is_deleted == False)
    if not user_role:
        return jsonify({"error": "Роль не назначена пользователю"}), 404
    # Жесткое удаление связи
    user_role.delete_instance()
    return jsonify({"message": "Роль удалена у пользователя"}), 204

@app.route('/api/ref/user/<int:user_id>/role/<int:role_id>/soft', methods=['DELETE'])
def soft_delete_user_role_route(user_id, role_id):
    deleted_by = request.form.get('deleted_by')
    if not deleted_by:
        return jsonify({"error": "deleted_by не предоставлен"}), 400
    try:
        deleted_by = int(deleted_by)
    except ValueError:
        return jsonify({"error": "Неверный формат deleted_by"}), 400
    require_authorization(deleted_by)
    # Проверка наличия разрешения на мягкое удаление роли у пользователя
    if not check_permission(deleted_by, 'remove-role-from-user'):
        return jsonify({"error": "Доступ запрещен. Требуется: remove-role-from-user"}), 403
    # Проверка существования связи пользователь-роль
    user_role = UserRole.get_or_none(UserRole.user_id == user_id, UserRole.role_id == role_id, UserRole.is_deleted == False)
    if not user_role:
        return jsonify({"error": "Связь пользователь-роль не найдена"}), 404
    # Мягкое удаление связи
    soft_delete(user_role, deleted_by)
    return jsonify({"message": "Роль мягко удалена у пользователя"}), 200

@app.route('/api/ref/user/<int:user_id>/role/<int:role_id>/restore', methods=['POST'])
def restore_user_role_route(user_id, role_id):
    user_id_request = request.form.get('user_id')
    if not user_id_request:
        return jsonify({"error": "user_id не предоставлен"}), 400
    try:
        user_id_request = int(user_id_request)
    except ValueError:
        return jsonify({"error": "Неверный формат user_id"}), 400
    require_authorization(user_id_request)
    # Проверка наличия разрешения на восстановление роли у пользователя
    if not check_permission(user_id_request, 'restore-user-role'):
        return jsonify({"error": "Доступ запрещен. Требуется: restore-user-role"}), 403
    # Проверка существования мягко удаленной связи пользователь-роль
    user_role = UserRole.get_or_none(UserRole.user_id == user_id, UserRole.role_id == role_id, UserRole.is_deleted == True)
    if not user_role:
        return jsonify({"error": "Связь пользователь-роль не найдена или не была мягко удалена"}), 404
    # Восстановление связи
    user_role.is_deleted = False
    user_role.deleted_at = None
    user_role.deleted_by = None
    user_role.save()
    return jsonify({"message": "Роль восстановлена у пользователя"}), 200

# Инициализация базы данных и создание таблиц
db.connect()
db.create_tables([Role, Permission, User, UserRole, RolePermission])


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
                Role.create(name=role_data["name"], description=role_data["description"], code=role_data["code"],
                            created_by=1)
    print("Роли успешно добавлены.")


def seed_permissions():
    entities = ["user", "role", "permission"]
    actions = ["get-list", "read", "create", "update", "delete", "restore"]
    with db.atomic():
        for entity in entities:
            for action in actions:
                code = f"{action}-{entity}"
                if not Permission.select().where(Permission.code == code).exists():
                    Permission.create(name=f"{action.capitalize()} {entity}", description=f"{action} access to {entity}",
                                      code=code, created_by=1)
        # Дополнительные разрешения для управления связями
        extra_permissions = [
            {"code": "assign-role-to-user", "name": "Assign role to user", "description": "Assign role to user"},
            {"code": "remove-role-from-user", "name": "Remove role from user", "description": "Remove role from user"},
            {"code": "assign-permission-to-role", "name": "Assign permission to role", "description": "Assign permission to role"},
            {"code": "remove-permission-from-role", "name": "Remove permission from role", "description": "Remove permission from role"},
            {"code": "restore-user-role", "name": "Restore user role", "description": "Restore user role"},
            {"code": "restore-role-permission", "name": "Restore role permission", "description": "Restore role permission"},
        ]
        for perm in extra_permissions:
            if not Permission.select().where(Permission.code == perm["code"]).exists():
                Permission.create(name=perm["name"], description=perm["description"], code=perm["code"], created_by=1)
    print("Разрешения успешно добавлены.")


def assign_permissions_to_roles():
    admin_role = Role.get(Role.code == "admin")
    user_role = Role.get(Role.code == "user")
    guest_role = Role.get(Role.code == "guest")
    permissions = {perm.code: perm for perm in Permission.select()}

    # Назначаем администратору все разрешения
    for permission in permissions.values():
        if not RolePermission.select().where(
                (RolePermission.role == admin_role) & (RolePermission.permission == permission)).exists():
            RolePermission.create(role=admin_role, permission=permission, created_by=1)

    # Назначаем пользователю только ограниченные разрешения
    user_permissions = ["get-list-user", "read-user", "update-user"]
    for code in user_permissions:
        if code in permissions and not RolePermission.select().where(
                (RolePermission.role == user_role) & (RolePermission.permission == permissions[code])).exists():
            RolePermission.create(role=role_user, permission=permissions[code], created_by=1)

    # Назначаем гостю только разрешение на просмотр списка пользователей
    guest_permissions = ["get-list-user"]
    for code in guest_permissions:
        if code in permissions and not RolePermission.select().where(
                (RolePermission.role == guest_role) & (RolePermission.permission == permissions[code])).exists():
            RolePermission.create(role=guest_role, permission=permissions[code], created_by=1)

    print("Роли и разрешения назначены согласно ТЗ.")


def seed_users():
    # Создаем тестового пользователя и назначаем ему роль Admin
    if not User.select().where(User.id == 1).exists():
        test_user = User.create(id=1, username="test_user", created_by=1)
        admin_role = Role.get(Role.code == "admin")
        UserRole.create(user=test_user, role=admin_role, created_by=1)
    print("Тестовый пользователь с ролью Admin успешно добавлен.")


# Выполнение функций для начальной настройки базы данных
seed_roles()
seed_permissions()
assign_permissions_to_roles()
seed_users()

# Запуск приложения
if __name__ == "__main__":
    app.run(debug=True)

from flask import Flask, request, jsonify
from peewee import DoesNotExist
from models import Role, Permission, User, UsersAndRoles, RolesAndPermissions
from dto import RoleDTO, UserDTO, PermissionDTO

app = Flask(__name__)


@app.route('/api/ref/policy/role', methods=['POST', 'GET'])
def create_role():
    # Проверка заголовка Content-Type, если не установлен, установить по умолчанию
    content_type = request.headers.get('Content-Type', 'application/json')

    if content_type != 'application/json':
        return jsonify({"error": "Content-Type must be application/json"}), 400

    data = request.get_json()
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    # Пример логики создания роли
    role = {
        "name": data.get('name'),
        "description": data.get('description'),
        "code": data.get('code')
    }

    # Ваш код для добавления роли в базу данных здесь (например, с использованием Peewee)

    return jsonify(role), 201


@app.route('/api/ref/user', methods=['GET', 'POST'])
def get_users():
    users = User.select()
    return jsonify([UserDTO(user).__dict__ for user in users])

@app.route('/api/ref/user/<int:user_id>/role', methods=['POST'])
def assign_role_to_user(user_id):
    data = request.get_json()
    try:
        user = User.get_by_id(user_id)
        role = Role.get(Role.name == data['role_name'])
        UsersAndRoles.create(user=user, role=role)
        return jsonify({"message": f"Role {role.name} assigned to user {user.username}."}), 200
    except DoesNotExist:
        return jsonify({'error': 'User or role not found'}), 404

if __name__ == '__main__':
    app.run(debug=True)

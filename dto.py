class RoleDTO:
    def __init__(self, role):
        self.id = role.id
        self.name = role.name
        self.description = role.description
        self.code = role.code

class UserDTO:
    def __init__(self, user):
        self.id = user.id
        self.username = user.username
        self.email = user.email
        self.roles = [role.name for role in user.roles()]

class PermissionDTO:
    def __init__(self, permission):
        self.id = permission.id
        self.name = permission.name
        self.description = permission.description
        self.code = permission.code

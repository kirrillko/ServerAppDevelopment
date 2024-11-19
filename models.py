from peewee import *
import datetime

db = SqliteDatabase('app.db')

class BaseModel(Model):
    created_at = DateTimeField(default=datetime.datetime.now)
    created_by = IntegerField()
    deleted_at = DateTimeField(null=True)
    deleted_by = IntegerField(null=True)

    class Meta:
        database = db

class Role(BaseModel):
    name = CharField(unique=True)
    description = TextField()
    code = CharField(unique=True)

    def permissions(self):
        return Permission.select().join(RolesAndPermissions).where(RolesAndPermissions.role == self)

class Permission(BaseModel):
    name = CharField(unique=True)
    description = TextField()
    code = CharField(unique=True)

class User(BaseModel):
    username = CharField(unique=True)
    email = CharField(unique=True)

    def roles(self):
        return Role.select().join(UsersAndRoles).where(UsersAndRoles.user == self)

class UsersAndRoles(BaseModel):
    user = ForeignKeyField(User)
    role = ForeignKeyField(Role)

class RolesAndPermissions(BaseModel):
    role = ForeignKeyField(Role)
    permission = ForeignKeyField(Permission)

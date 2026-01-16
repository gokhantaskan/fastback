from sqladmin import ModelView

from app.models.user import User


class UserAdmin(ModelView, model=User):
    name = "User"
    name_plural = "Users"

    column_list = [
        User.id,
        User.email,
        User.first_name,
        User.last_name,
        User.is_active,
        User.email_verified,
    ]
    column_searchable_list = [
        User.email,
        User.first_name,
        User.last_name,
        User.firebase_uid,
    ]
    column_sortable_list = [
        User.id,
        User.email,
        User.first_name,
        User.last_name,
        User.is_active,
        User.email_verified,
    ]

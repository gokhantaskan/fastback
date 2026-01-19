from sqladmin import ModelView

from app.user.models import User


class UserAdmin(ModelView, model=User):
    name = "User"
    name_plural = "Users"

    column_list = [
        *User.model_fields.keys(),
    ]

    column_searchable_list = [
        User.email,
        User.first_name,
        User.last_name,
        User.external_id,
    ]

    column_sortable_list = [
        *User.model_fields.keys(),
    ]

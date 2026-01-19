from sqladmin import ModelView

from app.user.models import User


class UserAdmin(ModelView, model=User):
    name = "User"
    name_plural = "Users"

    column_list = [
        User.email,
        User.first_name,
        User.last_name,
        User.status,
        User.id,
        User.external_id,
        User.is_admin,
        User.created_at,
        User.updated_at,
    ]

    column_searchable_list = [
        User.email,
        User.first_name,
        User.last_name,
        User.external_id,
    ]

    column_sortable_list = [getattr(User, field) for field in User.model_fields]

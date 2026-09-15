from __future__ import annotations

import uuid

from advanced_alchemy.repository import SQLAlchemySyncRepository
from sqlalchemy import select

from ads_preferences.models import UserModel


class UserModelRepository(SQLAlchemySyncRepository[UserModel]):
    """Data layer. Requires an open transaction and never begins one."""

    model_type = UserModel

    def list_for_user(self, user_id: uuid.UUID) -> list[UserModel]:
        statement = (
            select(UserModel)
            .where(UserModel.user_id == user_id)
            .order_by(UserModel.name.asc(), UserModel.id.asc())
        )
        return list(self.session.scalars(statement).all())

    def get_for_user(self, user_id: uuid.UUID, model_id: uuid.UUID) -> UserModel | None:
        statement = select(UserModel).where(
            UserModel.user_id == user_id,
            UserModel.id == model_id,
        )
        return self.session.scalars(statement).first()

    def insert_for_user(self, row: UserModel) -> UserModel:
        self.session.add(row)
        self.session.flush()
        return row

    def update_for_user(self, row: UserModel) -> UserModel:
        self.session.flush()
        return row

    def delete_for_user(self, user_id: uuid.UUID, model_id: uuid.UUID) -> bool:
        row = self.get_for_user(user_id, model_id)
        if row is None:
            return False
        self.session.delete(row)
        self.session.flush()
        return True

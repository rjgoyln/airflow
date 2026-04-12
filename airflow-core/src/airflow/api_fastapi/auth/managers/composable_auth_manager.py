#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

from airflow.api_fastapi.auth.managers.base_auth_manager import BaseAuthManager
from airflow.api_fastapi.auth.managers.models.base_user import BaseUser
from airflow.configuration import conf
from airflow.exceptions import AirflowConfigException

if TYPE_CHECKING:
    from fastapi import FastAPI

    from airflow.api_fastapi.auth.managers.base_auth_manager import ResourceMethod
    from airflow.api_fastapi.auth.managers.models.resource_details import (
        AccessView,
        AssetAliasDetails,
        AssetDetails,
        ConfigurationDetails,
        ConnectionDetails,
        DagAccessEntity,
        DagDetails,
        PoolDetails,
        TeamDetails,
        VariableDetails,
    )
    from airflow.api_fastapi.common.types import ExtraMenuItem, MenuItem
    from airflow.cli.cli_config import CLICommand


class ComposableAuthManager(BaseAuthManager[BaseUser]):
    """Compose authentication and authorization from two independent auth managers."""

    def __init__(self) -> None:
        authn_manager_cls = self._get_configured_manager_cls("authn_manager")
        authz_manager_cls = self._get_configured_manager_cls("authz_manager")

        if authn_manager_cls is authz_manager_cls:
            manager = authn_manager_cls()
            self._authn_manager = manager
            self._authz_manager = manager
        else:
            self._authn_manager = authn_manager_cls()
            self._authz_manager = authz_manager_cls()

    @staticmethod
    def _get_configured_manager_cls(config_key: str) -> type[BaseAuthManager]:
        manager_cls = conf.getimport(section="core", key=config_key, fallback=None)
        if manager_cls is None:
            raise AirflowConfigException(
                f"No auth manager defined in the config. Please specify [core] {config_key}."
            )

        if not isinstance(manager_cls, type) or not issubclass(manager_cls, BaseAuthManager):
            raise AirflowConfigException(
                f'The "{config_key}" key in "core" section must point to a BaseAuthManager subclass. '
                f"Current value: {manager_cls!r}."
            )
        return manager_cls

    @staticmethod
    def _iter_unique_manager_classes() -> tuple[type[BaseAuthManager], ...]:
        authn_manager_cls = ComposableAuthManager._get_configured_manager_cls("authn_manager")
        authz_manager_cls = ComposableAuthManager._get_configured_manager_cls("authz_manager")
        if authn_manager_cls is authz_manager_cls:
            return (authn_manager_cls,)
        return (authn_manager_cls, authz_manager_cls)

    def _iter_unique_managers(self) -> tuple[BaseAuthManager, ...]:
        if self._authn_manager is self._authz_manager:
            return (self._authn_manager,)
        return (self._authn_manager, self._authz_manager)

    def init(self) -> None:
        for manager in self._iter_unique_managers():
            manager.init()

    async def get_user_from_token(self, token: str) -> BaseUser:
        return await self._authn_manager.get_user_from_token(token)

    def generate_jwt(
        self,
        user: BaseUser,
        *,
        expiration_time_in_seconds: int = conf.getint("api_auth", "jwt_expiration_time"),
    ) -> str:
        return self._authn_manager.generate_jwt(
            user=cast("Any", user), expiration_time_in_seconds=expiration_time_in_seconds
        )

    def revoke_token(self, token: str) -> None:
        self._authn_manager.revoke_token(token)

    def deserialize_user(self, token: dict[str, Any]) -> BaseUser:
        return self._authn_manager.deserialize_user(token)

    def serialize_user(self, user: BaseUser) -> dict[str, Any]:
        return self._authn_manager.serialize_user(cast("Any", user))

    def get_url_login(self, **kwargs) -> str:
        return self._authn_manager.get_url_login(**kwargs)

    def get_url_logout(self) -> str | None:
        return self._authn_manager.get_url_logout()

    def refresh_user(self, *, user: BaseUser) -> BaseUser | None:
        return self._authn_manager.refresh_user(user=cast("Any", user))

    def is_authorized_configuration(
        self,
        *,
        method: ResourceMethod,
        user: BaseUser,
        details: ConfigurationDetails | None = None,
    ) -> bool:
        return self._authz_manager.is_authorized_configuration(
            method=method, user=cast("Any", user), details=details
        )

    def is_authorized_connection(
        self,
        *,
        method: ResourceMethod,
        user: BaseUser,
        details: ConnectionDetails | None = None,
    ) -> bool:
        return self._authz_manager.is_authorized_connection(
            method=method, user=cast("Any", user), details=details
        )

    def is_authorized_dag(
        self,
        *,
        method: ResourceMethod,
        user: BaseUser,
        access_entity: DagAccessEntity | None = None,
        details: DagDetails | None = None,
    ) -> bool:
        return self._authz_manager.is_authorized_dag(
            method=method,
            user=cast("Any", user),
            access_entity=access_entity,
            details=details,
        )

    def is_authorized_asset(
        self,
        *,
        method: ResourceMethod,
        user: BaseUser,
        details: AssetDetails | None = None,
    ) -> bool:
        return self._authz_manager.is_authorized_asset(method=method, user=cast("Any", user), details=details)

    def is_authorized_asset_alias(
        self,
        *,
        method: ResourceMethod,
        user: BaseUser,
        details: AssetAliasDetails | None = None,
    ) -> bool:
        return self._authz_manager.is_authorized_asset_alias(
            method=method, user=cast("Any", user), details=details
        )

    def is_authorized_pool(
        self,
        *,
        method: ResourceMethod,
        user: BaseUser,
        details: PoolDetails | None = None,
    ) -> bool:
        return self._authz_manager.is_authorized_pool(method=method, user=cast("Any", user), details=details)

    def is_authorized_team(
        self,
        *,
        method: ResourceMethod,
        user: BaseUser,
        details: TeamDetails | None = None,
    ) -> bool:
        return self._authz_manager.is_authorized_team(method=method, user=cast("Any", user), details=details)

    def is_authorized_variable(
        self,
        *,
        method: ResourceMethod,
        user: BaseUser,
        details: VariableDetails | None = None,
    ) -> bool:
        return self._authz_manager.is_authorized_variable(
            method=method, user=cast("Any", user), details=details
        )

    def is_authorized_view(
        self,
        *,
        access_view: AccessView,
        user: BaseUser,
    ) -> bool:
        return self._authz_manager.is_authorized_view(access_view=access_view, user=cast("Any", user))

    def is_authorized_custom_view(
        self,
        *,
        method: ResourceMethod | str,
        resource_name: str,
        user: BaseUser,
    ) -> bool:
        return self._authz_manager.is_authorized_custom_view(
            method=cast("Any", method),
            resource_name=resource_name,
            user=cast("Any", user),
        )

    def filter_authorized_menu_items(self, menu_items: list[MenuItem], *, user: BaseUser) -> list[MenuItem]:
        return self._authz_manager.filter_authorized_menu_items(menu_items=menu_items, user=cast("Any", user))

    def is_authorized_hitl_task(self, *, assigned_users: set[str], user: BaseUser) -> bool:
        return self._authz_manager.is_authorized_hitl_task(
            assigned_users=assigned_users, user=cast("Any", user)
        )

    def get_extra_menu_items(self, *, user: BaseUser) -> list[ExtraMenuItem]:
        authn_items = self._authn_manager.get_extra_menu_items(user=cast("Any", user))
        authz_items = self._authz_manager.get_extra_menu_items(user=cast("Any", user))
        return [*authn_items, *authz_items]

    def get_fastapi_app(self) -> FastAPI | None:
        return self._authn_manager.get_fastapi_app()

    @staticmethod
    def get_cli_commands() -> list[CLICommand]:
        commands: list[CLICommand] = []
        seen_names: set[str] = set()
        for manager_cls in ComposableAuthManager._iter_unique_manager_classes():
            for command in manager_cls.get_cli_commands():
                if command.name in seen_names:
                    continue
                seen_names.add(command.name)
                commands.append(command)
        return commands

    def _get_teams(self) -> set[str]:
        return self._authz_manager._get_teams()

    @staticmethod
    def get_db_manager() -> str | None:
        db_managers = {
            db_manager
            for manager_cls in ComposableAuthManager._iter_unique_manager_classes()
            if (db_manager := manager_cls.get_db_manager())
        }

        if len(db_managers) > 1:
            raise AirflowConfigException(
                "Configured authn/authz managers require different DB managers. "
                "Please use managers that share the same DB manager or only one DB-backed manager."
            )

        return next(iter(db_managers), None)

"""
RemoteLink - Camada de Banco de Dados (PostgreSQL via asyncpg)
"""

import asyncio
import json
import time
import logging
import secrets
from datetime import datetime, timezone
from typing import Optional, List, Dict

from shared.protocol import verify_password, hash_password_bcrypt

import asyncpg

logger = logging.getLogger("rnremote.db")


class Database:
    """Gerencia conexão com PostgreSQL."""

    def __init__(self, dsn: str):
        """
        dsn exemplo: postgresql://remotelink:SENHA@localhost:5432/remotelink
        """
        self.dsn = dsn
        self.pool: Optional[asyncpg.Pool] = None

    async def connect(self):
        """Cria pool de conexões."""
        self.pool = await asyncpg.create_pool(
            self.dsn,
            min_size=2,
            max_size=10,
            command_timeout=30
        )
        logger.info("Conectado ao PostgreSQL")
        await self.ensure_agent_columns()
        await self.ensure_group_tables()
        await self.ensure_client_tables()
        await self.ensure_profile_tables()
        await self.ensure_access_tables()

    async def close(self):
        if self.pool:
            await self.pool.close()
            logger.info("Pool PostgreSQL fechado")

    # ─── Migração / Colunas ───

    async def ensure_agent_columns(self):
        """Verifica se as colunas necessárias existem na tabela agents."""
        async with self.pool.acquire() as conn:
            has_nickname = await conn.fetchval(
                "SELECT COUNT(*) FROM information_schema.columns "
                "WHERE table_name='agents' AND column_name='nickname'"
            )
            has_binding = await conn.fetchval(
                "SELECT COUNT(*) FROM information_schema.columns "
                "WHERE table_name='agents' AND column_name='binding_hash'"
            )
            if not has_nickname or not has_binding:
                # Requer que o superusuário postgres rode a migração manualmente:
                # ALTER TABLE agents ADD COLUMN IF NOT EXISTS nickname VARCHAR(200) DEFAULT '';
                # ALTER TABLE agents ADD COLUMN IF NOT EXISTS binding_hash VARCHAR(64);
                logger.warning(
                    "Colunas 'nickname' e/ou 'binding_hash' ausentes na tabela agents. "
                    "Execute a migração como superusuário do PostgreSQL."
                )

    # ─── Agentes ───

    async def provision_agent(self, nickname: str, password_hash: str,
                              binding_hash: str) -> str:
        """
        Cria um novo agente provisionado pelo painel.
        Gera agent_id único de 9 dígitos.
        Retorna o agent_id gerado.
        """
        async with self.pool.acquire() as conn:
            for _ in range(20):
                agent_id = ''.join([str(secrets.randbelow(10)) for _ in range(9)])
                exists = await conn.fetchval(
                    "SELECT 1 FROM agents WHERE agent_id = $1", agent_id
                )
                if not exists:
                    await conn.execute(
                        """
                        INSERT INTO agents
                            (agent_id, nickname, password_hash, binding_hash,
                             hostname, os_type, os_version, username,
                             is_online, last_seen, updated_at)
                        VALUES ($1, $2, $3, $4, '', '', '', '', FALSE, NOW(), NOW())
                        """,
                        agent_id, nickname, password_hash, binding_hash
                    )
                    return agent_id
            raise RuntimeError("Não foi possível gerar agent_id único")

    async def update_agent_binding(self, agent_id: str, binding_hash: str):
        """Atualiza o binding_hash de um agente recém-provisionado."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET binding_hash = $1 WHERE agent_id = $2",
                binding_hash, agent_id
            )

    async def register_agent(self, agent_id: str, password_hash: str,
                             hostname: str = "", os_type: str = "",
                             os_version: str = "", username: str = "",
                             ip_address: str = "", screen_width: int = 0,
                             screen_height: int = 0) -> dict:
        """Registra ou atualiza agente no banco."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO agents (agent_id, password_hash, hostname, os_type,
                    os_version, username, ip_address, screen_width, screen_height,
                    is_online, last_seen, updated_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, TRUE, NOW(), NOW())
                ON CONFLICT (agent_id) DO UPDATE SET
                    hostname = EXCLUDED.hostname,
                    os_type = EXCLUDED.os_type,
                    os_version = EXCLUDED.os_version,
                    username = EXCLUDED.username,
                    ip_address = EXCLUDED.ip_address,
                    screen_width = EXCLUDED.screen_width,
                    screen_height = EXCLUDED.screen_height,
                    is_online = TRUE,
                    last_seen = NOW(),
                    updated_at = NOW()
                RETURNING *
                """,
                agent_id, password_hash, hostname, os_type,
                os_version, username, ip_address, screen_width, screen_height
            )
            return dict(row) if row else {}

    async def set_agent_offline(self, agent_id: str):
        """Marca agente como offline."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET is_online = FALSE, last_seen = NOW() WHERE agent_id = $1",
                agent_id
            )

    async def set_all_agents_offline(self):
        """Marca todos como offline (chamado no startup do relay)."""
        async with self.pool.acquire() as conn:
            await conn.execute("UPDATE agents SET is_online = FALSE")

    async def get_agent(self, agent_id: str) -> Optional[dict]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM agents WHERE agent_id = $1", agent_id
            )
            return dict(row) if row else None

    async def get_online_agents(self) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM agents WHERE is_online = TRUE ORDER BY last_seen DESC"
            )
            return [dict(r) for r in rows]

    async def get_all_agents(self) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM agents ORDER BY is_online DESC, last_seen DESC"
            )
            return [dict(r) for r in rows]

    async def get_all_agents_safe(self) -> List[dict]:
        """Retorna agentes sem campos sensíveis (password_hash, binding_hash)."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT id, agent_id, nickname, hostname, os_type, os_version,
                       username, ip_address, screen_width, screen_height,
                       is_online, last_seen, created_at, updated_at
                FROM agents ORDER BY is_online DESC, last_seen DESC
            """)
            return [dict(r) for r in rows]

    async def update_agent_heartbeat(self, agent_id: str):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET last_seen = NOW() WHERE agent_id = $1",
                agent_id
            )

    async def update_agent_nickname(self, agent_id: str, nickname: str):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "UPDATE agents SET nickname = $1 WHERE agent_id = $2",
                nickname, agent_id
            )

    async def delete_agent(self, agent_id: str):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM agents WHERE agent_id = $1", agent_id
            )

    # ─── Sessões ───

    async def create_session(self, session_id: str, agent_id: str,
                             viewer_id: str, viewer_ip: str = "",
                             viewer_name: str = "") -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO sessions (session_id, agent_id, viewer_id, viewer_ip, viewer_name, status)
                VALUES ($1, $2, $3, $4, $5, 'active')
                RETURNING *
                """,
                session_id, agent_id, viewer_id, viewer_ip, viewer_name
            )
            return dict(row) if row else {}

    async def end_session(self, session_id: str, bytes_transferred: int = 0):
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE sessions SET
                    ended_at = NOW(),
                    bytes_transferred = $2,
                    duration_seconds = EXTRACT(EPOCH FROM (NOW() - started_at))::INT,
                    status = 'ended'
                WHERE session_id = $1
                """,
                session_id, bytes_transferred
            )

    async def get_active_sessions(self) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """
                SELECT s.*, a.hostname, a.os_type
                FROM sessions s
                JOIN agents a ON a.agent_id = s.agent_id
                WHERE s.status = 'active'
                ORDER BY s.started_at DESC
                """
            )
            return [dict(r) for r in rows]

    async def get_session_history(self, limit: int = 100,
                                  agent_id: str = None) -> List[dict]:
        async with self.pool.acquire() as conn:
            if agent_id:
                rows = await conn.fetch(
                    """
                    SELECT s.*, a.hostname, a.os_type
                    FROM sessions s
                    JOIN agents a ON a.agent_id = s.agent_id
                    WHERE s.agent_id = $1
                    ORDER BY s.started_at DESC LIMIT $2
                    """,
                    agent_id, limit
                )
            else:
                rows = await conn.fetch(
                    """
                    SELECT s.*, a.hostname, a.os_type
                    FROM sessions s
                    JOIN agents a ON a.agent_id = s.agent_id
                    ORDER BY s.started_at DESC LIMIT $1
                    """,
                    limit
                )
            return [dict(r) for r in rows]

    async def end_all_active_sessions(self):
        """Encerra sessões ativas (chamado no startup)."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                UPDATE sessions SET status = 'ended', ended_at = NOW()
                WHERE status = 'active'
                """
            )

    # ─── Audit Log ───

    async def log_event(self, event_type: str, agent_id: str = None,
                        viewer_id: str = None, session_id: str = None,
                        ip_address: str = None, details: dict = None):
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO audit_logs (event_type, agent_id, viewer_id,
                    session_id, ip_address, details)
                VALUES ($1, $2, $3, $4, $5, $6)
                """,
                event_type, agent_id, viewer_id, session_id,
                ip_address, json.dumps(details) if details else None
            )

    async def get_audit_logs(self, limit: int = 200,
                             event_type: str = None) -> List[dict]:
        async with self.pool.acquire() as conn:
            if event_type:
                rows = await conn.fetch(
                    "SELECT * FROM audit_logs WHERE event_type = $1 ORDER BY created_at DESC LIMIT $2",
                    event_type, limit
                )
            else:
                rows = await conn.fetch(
                    "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT $1",
                    limit
                )
            return [dict(r) for r in rows]

    # ─── Admin Users ───

    async def authenticate_admin(self, email: str,
                                 password: str) -> Optional[dict]:
        """
        Autentica usuário admin.
        Aceita senha em claro e verifica contra bcrypt ou sha256 legado.
        Se o hash ainda for sha256, faz upgrade automático para bcrypt.
        """
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT * FROM admin_users WHERE email = $1 AND is_active = TRUE",
                email
            )
            if not row:
                return None
            stored_hash = row['password_hash']
            if not verify_password(password, stored_hash):
                return None
            # Migração automática: se ainda for sha256, atualiza para bcrypt
            if not (stored_hash.startswith("$2b$") or stored_hash.startswith("$2a$")):
                new_hash = hash_password_bcrypt(password)
                await conn.execute(
                    "UPDATE admin_users SET password_hash = $1 WHERE id = $2",
                    new_hash, row['id']
                )
            await conn.execute(
                "UPDATE admin_users SET last_login = NOW() WHERE id = $1",
                row['id']
            )
            return dict(row)

    async def get_all_admin_users(self) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT id, email, display_name, role, is_active, mfa_enabled, last_login, created_at
                   FROM admin_users ORDER BY created_at"""
            )
            return [dict(r) for r in rows]

    async def create_admin_user(self, email: str, password_hash: str,
                                display_name: str = "", role: str = "admin") -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO admin_users (email, username, password_hash, display_name, role)
                VALUES ($1, $1, $2, $3, $4)
                RETURNING id, email, display_name, role, is_active, created_at
                """,
                email, password_hash, display_name, role
            )
            return dict(row) if row else {}

    async def update_admin_user(self, user_id: int, email: str = None,
                                password_hash: str = None, display_name: str = None,
                                role: str = None, is_active: bool = None,
                                mfa_enabled: bool = None) -> bool:
        fields, values, idx = [], [], 1
        if email is not None:
            fields.append(f"email = ${idx}"); values.append(email); idx += 1
        if password_hash is not None:
            fields.append(f"password_hash = ${idx}"); values.append(password_hash); idx += 1
        if display_name is not None:
            fields.append(f"display_name = ${idx}"); values.append(display_name); idx += 1
        if role is not None:
            fields.append(f"role = ${idx}"); values.append(role); idx += 1
        if is_active is not None:
            fields.append(f"is_active = ${idx}"); values.append(is_active); idx += 1
        if mfa_enabled is not None:
            fields.append(f"mfa_enabled = ${idx}"); values.append(mfa_enabled); idx += 1
        if not fields:
            return False
        values.append(user_id)
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                f"UPDATE admin_users SET {', '.join(fields)} WHERE id = ${idx}",
                *values
            )
            return result == "UPDATE 1"

    async def get_admin_user_by_id(self, user_id: int) -> Optional[dict]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT id, email, role FROM admin_users WHERE id = $1", user_id
            )
            return dict(row) if row else None

    async def count_active_superadmins(self) -> int:
        async with self.pool.acquire() as conn:
            return await conn.fetchval(
                "SELECT COUNT(*) FROM admin_users WHERE role='superadmin' AND is_active=true"
            )

    async def delete_admin_user(self, user_id: int) -> bool:
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM admin_users WHERE id = $1", user_id
            )
            return result == "DELETE 1"

    # ─── Controle de Acesso por Usuário ───

    async def get_user_access(self, user_id: int) -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT access_all_clients, access_all_groups FROM admin_users WHERE id = $1",
                user_id
            )
            if not row:
                return {"all_clients": True, "client_ids": [], "all_groups": True, "group_ids": []}
            client_ids = []
            group_ids  = []
            if not row['access_all_clients']:
                r = await conn.fetch("SELECT client_id FROM user_client_access WHERE user_id = $1", user_id)
                client_ids = [x['client_id'] for x in r]
            if not row['access_all_groups']:
                r = await conn.fetch("SELECT group_id FROM user_group_access WHERE user_id = $1", user_id)
                group_ids = [x['group_id'] for x in r]
            return {
                "all_clients": bool(row['access_all_clients']),
                "client_ids":  client_ids,
                "all_groups":  bool(row['access_all_groups']),
                "group_ids":   group_ids,
            }

    async def set_user_access(self, user_id: int, all_clients: bool,
                              client_ids: List[int], all_groups: bool,
                              group_ids: List[int]):
        async with self.pool.acquire() as conn:
            async with conn.transaction():
                await conn.execute(
                    "UPDATE admin_users SET access_all_clients=$1, access_all_groups=$2 WHERE id=$3",
                    all_clients, all_groups, user_id
                )
                await conn.execute("DELETE FROM user_client_access WHERE user_id=$1", user_id)
                await conn.execute("DELETE FROM user_group_access  WHERE user_id=$1", user_id)
                if not all_clients and client_ids:
                    await conn.executemany(
                        "INSERT INTO user_client_access (user_id, client_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
                        [(user_id, cid) for cid in client_ids]
                    )
                if not all_groups and group_ids:
                    await conn.executemany(
                        "INSERT INTO user_group_access (user_id, group_id) VALUES ($1,$2) ON CONFLICT DO NOTHING",
                        [(user_id, gid) for gid in group_ids]
                    )

    # ─── Perfis (Profiles) ───

    ALL_MODULES = [
        'machines','dashboard','clients','sessions','audit',
        'agents','agent_linux','agent_pfsense','agent_windows',
        'agent_update','groups','general','users','profiles'
    ]

    async def ensure_profile_tables(self):
        """Verifica tabelas de perfis e cria perfis padrão se necessário."""
        async with self.pool.acquire() as conn:
            has_profiles = await conn.fetchval(
                "SELECT COUNT(*) FROM information_schema.tables WHERE table_name='profiles'"
            )
            if not has_profiles:
                logger.warning("Tabela 'profiles' não encontrada. Execute a migração como superusuário do PostgreSQL.")
                return
            # Cria perfis padrão se não existirem
            await self._ensure_default_profiles(conn)

    async def _ensure_default_profiles(self, conn):
        """Cria perfis Admin e Viewer com permissões padrão, se ainda não existem."""
        admin_id = await conn.fetchval("SELECT id FROM profiles WHERE name='Admin'")
        if not admin_id:
            row = await conn.fetchrow(
                "INSERT INTO profiles (name, description) VALUES ('Admin', 'Acesso completo ao sistema') RETURNING id"
            )
            admin_id = row['id']
            for mod in self.ALL_MODULES:
                await conn.execute("""
                    INSERT INTO profile_permissions (profile_id, module, can_view, can_create, can_edit, can_delete)
                    VALUES ($1, $2, TRUE, TRUE, TRUE, TRUE) ON CONFLICT DO NOTHING
                """, admin_id, mod)
            logger.info("Perfil 'Admin' criado com todas as permissões")

        # Vincula o usuário master ao perfil Admin se não tiver perfil
        await conn.execute("""
            UPDATE admin_users SET profile_id = $1, role = 'superadmin'
            WHERE email = 'app@rochaneto.com' AND profile_id IS NULL
        """, admin_id)

    async def get_all_profiles(self) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT p.*, COUNT(u.id) AS user_count
                FROM profiles p
                LEFT JOIN admin_users u ON u.profile_id = p.id
                GROUP BY p.id ORDER BY p.name
            """)
            return [dict(r) for r in rows]

    async def get_profile(self, profile_id: int) -> Optional[dict]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM profiles WHERE id = $1", profile_id)
            return dict(row) if row else None

    async def create_profile(self, name: str, description: str = '') -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO profiles (name, description) VALUES ($1, $2) RETURNING *",
                name, description
            )
            return dict(row) if row else {}

    async def update_profile(self, profile_id: int, name: str = None,
                             description: str = None) -> bool:
        fields, values, idx = [], [], 1
        if name is not None:
            fields.append(f"name = ${idx}"); values.append(name); idx += 1
        if description is not None:
            fields.append(f"description = ${idx}"); values.append(description); idx += 1
        if not fields:
            return False
        values.append(profile_id)
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                f"UPDATE profiles SET {', '.join(fields)} WHERE id = ${idx}", *values
            )
            return result == "UPDATE 1"

    async def delete_profile(self, profile_id: int) -> bool:
        async with self.pool.acquire() as conn:
            result = await conn.execute("DELETE FROM profiles WHERE id = $1", profile_id)
            return result == "DELETE 1"

    async def get_profile_permissions(self, profile_id: int) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                "SELECT * FROM profile_permissions WHERE profile_id = $1 ORDER BY module",
                profile_id
            )
            return [dict(r) for r in rows]

    async def save_profile_permissions(self, profile_id: int,
                                       permissions: List[dict]):
        """Salva lista de permissões [{module, can_view, can_create, can_edit, can_delete}]."""
        async with self.pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM profile_permissions WHERE profile_id = $1", profile_id
            )
            for p in permissions:
                await conn.execute("""
                    INSERT INTO profile_permissions
                        (profile_id, module, can_view, can_create, can_edit, can_delete)
                    VALUES ($1, $2, $3, $4, $5, $6)
                """,
                profile_id,
                p['module'],
                bool(p.get('can_view', False)),
                bool(p.get('can_create', False)),
                bool(p.get('can_edit', False)),
                bool(p.get('can_delete', False))
                )

    async def get_user_permissions(self, user_id: int) -> dict:
        """Retorna dict {module: {can_view, can_create, can_edit, can_delete}} do perfil do usuário."""
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT profile_id, role FROM admin_users WHERE id = $1", user_id
            )
            if not row:
                return {}
            # superadmin tem tudo
            if row['role'] == 'superadmin':
                return {'*': True}
            if not row['profile_id']:
                return {}
            rows = await conn.fetch(
                "SELECT * FROM profile_permissions WHERE profile_id = $1",
                row['profile_id']
            )
            return {r['module']: {
                'can_view':   r['can_view'],
                'can_create': r['can_create'],
                'can_edit':   r['can_edit'],
                'can_delete': r['can_delete'],
            } for r in rows}

    async def update_user_profile(self, user_id: int, profile_id: Optional[int]) -> bool:
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "UPDATE admin_users SET profile_id = $1 WHERE id = $2",
                profile_id, user_id
            )
            return result == "UPDATE 1"

    async def get_all_admin_users_with_profile(self) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT u.id, u.email, u.display_name, u.role, u.is_active,
                       u.mfa_enabled, u.last_login, u.created_at, u.profile_id,
                       p.name AS profile_name
                FROM admin_users u
                LEFT JOIN profiles p ON p.id = u.profile_id
                ORDER BY u.created_at
            """)
            return [dict(r) for r in rows]

    # ─── Settings ───

    async def get_setting(self, key: str, default: str = None) -> str:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "SELECT value FROM settings WHERE key = $1", key
            )
            return row['value'] if row else default

    async def set_setting(self, key: str, value: str):
        async with self.pool.acquire() as conn:
            await conn.execute(
                """
                INSERT INTO settings (key, value, updated_at)
                VALUES ($1, $2, NOW())
                ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()
                """,
                key, value
            )

    async def get_all_settings(self) -> dict:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT key, value FROM settings")
            return {r['key']: r['value'] for r in rows}

    # ─── Grupos de Agentes ───

    async def ensure_group_tables(self):
        """Cria tabelas de grupos se não existirem."""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_groups (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL UNIQUE,
                    description TEXT DEFAULT '',
                    color VARCHAR(20) DEFAULT '#3b82f6',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS agent_group_members (
                    group_id INT REFERENCES agent_groups(id) ON DELETE CASCADE,
                    agent_id VARCHAR(20) REFERENCES agents(agent_id) ON DELETE CASCADE,
                    PRIMARY KEY (group_id, agent_id)
                )
            """)

    async def get_all_groups(self) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT g.*, COUNT(m.agent_id) AS agent_count,
                       c.name AS client_name
                FROM agent_groups g
                LEFT JOIN agent_group_members m ON m.group_id = g.id
                LEFT JOIN clients c ON c.id = g.client_id
                GROUP BY g.id, c.name ORDER BY c.name NULLS LAST, g.name
            """)
            return [dict(r) for r in rows]

    async def get_client_groups(self, client_id: int) -> List[dict]:
        """Retorna grupos que possuem pelo menos um agente vinculado ao cliente."""
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT DISTINCT g.id, g.name, g.color, g.alert_enabled, g.alert_message,
                       COUNT(m.agent_id) OVER (PARTITION BY g.id) AS agent_count
                FROM agent_groups g
                JOIN agent_group_members m ON m.group_id = g.id
                JOIN client_agents ca ON ca.agent_id = m.agent_id
                WHERE ca.client_id = $1
                ORDER BY g.name
            """, client_id)
            return [dict(r) for r in rows]

    async def create_group(self, name: str, description: str = '',
                           color: str = '#3b82f6', client_id: int = None,
                           alert_enabled: bool = False, alert_message: str = '') -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO agent_groups (name, description, color, client_id, alert_enabled, alert_message) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
                name, description, color, client_id, alert_enabled, alert_message
            )
            return dict(row) if row else {}

    async def update_group(self, group_id: int, name: str = None,
                           description: str = None, color: str = None,
                           client_id: int = None, alert_enabled: bool = None,
                           alert_message: str = None) -> bool:
        fields, values, idx = [], [], 1
        if name is not None:
            fields.append(f"name = ${idx}"); values.append(name); idx += 1
        if description is not None:
            fields.append(f"description = ${idx}"); values.append(description); idx += 1
        if color is not None:
            fields.append(f"color = ${idx}"); values.append(color); idx += 1
        if client_id is not None:
            fields.append(f"client_id = ${idx}"); values.append(client_id); idx += 1
        if alert_enabled is not None:
            fields.append(f"alert_enabled = ${idx}"); values.append(alert_enabled); idx += 1
        if alert_message is not None:
            fields.append(f"alert_message = ${idx}"); values.append(alert_message); idx += 1
        if not fields:
            return False
        values.append(group_id)
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                f"UPDATE agent_groups SET {', '.join(fields)} WHERE id = ${idx}", *values
            )
            return result == "UPDATE 1"

    async def delete_group(self, group_id: int) -> bool:
        async with self.pool.acquire() as conn:
            result = await conn.execute("DELETE FROM agent_groups WHERE id = $1", group_id)
            return result == "DELETE 1"

    async def get_group_agents(self, group_id: int) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT a.agent_id, a.hostname, a.os_type, a.username, a.ip_address, a.is_online
                FROM agents a
                JOIN agent_group_members m ON m.agent_id = a.agent_id
                WHERE m.group_id = $1 ORDER BY a.hostname
            """, group_id)
            return [dict(r) for r in rows]

    async def get_agents_in_any_group(self) -> list:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT agent_id FROM agent_group_members")
            return [r['agent_id'] for r in rows]

    async def add_agent_to_group(self, group_id: int, agent_id: str):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO agent_group_members (group_id, agent_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                group_id, agent_id
            )

    async def remove_agent_from_group(self, group_id: int, agent_id: str):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM agent_group_members WHERE group_id = $1 AND agent_id = $2",
                group_id, agent_id
            )

    async def ensure_access_tables(self):
        """Garante colunas e tabelas de controle de acesso por usuário."""
        async with self.pool.acquire() as conn:
            # ALTER TABLE pode falhar se o usuário DB não for owner (colunas já existem após migração manual)
            for ddl in [
                "ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS access_all_clients BOOLEAN NOT NULL DEFAULT TRUE",
                "ALTER TABLE admin_users ADD COLUMN IF NOT EXISTS access_all_groups  BOOLEAN NOT NULL DEFAULT TRUE",
            ]:
                try:
                    await conn.execute(ddl)
                except Exception:
                    pass  # coluna já existe ou sem privilégio — ignorar
            for ddl in [
                """CREATE TABLE IF NOT EXISTS user_client_access (
                    user_id   INT REFERENCES admin_users(id) ON DELETE CASCADE,
                    client_id INT REFERENCES clients(id)     ON DELETE CASCADE,
                    PRIMARY KEY (user_id, client_id)
                )""",
                """CREATE TABLE IF NOT EXISTS user_group_access (
                    user_id  INT REFERENCES admin_users(id)    ON DELETE CASCADE,
                    group_id INT REFERENCES agent_groups(id)   ON DELETE CASCADE,
                    PRIMARY KEY (user_id, group_id)
                )""",
            ]:
                try:
                    await conn.execute(ddl)
                except Exception:
                    pass  # tabela já existe ou sem privilégio — ignorar

    # ─── Clientes ───

    async def ensure_client_tables(self):
        """Cria tabelas de clientes se não existirem."""
        async with self.pool.acquire() as conn:
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS clients (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(200) NOT NULL,
                    document VARCHAR(20) DEFAULT '',
                    email VARCHAR(200) DEFAULT '',
                    phone VARCHAR(30) DEFAULT '',
                    notes TEXT DEFAULT '',
                    created_at TIMESTAMPTZ DEFAULT NOW()
                )
            """)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS client_agents (
                    client_id INT REFERENCES clients(id) ON DELETE CASCADE,
                    agent_id VARCHAR(20) REFERENCES agents(agent_id) ON DELETE CASCADE,
                    PRIMARY KEY (client_id, agent_id)
                )
            """)

    async def get_all_clients(self) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT c.*, COUNT(ca.agent_id) AS agent_count
                FROM clients c
                LEFT JOIN client_agents ca ON ca.client_id = c.id
                GROUP BY c.id ORDER BY c.name
            """)
            return [dict(r) for r in rows]

    async def get_client(self, client_id: int) -> Optional[dict]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow("SELECT * FROM clients WHERE id = $1", client_id)
            return dict(row) if row else None

    async def create_client(self, name: str, document: str = '', email: str = '',
                            phone: str = '', notes: str = '',
                            alert_enabled: bool = False, alert_message: str = '') -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO clients (name, document, email, phone, notes, alert_enabled, alert_message) "
                "VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
                name, document, email, phone, notes, alert_enabled, alert_message
            )
            return dict(row) if row else {}

    async def update_client(self, client_id: int, name: str = None, document: str = None,
                            email: str = None, phone: str = None, notes: str = None,
                            alert_enabled: bool = None, alert_message: str = None) -> bool:
        fields, values, idx = [], [], 1
        for col, val in [('name', name), ('document', document), ('email', email),
                         ('phone', phone), ('notes', notes),
                         ('alert_enabled', alert_enabled), ('alert_message', alert_message)]:
            if val is not None:
                fields.append(f"{col} = ${idx}"); values.append(val); idx += 1
        if not fields:
            return False
        values.append(client_id)
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                f"UPDATE clients SET {', '.join(fields)} WHERE id = ${idx}", *values
            )
            return result == "UPDATE 1"

    async def delete_client(self, client_id: int) -> bool:
        async with self.pool.acquire() as conn:
            result = await conn.execute("DELETE FROM clients WHERE id = $1", client_id)
            return result == "DELETE 1"

    async def get_client_agents(self, client_id: int) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("""
                SELECT a.agent_id, a.nickname, a.hostname, a.os_type, a.username,
                       a.ip_address, a.is_online
                FROM agents a
                JOIN client_agents ca ON ca.agent_id = a.agent_id
                WHERE ca.client_id = $1 ORDER BY a.hostname
            """, client_id)
            return [dict(r) for r in rows]

    async def get_agents_in_any_client(self) -> list:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch("SELECT agent_id FROM client_agents")
            return [r['agent_id'] for r in rows]

    async def add_agent_to_client(self, client_id: int, agent_id: str):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "INSERT INTO client_agents (client_id, agent_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                client_id, agent_id
            )

    async def remove_agent_from_client(self, client_id: int, agent_id: str):
        async with self.pool.acquire() as conn:
            await conn.execute(
                "DELETE FROM client_agents WHERE client_id = $1 AND agent_id = $2",
                client_id, agent_id
            )

    # ─── Estatísticas ───

    async def get_stats(self) -> dict:
        async with self.pool.acquire() as conn:
            total_agents = await conn.fetchval("SELECT COUNT(*) FROM agents")
            online_agents = await conn.fetchval(
                "SELECT COUNT(*) FROM agents WHERE is_online = TRUE"
            )
            total_sessions = await conn.fetchval("SELECT COUNT(*) FROM sessions")
            active_sessions = await conn.fetchval(
                "SELECT COUNT(*) FROM sessions WHERE status = 'active'"
            )
            total_bytes = await conn.fetchval(
                "SELECT COALESCE(SUM(bytes_transferred), 0) FROM sessions"
            )
            today_sessions = await conn.fetchval(
                "SELECT COUNT(*) FROM sessions WHERE started_at >= CURRENT_DATE"
            )

            return {
                "total_agents": int(total_agents),
                "online_agents": int(online_agents),
                "total_sessions": int(total_sessions),
                "active_sessions": int(active_sessions),
                "total_bytes_transferred": int(total_bytes),
                "sessions_today": int(today_sessions),
            }

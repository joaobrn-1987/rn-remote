"""
RemoteLink - Camada de Banco de Dados (PostgreSQL via asyncpg)
"""

import asyncio
import json
import time
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict

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
        import random
        async with self.pool.acquire() as conn:
            for _ in range(20):
                agent_id = ''.join([str(random.randint(0, 9)) for _ in range(9)])
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
                             viewer_id: str, viewer_ip: str = "") -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO sessions (session_id, agent_id, viewer_id, viewer_ip, status)
                VALUES ($1, $2, $3, $4, 'active')
                RETURNING *
                """,
                session_id, agent_id, viewer_id, viewer_ip
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
                                 password_hash: str) -> Optional[dict]:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                SELECT * FROM admin_users
                WHERE email = $1 AND password_hash = $2 AND is_active = TRUE
                """,
                email, password_hash
            )
            if row:
                await conn.execute(
                    "UPDATE admin_users SET last_login = NOW() WHERE id = $1",
                    row['id']
                )
                return dict(row)
            return None

    async def get_all_admin_users(self) -> List[dict]:
        async with self.pool.acquire() as conn:
            rows = await conn.fetch(
                """SELECT id, email, display_name, role, is_active, last_login, created_at
                   FROM admin_users ORDER BY created_at"""
            )
            return [dict(r) for r in rows]

    async def create_admin_user(self, email: str, password_hash: str,
                                display_name: str = "", role: str = "admin") -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                """
                INSERT INTO admin_users (email, password_hash, display_name, role)
                VALUES ($1, $2, $3, $4)
                RETURNING id, email, display_name, role, is_active, created_at
                """,
                email, password_hash, display_name, role
            )
            return dict(row) if row else {}

    async def update_admin_user(self, user_id: int, email: str = None,
                                password_hash: str = None, display_name: str = None,
                                role: str = None, is_active: bool = None) -> bool:
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
        if not fields:
            return False
        values.append(user_id)
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                f"UPDATE admin_users SET {', '.join(fields)} WHERE id = ${idx}",
                *values
            )
            return result == "UPDATE 1"

    async def delete_admin_user(self, user_id: int) -> bool:
        async with self.pool.acquire() as conn:
            result = await conn.execute(
                "DELETE FROM admin_users WHERE id = $1", user_id
            )
            return result == "DELETE 1"

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
                SELECT g.*, COUNT(m.agent_id) AS agent_count
                FROM agent_groups g
                LEFT JOIN agent_group_members m ON m.group_id = g.id
                GROUP BY g.id ORDER BY g.name
            """)
            return [dict(r) for r in rows]

    async def create_group(self, name: str, description: str = '',
                           color: str = '#3b82f6') -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO agent_groups (name, description, color) VALUES ($1, $2, $3) RETURNING *",
                name, description, color
            )
            return dict(row) if row else {}

    async def update_group(self, group_id: int, name: str = None,
                           description: str = None, color: str = None) -> bool:
        fields, values, idx = [], [], 1
        if name is not None:
            fields.append(f"name = ${idx}"); values.append(name); idx += 1
        if description is not None:
            fields.append(f"description = ${idx}"); values.append(description); idx += 1
        if color is not None:
            fields.append(f"color = ${idx}"); values.append(color); idx += 1
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
                            phone: str = '', notes: str = '') -> dict:
        async with self.pool.acquire() as conn:
            row = await conn.fetchrow(
                "INSERT INTO clients (name, document, email, phone, notes) "
                "VALUES ($1, $2, $3, $4, $5) RETURNING *",
                name, document, email, phone, notes
            )
            return dict(row) if row else {}

    async def update_client(self, client_id: int, name: str = None, document: str = None,
                            email: str = None, phone: str = None, notes: str = None) -> bool:
        fields, values, idx = [], [], 1
        for col, val in [('name', name), ('document', document), ('email', email),
                         ('phone', phone), ('notes', notes)]:
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

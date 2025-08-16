import os
import json
import pymysql
from datetime import datetime
from dotenv import load_dotenv
from passlib.hash import argon2, bcrypt

# =========================
# Cargar .env
# =========================
load_dotenv()
DB_CFG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
    "charset": os.getenv("DB_CHARSET", "utf8mb4"),
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": False,
}

# =========================
# Utilidades de DB
# =========================
def get_conn():
    return pymysql.connect(**DB_CFG)

def table_exists(cur, name):
    cur.execute("SHOW TABLES LIKE %s", (name,))
    return cur.fetchone() is not None

def get_columns(cur, table):
    cur.execute(f"SHOW COLUMNS FROM `{table}`")
    return [r["Field"] for r in cur.fetchall()]

# =========================
# Detección de esquema Shield
# =========================
class SchemaInfo:
    def __init__(self, cur):
        self.has_auth_identities = table_exists(cur, "auth_identities")
        self.has_auth_groups = table_exists(cur, "auth_groups")
        self.has_auth_groups_users = table_exists(cur, "auth_groups_users")
        # users: puede o no tener email/password_hash según versión
        self.users_cols = get_columns(cur, "users") if table_exists(cur, "users") else []

        # auth_groups_users columnas
        self.agu_cols = get_columns(cur, "auth_groups_users") if self.has_auth_groups_users else []
        self.agu_uses_group_id = "group_id" in self.agu_cols
        self.agu_uses_group_string = "group" in self.agu_cols  # string con el nombre

        # auth_identities columnas (Shield moderno)
        if self.has_auth_identities:
            self.ai_cols = get_columns(cur, "auth_identities")
        else:
            self.ai_cols = []

    def __repr__(self):
        return (
            f"SchemaInfo(auth_identities={self.has_auth_identities}, "
            f"auth_groups={self.has_auth_groups}, auth_groups_users={self.has_auth_groups_users}, "
            f"agu_uses_group_id={self.agu_uses_group_id}, agu_uses_group_string={self.agu_uses_group_string}, "
            f"users_cols={self.users_cols})"
        )

# =========================
# Hashing
# =========================
def make_password_hash(password: str, algo: str = "argon2id") -> str:
    """
    Shield usa password_hash() en PHP; recomendado Argon2id cuando está disponible.
    Puedes elegir 'argon2id' (por defecto) o 'bcrypt'.
    """
    algo = (algo or "argon2id").lower()
    if algo in ("argon2", "argon2id", "argon"):
        # passlib.argon2 produce un hash compatible con verificación
        return argon2.hash(password)
    elif algo == "bcrypt":
        return bcrypt.hash(password)
    else:
        raise ValueError("Algo de hash no soportado. Usa 'argon2id' o 'bcrypt'.")

# =========================
# Grupos
# =========================
def ensure_groups(cur, schema: SchemaInfo, wanted=("superadmin", "admin", "user")):
    if not schema.has_auth_groups:
        # Crear tabla grupos si no existe NO es responsabilidad del script;
        # aquí simplemente garantizamos filas si la tabla existe.
        return

    cur.execute("SELECT name, id FROM auth_groups")
    existing = {r["name"]: r["id"] for r in cur.fetchall()}
    for g in wanted:
        if g not in existing:
            cur.execute(
                "INSERT INTO auth_groups (name, description) VALUES (%s, %s)",
                (g, f"Grupo {g}"),
            )

def get_group_id(cur, group_name: str):
    cur.execute("SELECT id FROM auth_groups WHERE name=%s", (group_name,))
    row = cur.fetchone()
    return row["id"] if row else None

# =========================
# Usuarios
# =========================
def get_user_by_email(cur, schema: SchemaInfo, email: str):
    """
    Devuelve {'id': ..., 'email': ...} o None.
    Funciona con Shield moderno (auth_identities) o esquema antiguo (users.email).
    """
    if schema.has_auth_identities:
        cur.execute(
            """
            SELECT u.id AS id, ai.secret AS email
            FROM users u
            JOIN auth_identities ai ON ai.user_id = u.id
            WHERE ai.type='email_password' AND ai.secret=%s
            """,
            (email,),
        )
        return cur.fetchone()
    # Fallback: email directo en users
    if "email" in schema.users_cols:
        cur.execute("SELECT id, email FROM users WHERE email=%s", (email,))
        return cur.fetchone()
    return None

def create_user(cur, schema: SchemaInfo, email: str, password: str,
                username: str | None = None, algo: str = "argon2id",
                extra_identity: dict | None = None):
    """
    Crea el usuario en `users` y la identidad de email/password (Shield moderno).
    Si no hay `auth_identities`, inserta email/password en `users` (esquema antiguo).
    Retorna user_id.
    """
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    if get_user_by_email(cur, schema, email):
        raise ValueError(f"El email '{email}' ya existe.")

    # Insertar en users (mínimos campos compatibles)
    cols = []
    vals = []
    if "username" in schema.users_cols and username:
        cols += ["username"]
        vals += [username]
    if "active" in schema.users_cols:
        cols += ["active"]
        vals += [1]
    if "status" in schema.users_cols:
        cols += ["status"]
        vals += ["active"]
    if "created_at" in schema.users_cols:
        cols += ["created_at"]
        vals += [now]
    if "updated_at" in schema.users_cols:
        cols += ["updated_at"]
        vals += [now]

    if not cols:
        # Al menos insertar el id autoincrement
        cur.execute("INSERT INTO users () VALUES ()")
    else:
        cols_sql = ", ".join(f"`{c}`" for c in cols)
        placeholders = ", ".join(["%s"] * len(vals))
        cur.execute(f"INSERT INTO users ({cols_sql}) VALUES ({placeholders})", vals)

    cur.execute("SELECT LAST_INSERT_ID() AS id")
    user_id = cur.fetchone()["id"]

    # Identidad (Shield moderno) o fallback
    pwd_hash = make_password_hash(password, algo)

    if schema.has_auth_identities:
        data = {
            "user_id": user_id,
            "type": "email_password",
            "secret": email,       # email
            "secret2": pwd_hash,   # password hash
            "expires": None,
            "extra": json.dumps(extra_identity or {}),
        }

        cols = []
        vals = []
        for k, v in data.items():
            if k in schema.ai_cols:
                cols.append(k)
                vals.append(v)

        cols_sql = ", ".join(f"`{c}`" for c in cols)
        placeholders = ", ".join(["%s"] * len(vals))
        cur.execute(f"INSERT INTO auth_identities ({cols_sql}) VALUES ({placeholders})", vals)

    else:
        # Esquema antiguo: users.email + users.password_hash (o password)
        if "email" in schema.users_cols:
            cur.execute("UPDATE users SET email=%s WHERE id=%s", (email, user_id))
        # Campo de password (común en proyectos sin Shield)
        if "password_hash" in schema.users_cols:
            cur.execute("UPDATE users SET password_hash=%s WHERE id=%s", (pwd_hash, user_id))
        elif "password" in schema.users_cols:
            cur.execute("UPDATE users SET password=%s WHERE id=%s", (pwd_hash, user_id))

    return user_id

# =========================
# Asignación de grupos
# =========================
def add_user_to_group(cur, schema: SchemaInfo, user_id: int, group_name: str):
    """
    Inserta en auth_groups_users, evitando duplicados.
    Soporta variantes: (user_id, group_id) o (user_id, `group` varchar)
    """
    if not schema.has_auth_groups_users:
        raise RuntimeError("No existe la tabla 'auth_groups_users'.")

    if schema.agu_uses_group_id:
        gid = get_group_id(cur, group_name)
        if gid is None:
            raise ValueError(f"Grupo '{group_name}' no existe.")
        # evitar duplicados
        cur.execute(
            "SELECT 1 AS x FROM auth_groups_users WHERE user_id=%s AND group_id=%s",
            (user_id, gid),
        )
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO auth_groups_users (user_id, group_id) VALUES (%s, %s)",
                (user_id, gid),
            )
    elif schema.agu_uses_group_string:
        cur.execute(
            "SELECT 1 AS x FROM auth_groups_users WHERE user_id=%s AND `group`=%s",
            (user_id, group_name),
        )
        if not cur.fetchone():
            cur.execute(
                "INSERT INTO auth_groups_users (user_id, `group`) VALUES (%s, %s)",
                (user_id, group_name),
            )
    else:
        raise RuntimeError("Estructura de 'auth_groups_users' no reconocida.")

def add_email_to_group(cur, schema: SchemaInfo, email: str, group_name: str):
    u = get_user_by_email(cur, schema, email)
    if not u:
        raise ValueError(f"No existe usuario con email '{email}'.")
    add_user_to_group(cur, schema, u["id"], group_name)

# =========================
# API principal
# =========================
def create_user_and_assign_group(email: str, password: str, group_name: str,
                                 username: str | None = None, algo: str = "argon2id"):
    """
    Crea usuario y lo asigna a un grupo (superadmin|admin|user).
    """
    group_name = group_name.lower().strip()
    if group_name not in ("superadmin", "admin", "user"):
        raise ValueError("group_name inválido. Usa 'superadmin', 'admin' o 'user'.")

    with get_conn() as conn:
        cur = conn.cursor()
        schema = SchemaInfo(cur)
        ensure_groups(cur, schema, ("superadmin", "admin", "user"))
        user_id = create_user(cur, schema, email, password, username=username, algo=algo)
        add_user_to_group(cur, schema, user_id, group_name)
        conn.commit()
        return user_id

def add_group_to_existing_email(email: str, group_name: str):
    """
    Agrega el grupo a un usuario existente identificado por su email.
    """
    group_name = group_name.lower().strip()
    with get_conn() as conn:
        cur = conn.cursor()
        schema = SchemaInfo(cur)
        ensure_groups(cur, schema, ("superadmin", "admin", "user"))
        add_email_to_group(cur, schema, email, group_name)
        conn.commit()

# =========================
# Uso de ejemplo (quitar o adaptar)
# =========================
if __name__ == "__main__":
    # Ejemplos:
    # 1) Crear usuario y asignar grupo
    #    python manage_shield_users.py
    email = "nuevo.user@example.com"
    password = "C0ntr4s3na!Segura"
    username = "nuevouser"
    user_id = create_user_and_assign_group(
        email=email,
        password=password,
        group_name="admin",
        username=username,
        algo="argon2id",  # o "bcrypt"
    )
    print(f"Usuario creado con id={user_id}")

    # 2) Agregar grupo a un usuario existente (por email)
    add_group_to_existing_email("otro.user@example.com", "user")
    print("Grupo agregado a usuario existente.")

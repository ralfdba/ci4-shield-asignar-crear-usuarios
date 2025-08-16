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
    return cur.fetchall()  # [{Field, Type, Null, Key, Default, Extra}]

def colnames(cols):
    return [c["Field"] for c in cols]

def now_utc_str():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def insert_with_timestamps(cur, table, base_cols, base_vals, cols_meta):
    """
    Inserta en `table` agregando created_at/updated_at si existen y no están ya.
    Retorna lastrowid (si aplica).
    """
    cols = list(base_cols)
    vals = list(base_vals)
    names = colnames(cols_meta)

    ts = now_utc_str()
    if "created_at" in names and "created_at" not in cols:
        cols.append("created_at"); vals.append(ts)
    if "updated_at" in names and "updated_at" not in cols:
        cols.append("updated_at"); vals.append(ts)

    cols_sql = ", ".join(f"`{c}`" for c in cols)
    placeholders = ", ".join(["%s"] * len(vals))
    sql = f"INSERT INTO `{table}` ({cols_sql}) VALUES ({placeholders})"
    cur.execute(sql, vals)

    cur.execute("SELECT LAST_INSERT_ID() AS id")
    row = cur.fetchone()
    return row["id"] if row and "id" in row else None

# =========================
# Detección de esquema Shield
# =========================
class SchemaInfo:
    def __init__(self, cur):
        self.has_auth_identities = table_exists(cur, "auth_identities")
        self.has_auth_groups = table_exists(cur, "auth_groups")
        self.has_auth_groups_users = table_exists(cur, "auth_groups_users")

        self.users_cols_meta = get_columns(cur, "users") if table_exists(cur, "users") else []
        self.users_cols = colnames(self.users_cols_meta)

        if self.has_auth_identities:
            self.ai_cols_meta = get_columns(cur, "auth_identities")
            self.ai_cols = colnames(self.ai_cols_meta)
        else:
            self.ai_cols_meta = []
            self.ai_cols = []

        if self.has_auth_groups_users:
            self.agu_cols_meta = get_columns(cur, "auth_groups_users")
            self.agu_cols = colnames(self.agu_cols_meta)
            self.agu_uses_group_id = "group_id" in self.agu_cols
            self.agu_uses_group_string = "group" in self.agu_cols
        else:
            self.agu_cols_meta = []
            self.agu_cols = []
            self.agu_uses_group_id = False
            self.agu_uses_group_string = False

        if self.has_auth_groups:
            self.ag_cols_meta = get_columns(cur, "auth_groups")
            self.ag_cols = colnames(self.ag_cols_meta)
        else:
            self.ag_cols_meta = []
            self.ag_cols = []

    def __repr__(self):
        return f"SchemaInfo(users={self.users_cols}, ai={self.ai_cols}, agu={self.agu_cols}, ag={self.ag_cols})"

# =========================
# Hashing
# =========================
def make_password_hash(password: str, algo: str = "argon2id") -> str:
    algo = (algo or "argon2id").lower()
    if algo in ("argon2id", "argon2", "argon"):
        return argon2.hash(password)
    if algo == "bcrypt":
        return bcrypt.hash(password)
    raise ValueError("Algo de hash no soportado. Usa 'argon2id' o 'bcrypt'.")

# =========================
# Grupos
# =========================
def ensure_groups(cur, schema: SchemaInfo, wanted=("superadmin", "admin", "user")):
    if not schema.has_auth_groups:
        return
    cur.execute("SELECT name, id FROM auth_groups")
    existing = {r["name"]: r["id"] for r in cur.fetchall()}
    for g in wanted:
        if g not in existing:
            base_cols = ["name", "description"]
            base_vals = [g, f"Grupo {g}"]
            insert_with_timestamps(cur, "auth_groups", base_cols, base_vals, schema.ag_cols_meta)

def get_group_id(cur, group_name: str):
    cur.execute("SELECT id FROM auth_groups WHERE name=%s", (group_name,))
    row = cur.fetchone()
    return row["id"] if row else None

# =========================
# Usuarios
# =========================
def get_user_by_email(cur, schema: SchemaInfo, email: str):
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
        row = cur.fetchone()
        if row:
            return row
    if "email" in schema.users_cols:
        cur.execute("SELECT id, email FROM users WHERE email=%s", (email,))
        return cur.fetchone()
    return None

def create_user(cur, schema: SchemaInfo, email: str, password: str,
                username: str | None = None, algo: str = "argon2id",
                extra_identity: dict | None = None):
    if get_user_by_email(cur, schema, email):
        raise ValueError(f"El email '{email}' ya existe.")

    pwd_hash = make_password_hash(password, algo)

    # Insert en users
    base_cols, base_vals = [], []
    if "email" in schema.users_cols:
        base_cols += ["email"]; base_vals += [email]
    if "username" in schema.users_cols and username:
        base_cols += ["username"]; base_vals += [username]
    if "password_hash" in schema.users_cols:
        base_cols += ["password_hash"]; base_vals += [pwd_hash]
    elif "password" in schema.users_cols:
        base_cols += ["password"]; base_vals += [pwd_hash]
    if "active" in schema.users_cols:
        base_cols += ["active"]; base_vals += [1]
    if "status" in schema.users_cols:
        base_cols += ["status"]; base_vals += ["active"]

    user_id = insert_with_timestamps(cur, "users", base_cols, base_vals, schema.users_cols_meta)

    # auth_identities
    if schema.has_auth_identities:
        ai_cols, ai_vals = [], []
        names = schema.ai_cols
        data_map = {
            "user_id": user_id,
            "type": "email_password",
            "secret": email,
            "secret2": pwd_hash,
            "expires": None,
            "extra": json.dumps(extra_identity or {}),
        }
        for k in ("user_id", "type", "secret", "secret2", "expires", "extra"):
            if k in names:
                ai_cols.append(k); ai_vals.append(data_map[k])
        insert_with_timestamps(cur, "auth_identities", ai_cols, ai_vals, schema.ai_cols_meta)

    return user_id

# =========================
# Asignación de grupos
# =========================
def add_user_to_group(cur, schema: SchemaInfo, user_id: int, group_name: str):
    if not schema.has_auth_groups_users:
        raise RuntimeError("No existe la tabla 'auth_groups_users'.")

    if schema.agu_uses_group_id:
        gid = get_group_id(cur, group_name)
        if gid is None:
            raise ValueError(f"Grupo '{group_name}' no existe.")
        cur.execute("SELECT 1 FROM auth_groups_users WHERE user_id=%s AND group_id=%s", (user_id, gid))
        if not cur.fetchone():
            base_cols = ["user_id", "group_id"]
            base_vals = [user_id, gid]
            insert_with_timestamps(cur, "auth_groups_users", base_cols, base_vals, schema.agu_cols_meta)
    elif schema.agu_uses_group_string:
        cur.execute("SELECT 1 FROM auth_groups_users WHERE user_id=%s AND `group`=%s", (user_id, group_name))
        if not cur.fetchone():
            base_cols = ["user_id", "group"]
            base_vals = [user_id, group_name]
            insert_with_timestamps(cur, "auth_groups_users", base_cols, base_vals, schema.agu_cols_meta)
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
    group_name = group_name.lower().strip()
    if group_name not in ("superadmin", "admin", "user"):
        raise ValueError("group_name inválido. Usa 'superadmin', 'admin' o 'user'.")

    with get_conn() as conn:
        try:
            cur = conn.cursor()
            schema = SchemaInfo(cur)
            ensure_groups(cur, schema, ("superadmin", "admin", "user"))
            user_id = create_user(cur, schema, email, password, username=username, algo=algo)
            add_user_to_group(cur, schema, user_id, group_name)
            conn.commit()
            return user_id
        except Exception:
            conn.rollback()
            raise

def add_group_to_existing_email(email: str, group_name: str):
    group_name = group_name.lower().strip()
    with get_conn() as conn:
        try:
            cur = conn.cursor()
            schema = SchemaInfo(cur)
            ensure_groups(cur, schema, ("superadmin", "admin", "user"))
            add_email_to_group(cur, schema, email, group_name)
            conn.commit()
        except Exception:
            conn.rollback()
            raise

# =========================
# Uso de ejemplo
# =========================
if __name__ == "__main__":
    
    email = "nuevo.user@example.com"
    password = "C0ntr4s3na!Segura"
    username = "nuevouser"
    uid = create_user_and_assign_group(
        email=email,
        password=password,
        group_name="admin",
        username=username,
        algo="argon2id",
    )
    print(f"[OK] Usuario creado id={uid}")
    
    add_group_to_existing_email("nuevo.user@example.com", "superadmin")
    print("[OK] Grupo agregado a usuario existente")

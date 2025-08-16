# Manage Shield Users (CodeIgniter 4 + Python)

Este proyecto contiene un script en **Python** para administrar usuarios de **CodeIgniter 4 + Shield** directamente desde la base de datos.  
Permite:

- Crear usuarios con email y contraseña.
- Asignarlos a uno de los grupos disponibles: `superadmin`, `admin` o `user`.
- Agregar un grupo adicional a un usuario ya existente (por email).
- Generar hashes de contraseña compatibles con **Shield** (`argon2id` recomendado, o `bcrypt` como alternativa).
- Detectar automáticamente el esquema de tablas (Shield moderno con `auth_identities` o esquemas antiguos).

---

## 🚀 Requisitos

- Python 3.9+
- Librerías:
  ```bash
  pip install pymysql passlib python-dotenv
  ```

- Base de datos configurada con **CodeIgniter 4 + Shield**.

---

## ⚙️ Configuración

Crea un archivo `.env` en la raíz del proyecto con los datos de tu base de datos:

```ini
DB_HOST=localhost
DB_USER=ciuser
DB_PASSWORD=cipass
DB_NAME=ci_db
DB_CHARSET=utf8mb4
```

---

## 📌 Uso

### 1. Crear usuario y asignar grupo
```python
from manage_shield_users import create_user_and_assign_group

user_id = create_user_and_assign_group(
    email="alice@acme.com",
    password="ClaveSegura!2025",
    group_name="admin",       # superadmin | admin | user
    username="alice",
    algo="argon2id"           # o "bcrypt"
)
print(f"Usuario creado con id={user_id}")
```

### 2. Agregar grupo a usuario existente (por email)
```python
from manage_shield_users import add_group_to_existing_email

add_group_to_existing_email("bob@acme.com", "superadmin")
print("Grupo agregado a usuario existente.")
```

### 3. Ejecución directa
También puedes ejecutar el script directamente:

```bash
python manage_shield_users.py
```

Esto creará un usuario de ejemplo y añadirá un grupo a otro.

---

## 📂 Tablas soportadas

El script soporta tanto esquemas modernos como antiguos de Shield:

- `users`
- `auth_identities`
- `auth_groups`
- `auth_groups_users`

Detecta automáticamente si `auth_groups_users` utiliza `group_id` (numérico) o `group` (string).

---

## 🔒 Hash de contraseñas

El script utiliza **passlib** para generar hashes compatibles:

- `argon2id` (recomendado por seguridad).
- `bcrypt` como alternativa.

Estos hashes son reconocidos por PHP `password_verify()` y por **Shield**.

---

## 📝 Roadmap

- [ ] Soporte para importación masiva desde CSV/Excel.  
- [ ] Interfaz de línea de comandos (CLI) con `argparse`.  
- [ ] Integración con pipelines de CI/CD.  

---

## 🤝 Contribuciones

¡Las contribuciones son bienvenidas!  
Si deseas mejorar este script, abre un **Pull Request** o crea un **Issue**.

---

## 📜 Licencia

MIT License.  
Libre para usar, modificar y distribuir.

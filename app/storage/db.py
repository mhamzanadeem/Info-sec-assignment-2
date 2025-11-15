"""MySQL users table + salted hashing (no chat storage).""" 
# app/storage/db.py
import pymysql
import argparse

# Database configuration
DB_HOST = "localhost"
DB_USER = "scuser"
DB_PASS = "scpass"
DB_NAME = "securechat"

def connect():
    """Connect to MySQL database"""
    return pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASS,
        database=DB_NAME
    )

def init_db():
    """Create users table if not exists"""
    conn = connect()
    cursor = conn.cursor()

    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        email VARCHAR(255),
        username VARCHAR(255) UNIQUE,
        salt VARBINARY(16),
        pwd_hash CHAR(64),
        PRIMARY KEY (username)
    )
    """)

    conn.commit()
    conn.close()
    print("[DB] users table created.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--init", action="store_true")
    args = parser.parse_args()

    if args.init:
        init_db()

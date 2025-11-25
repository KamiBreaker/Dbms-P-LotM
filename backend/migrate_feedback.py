import sqlalchemy
from sqlalchemy import create_engine, text
import os

# Database Configuration
DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db"

def migrate_feedback_table():
    engine = create_engine(DATABASE_URL)
    with engine.connect() as connection:
        try:
            print("Creating feedback table if not exists...")
            connection.execute(text("""
                CREATE TABLE IF NOT EXISTS feedback (
                    id INT AUTO_INCREMENT PRIMARY KEY,
                    user_id INT,
                    message VARCHAR(1000) NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                )
            """))
            print("Feedback table created (or already existed).")
        except Exception as e:
            print(f"Migration failed: {e}")

if __name__ == "__main__":
    migrate_feedback_table()

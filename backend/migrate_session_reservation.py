import sqlalchemy
from sqlalchemy import create_engine, text
import os

DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db"

def migrate_session_reservation():
    engine = create_engine(DATABASE_URL)
    with engine.connect() as connection:
        try:
            result = connection.execute(text("SHOW COLUMNS FROM parking_sessions LIKE 'reservation_id'"))
            if not result.fetchone():
                print("Adding reservation_id to parking_sessions...")
                connection.execute(text("ALTER TABLE parking_sessions ADD COLUMN reservation_id INTEGER"))
                connection.execute(text("ALTER TABLE parking_sessions ADD CONSTRAINT fk_sessions_reservations FOREIGN KEY (reservation_id) REFERENCES reservations(id)"))
                print("Migration successful.")
            else:
                print("reservation_id already exists.")
        except Exception as e:
            print(f"Migration failed: {e}")

if __name__ == "__main__":
    migrate_session_reservation()

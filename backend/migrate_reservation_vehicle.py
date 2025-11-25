import sqlalchemy
from sqlalchemy import create_engine, text
import os

# Database Configuration
DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db"

def migrate_db():
    engine = create_engine(DATABASE_URL)
    with engine.connect() as connection:
        try:
            # Check if vehicle_id column exists in reservations table
            result = connection.execute(text("SHOW COLUMNS FROM reservations LIKE 'vehicle_id'"))
            if not result.fetchone():
                print("Adding vehicle_id column to reservations table...")
                connection.execute(text("ALTER TABLE reservations ADD COLUMN vehicle_id INTEGER"))
                connection.execute(text("ALTER TABLE reservations ADD CONSTRAINT fk_reservations_vehicles FOREIGN KEY (vehicle_id) REFERENCES vehicles(id)"))
                print("Migration successful.")
            else:
                print("vehicle_id column already exists.")
        except Exception as e:
            print(f"Migration failed: {e}")

if __name__ == "__main__":
    migrate_db()

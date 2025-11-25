import json
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship

# --- Special Backup Script ---
# This script is designed to read the OLD database schema before the 'is_active' column was added.
# It defines its own 'LegacyUser' model to match the old schema.

print("--- Starting Legacy Data Backup ---")

# --- Database Configuration ---
DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db"
Base = declarative_base()

# --- Define Legacy Models (to match the DB) ---

# This is the key part: A User model WITHOUT the 'is_active' column
class LegacyUser(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default='user')
    discount_percentage = Column(Float, default=0.0)
    loyalty_tier = Column(Integer, default=0)

# Other models (assuming they haven't changed significantly)
class Vehicle(Base):
    __tablename__ = "vehicles"
    id = Column(Integer, primary_key=True)
    license_plate = Column(String(255), unique=True, index=True, nullable=False)
    vehicle_type = Column(String(255), default="Car")
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)

class ParkingLot(Base):
    __tablename__ = "parking_lots"
    id = Column(Integer, primary_key=True)
    name = Column(String(255), unique=True, nullable=False)
    area = Column(String(255), index=True, nullable=False)
    hourly_rate = Column(Float, nullable=False, default=2.5)

class ParkingSlot(Base):
    __tablename__ = "parking_slots"
    id = Column(Integer, primary_key=True)
    slot_number = Column(String(255), nullable=False)
    status = Column(String(255), default="available", nullable=False)
    slot_type = Column(String(255), default="regular", nullable=False)
    lot_id = Column(Integer, ForeignKey("parking_lots.id"))

class ParkingSession(Base):
    __tablename__ = "parking_sessions"
    id = Column(Integer, primary_key=True)
    check_in_time = Column(DateTime)
    expected_check_out_time = Column(DateTime, nullable=True)
    check_out_time = Column(DateTime, nullable=True)
    total_fee = Column(Float, nullable=True)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"))
    slot_id = Column(Integer, ForeignKey("parking_slots.id"))

class Reservation(Base):
    __tablename__ = "reservations"
    id = Column(Integer, primary_key=True)
    reservation_time = Column(DateTime)
    status = Column(String(255), default="active")
    slot_id = Column(Integer, ForeignKey("parking_slots.id"))
    user_id = Column(Integer, ForeignKey("users.id"))

class Penalty(Base):
    __tablename__ = "penalties"
    id = Column(Integer, primary_key=True)
    reason = Column(String(255), nullable=False)
    amount = Column(Float, nullable=False)
    session_id = Column(Integer, ForeignKey("parking_sessions.id"))

# --- Backup Logic ---
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

try:
    print("Fetching data using legacy models...")
    # Use the LegacyUser model to query
    users = db.query(LegacyUser).all()
    vehicles = db.query(Vehicle).all()
    parking_lots = db.query(ParkingLot).all()
    parking_slots = db.query(ParkingSlot).all()
    parking_sessions = db.query(ParkingSession).all()
    reservations = db.query(Reservation).all()
    penalties = db.query(Penalty).all()
    print(f"Found {len(users)} users, {len(vehicles)} vehicles, {len(parking_sessions)} sessions.")

    backup_data = {
        "users": [
            {"id": u.id, "name": u.name, "hashed_password": u.hashed_password, "role": u.role, "discount_percentage": u.discount_percentage, "loyalty_tier": u.loyalty_tier}
            for u in users if u.name != 'root'
        ],
        "vehicles": [{"id": v.id, "license_plate": v.license_plate, "vehicle_type": v.vehicle_type, "user_id": v.user_id} for v in vehicles],
        "parking_lots": [{"id": lot.id, "name": lot.name, "area": lot.area, "hourly_rate": lot.hourly_rate} for lot in parking_lots],
        "parking_slots": [{"id": slot.id, "slot_number": slot.slot_number, "slot_type": slot.slot_type, "lot_id": slot.lot_id, "status": slot.status} for slot in parking_slots],
        "parking_sessions": [
            {
                "id": ps.id, "check_in_time": ps.check_in_time.isoformat() if ps.check_in_time else None,
                "expected_check_out_time": ps.expected_check_out_time.isoformat() if ps.expected_check_out_time else None,
                "check_out_time": ps.check_out_time.isoformat() if ps.check_out_time else None,
                "total_fee": ps.total_fee, "vehicle_id": ps.vehicle_id, "slot_id": ps.slot_id,
            } for ps in parking_sessions if ps.vehicle_id is not None
        ],
        "reservations": [{"id": r.id, "reservation_time": r.reservation_time.isoformat() if r.reservation_time else None, "status": r.status, "slot_id": r.slot_id, "user_id": r.user_id} for r in reservations],
        "penalties": [{"id": p.id, "reason": p.reason, "amount": p.amount, "session_id": p.session_id} for p in penalties]
    }

    backup_file = "backup.json"
    with open(backup_file, "w") as f:
        json.dump(backup_data, f, indent=4)
    
    print(f"--- Backup successful! Data saved to '{backup_file}' ---")

except Exception as e:
    print(f"An error occurred during backup: {e}")

finally:
    db.close()

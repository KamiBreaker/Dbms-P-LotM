import json
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from p import User, Vehicle, ParkingSession, ParkingLot, ParkingSlot, Reservation, Penalty, Base

print("--- Starting Data Backup ---")

# --- Database Configuration ---
DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

db = SessionLocal()

try:
    # --- Fetch Data ---
    print("Fetching data from all tables...")
    users = db.query(User).all()
    vehicles = db.query(Vehicle).all()
    parking_lots = db.query(ParkingLot).all()
    parking_slots = db.query(ParkingSlot).all()
    parking_sessions = db.query(ParkingSession).all()
    reservations = db.query(Reservation).all()
    penalties = db.query(Penalty).all()
    print(f"Found {len(users)} users, {len(vehicles)} vehicles, {len(parking_sessions)} sessions.")

    # --- Prepare Data for JSON ---
    # NOTE: We cannot serialize the SQLAlchemy objects directly. We convert them to dicts.
    # We also can't serialize the password hash for security reasons, so we'll skip it.
    # The restore script will handle user creation differently.
    
    backup_data = {
        "users": [
            {"id": u.id, "name": u.name, "role": u.role, "discount_percentage": u.discount_percentage, "loyalty_tier": u.loyalty_tier}
            for u in users if u.name != 'root' # Don't back up the root user, it will be recreated
        ],
        "vehicles": [
            {"id": v.id, "license_plate": v.license_plate, "vehicle_type": v.vehicle_type, "user_id": v.user_id}
            for v in vehicles
        ],
        "parking_lots": [
            {"id": lot.id, "name": lot.name, "area": lot.area, "hourly_rate": lot.hourly_rate}
            for lot in parking_lots
        ],
        "parking_slots": [
            {"id": slot.id, "slot_number": slot.slot_number, "slot_type": slot.slot_type, "lot_id": slot.lot_id}
            for slot in parking_slots
        ],
        # We only back up sessions that are linked to a vehicle
        "parking_sessions": [
            {
                "id": ps.id,
                "check_in_time": ps.check_in_time.isoformat() if ps.check_in_time else None,
                "expected_check_out_time": ps.expected_check_out_time.isoformat() if ps.expected_check_out_time else None,
                "check_out_time": ps.check_out_time.isoformat() if ps.check_out_time else None,
                "total_fee": ps.total_fee,
                "vehicle_id": ps.vehicle_id,
                "slot_id": ps.slot_id,
            }
            for ps in parking_sessions if ps.vehicle_id is not None
        ],
        "reservations": [
            {"id": r.id, "reservation_time": r.reservation_time.isoformat(), "status": r.status, "slot_id": r.slot_id, "user_id": r.user_id}
            for r in reservations
        ],
        "penalties": [
            {"id": p.id, "reason": p.reason, "amount": p.amount, "session_id": p.session_id}
            for p in penalties
        ]
    }

    # --- Write to JSON file ---
    backup_file = "backup.json"
    with open(backup_file, "w") as f:
        json.dump(backup_data, f, indent=4)
    
    print(f"--- Backup successful! Data saved to '{backup_file}' ---")

except Exception as e:
    print(f"An error occurred during backup: {e}")
    print("Please ensure your database is running and accessible.")

finally:
    db.close()

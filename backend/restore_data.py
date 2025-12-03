import json
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from p import User, Vehicle, ParkingSession, ParkingLot, ParkingSlot, Reservation, Base, get_password_hash

print("--- Starting Data Restoration ---")

# --- Database Configuration ---
DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

# --- Read Backup File ---
backup_file = "backup.json"
try:
    with open(backup_file, "r") as f:
        backup_data = json.load(f)
    print("Backup file read successfully.")
except FileNotFoundError:
    print(f"Error: '{backup_file}' not found. Cannot restore data.")
    exit()
except json.JSONDecodeError:
    print(f"Error: Could not decode JSON from '{backup_file}'.")
    exit()

try:
    # --- Restore Data (in order of dependency) ---
    
    # Users
    print(f"Restoring {len(backup_data['users'])} users...")
    # Generate a temporary hashed password for all restored users
    temp_hashed_password = get_password_hash("temporary_password") 
    for user_data in backup_data["users"]:
        new_user = User(
            id=user_data["id"],
            name=user_data["name"],
            hashed_password=temp_hashed_password, # Assign temporary password
            role=user_data["role"],
            discount_percentage=user_data["discount_percentage"],
            loyalty_tier=user_data["loyalty_tier"],
            is_active=True,  # Activate all restored users
            total_activities=user_data.get("total_activities", 0)
        )
        db.merge(new_user) # Use merge to handle existing IDs

    # Vehicles
    print(f"Restoring {len(backup_data['vehicles'])} vehicles...")
    for vehicle_data in backup_data["vehicles"]:
        new_vehicle = Vehicle(**vehicle_data)
        db.merge(new_vehicle)

    # Parking Lots
    print(f"Restoring {len(backup_data['parking_lots'])} parking lots...")
    for lot_data in backup_data["parking_lots"]:
        # Ensure the name matches the area, as requested by the user
        lot_data['name'] = f"{lot_data['area']} Parking"
        new_lot = ParkingLot(**lot_data)
        db.merge(new_lot)

    # Parking Slots
    print(f"Restoring {len(backup_data['parking_slots'])} parking slots...")
    for slot_data in backup_data["parking_slots"]:
        new_slot = ParkingSlot(**slot_data)
        db.merge(new_slot)

    db.commit() # Commit these before restoring objects that depend on them

    # Parking Sessions
    print(f"Restoring {len(backup_data['parking_sessions'])} sessions...")
    for session_data in backup_data["parking_sessions"]:
        # Convert ISO string dates back to datetime objects
        session_data["check_in_time"] = datetime.fromisoformat(session_data["check_in_time"]) if session_data.get("check_in_time") else None
        session_data["expected_check_out_time"] = datetime.fromisoformat(session_data["expected_check_out_time"]) if session_data.get("expected_check_out_time") else None
        session_data["check_out_time"] = datetime.fromisoformat(session_data["check_out_time"]) if session_data.get("check_out_time") else None
        
        # Handle is_vip_session, defaulting to False if not in backup data
        session_data["is_vip_session"] = session_data.get("is_vip_session", False)

        new_session = ParkingSession(**session_data)
        db.merge(new_session)

    # Reservations
    print(f"Restoring {len(backup_data['reservations'])} reservations...")
    for res_data in backup_data["reservations"]:
        res_data["reservation_time"] = datetime.fromisoformat(res_data["reservation_time"]) if res_data.get("reservation_time") else None
        new_res = Reservation(
            id=res_data["id"],
            reservation_time=res_data["reservation_time"],
            status=res_data["status"],
            slot_id=res_data["slot_id"],
            user_id=res_data["user_id"],
            expected_check_in_time=None, # Old backup doesn't have this
            expected_check_out_time=None # Old backup doesn't have this
        )
        db.merge(new_res)

    # # Penalties
    # print(f"Restoring {len(backup_data['penalties'])} penalties...")
    # for penalty_data in backup_data["penalties"]:
    #     new_penalty = Penalty(**penalty_data)
    #     db.merge(new_penalty)

    # --- Final Commit ---
    db.commit()
    print("--- Data restoration complete! ---")

except Exception as e:
    print(f"An error occurred during restoration: {e}")
    db.rollback()

finally:
    db.close()

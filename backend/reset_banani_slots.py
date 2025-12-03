from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from p import Base, ParkingLot, ParkingSlot, ParkingSession, Reservation, Penalty, User, Vehicle

print("--- Starting Banani Slots Reset ---")

# --- Database Configuration ---
DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

try:
    # 1. Find Banani Parking Lot
    print("Finding 'Banani Parking Lot'...")
    banani_lot = db.query(ParkingLot).filter(ParkingLot.name == "Banani Parking Lot").first()
    if not banani_lot:
        print("Error: 'Banani Parking Lot' not found. Exiting.")
        exit()
    print(f"Found Banani Parking Lot (ID: {banani_lot.id}).")

    # 2. Identify slots A1-A5 in Banani
    slot_numbers_to_reset = [f"A{i}" for i in range(1, 6)]
    slots_to_delete = db.query(ParkingSlot).filter(
        ParkingSlot.lot_id == banani_lot.id,
        ParkingSlot.slot_number.in_(slot_numbers_to_reset)
    ).all()

    if not slots_to_delete:
        print("No existing slots A1-A5 found in Banani. Proceeding to add new ones.")
    else:
        slot_ids_to_delete = [s.id for s in slots_to_delete]
        print(f"Identified {len(slots_to_delete)} slots to delete: {slot_ids_to_delete}")

        # 3. Delete related records (ParkingSessions, Reservations)
        print("Deleting related ParkingSessions...")
        db.query(ParkingSession).filter(ParkingSession.slot_id.in_(slot_ids_to_delete)).delete(synchronize_session=False)
        
        print("Deleting related Reservations...")
        db.query(Reservation).filter(Reservation.slot_id.in_(slot_ids_to_delete)).delete(synchronize_session=False)

        # 4. Delete the slots themselves
        print("Deleting slots A1-A5 from Banani Parking Lot...")
        for slot in slots_to_delete:
            db.delete(slot)
        print("Existing slots A1-A5 deleted.")

    # 5. Add new slots A1-A5
    print("Adding new slots A1-A5 to Banani Parking Lot...")
    for i in range(1, 6):
        new_slot = ParkingSlot(
            slot_number=f"A{i}",
            status="available",
            slot_type="regular",
            lot_id=banani_lot.id
        )
        db.add(new_slot)
    print("New slots A1-A5 added.")

    db.commit()
    print("--- Banani Slots Reset Complete! ---")

except Exception as e:
    db.rollback()
    print(f"An error occurred during slot reset: {e}")
finally:
    db.close()

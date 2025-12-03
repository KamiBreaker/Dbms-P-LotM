from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from p import Base, User, Vehicle # Import your models

print("--- Starting Sample Vehicle Addition ---")

# --- Database Configuration ---
DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

try:
    # Fetch existing users to link vehicles
    users = db.query(User).all()
    user_map = {user.name: user for user in users}

    sample_vehicles_data = [
        # Linked to existing users
        {"license_plate": "DHAKA-METRO-GA-12-3456", "vehicle_type": "Sedan", "user_name": "evan"},
        {"license_plate": "CHATT-METRO-K-11-2233", "vehicle_type": "SUV", "user_name": "osman"},
        {"license_plate": "SYLHET-HA-01-0001", "vehicle_type": "Motorcycle", "user_name": "evan"},
        {"license_plate": "KHULNA-LA-19-8765", "vehicle_type": "Hatchback", "user_name": "osman"},
        
        # New vehicles, some linked to users, some unassigned
        {"license_plate": "DHAKA-METRO-GHA-10-9876", "vehicle_type": "Sedan", "user_name": "evan"},
        {"license_plate": "CHATT-METRO-M-05-4321", "vehicle_type": "Microbus", "user_name": "osman"},
        {"license_plate": "RAJ-METRO-TA-03-1122", "vehicle_type": "Motorcycle", "user_name": None}, # Unassigned
        {"license_plate": "BARI-B-15-6789", "vehicle_type": "Pickup", "user_name": "evan"},
        {"license_plate": "COM-THA-07-5555", "vehicle_type": "Truck", "user_name": None}, # Unassigned
        {"license_plate": "COX-BAZAR-CHA-02-0011", "vehicle_type": "SUV", "user_name": "osman"},
        {"license_plate": "BOGRA-JA-09-9988", "vehicle_type": "CNG Auto-rickshaw", "user_name": None}, # Unassigned
        {"license_plate": "MYM-GA-04-7777", "vehicle_type": "Sedan", "user_name": "evan"},
        {"license_plate": "RANG-KHA-06-1234", "vehicle_type": "Motorcycle", "user_name": None}, # Unassigned
    ]

    for data in sample_vehicles_data:
        license_plate = data["license_plate"]
        existing_vehicle = db.query(Vehicle).filter(Vehicle.license_plate == license_plate).first()
        
        if existing_vehicle:
            print(f"Vehicle with license plate {license_plate} already exists. Skipping.")
            continue

        user_id = None
        if data["user_name"]:
            user = user_map.get(data["user_name"])
            if user:
                user_id = user.id
            else:
                print(f"Warning: User '{data['user_name']}' not found for vehicle {license_plate}. Adding as unassigned.")

        new_vehicle = Vehicle(
            license_plate=license_plate,
            vehicle_type=data["vehicle_type"],
            user_id=user_id
        )
        db.add(new_vehicle)
        print(f"Added vehicle: {license_plate} ({data['vehicle_type']}) {'(User: ' + data['user_name'] + ')' if data['user_name'] else '(Unassigned)'}")

    db.commit()
    print("--- Sample Vehicle Addition Complete! ---")

except Exception as e:
    db.rollback()
    print(f"An error occurred during sample vehicle addition: {e}")
finally:
    db.close()

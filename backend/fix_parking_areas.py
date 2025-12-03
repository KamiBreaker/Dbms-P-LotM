import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.append(os.path.join(os.getcwd(), 'backend'))
from p import ParkingLot, DATABASE_URL

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

# Define the correct mappings based on Lot Name
# We will search by Name and update the Area
updates = {
    "MirpurDohs Parking": "Mirpur DOHS",
    "Mohammadpur Parking": "Mohammadpur",
    "Uttara Parking": "Uttara",
    "Gulshan Parking": "Gulshan",
    "Banani Parking": "Banani",
    "Bashundhara Parking": "Bashundhara"
}

try:
    for name, correct_area in updates.items():
        lot = session.query(ParkingLot).filter(ParkingLot.name == name).first()
        if lot:
            print(f"Updating '{lot.name}' area from '{lot.area}' to '{correct_area}'")
            lot.area = correct_area
        else:
            print(f"Warning: Lot with name '{name}' not found.")
    
    session.commit()
    print("Successfully updated parking lot areas.")

except Exception as e:
    session.rollback()
    print(f"Error updating database: {e}")
finally:
    session.close()

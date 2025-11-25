
import requests
import random
import string

# Configuration
FASTAPI_BASE_URL = "http://127.0.0.1:8000"
MIN_SPOTS_PER_LOT = 25
MAX_SPOTS_PER_LOT = 60

DEFAULT_PARKING_LOTS = [
    {"name": "MirpurDohs Parking", "area": "Mirpur", "hourly_rate": 3.0},
    {"name": "Mohammadpur Parking", "area": "Mohammadpur", "hourly_rate": 2.5},
    {"name": "Uttara Parking", "area": "Uttara", "hourly_rate": 2.0},
    {"name": "Gulshan Parking", "area": "Gulshan", "hourly_rate": 3.5},
    {"name": "Banani Parking", "area": "Banani", "hourly_rate": 2.75},
    {"name": "Bashundhara Parking", "area": "Bashundhara", "hourly_rate": 4.0},
    {"name": "Tejgaon Parking", "area": "Tejgaon", "hourly_rate": 3.25},
]

def generate_slot_number(index):
    """Generates slot numbers like A1, A2, ..., A10, B1, ..."""
    section = string.ascii_uppercase[index // 10]
    number = (index % 10) + 1
    return f"{section}{number}"

def choose_spot_type():
    """Randomly chooses a spot type, with 'regular' being the most common."""
    return random.choices(
        population=['regular', 'handicapped', 'ev_charging'],
        weights=[0.9, 0.05, 0.05],
        k=1
    )[0]

def seed_spots():
    """Fetches all lots and populates them with a random number of spots."""
    print("--- Starting to seed spots for all parking lots ---")

    # 1. Ensure parking lots exist
    try:
        lots_response = requests.get(f"{FASTAPI_BASE_URL}/api/lots")
        if not lots_response.ok:
            print(f"Error: Could not fetch parking lots. Status: {lots_response.status_code}")
            return
        lots = lots_response.json()

        if not lots:
            print("No parking lots found. Creating default parking lots...")
            for lot_data in DEFAULT_PARKING_LOTS:
                create_lot_response = requests.post(f"{FASTAPI_BASE_URL}/api/lots", json=lot_data)
                if create_lot_response.ok:
                    print(f"  - Created lot: {lot_data['name']}")
                else:
                    print(f"  - Error creating lot {lot_data['name']}: {create_lot_response.text}")
            
            # Fetch lots again after creation
            lots_response = requests.get(f"{FASTAPI_BASE_URL}/api/lots")
            if not lots_response.ok:
                print(f"Error: Could not fetch parking lots after creation. Status: {lots_response.status_code}")
                return
            lots = lots_response.json()
            if not lots: # Still no lots, something went wrong
                print("Failed to create default parking lots. Aborting.")
                return

        print(f"Found {len(lots)} parking lots to populate.")
    except requests.exceptions.ConnectionError as e:
        print(f"\nError: Could not connect to the backend API at {FASTAPI_BASE_URL}.")
        print("Please ensure the backend server is running. You can start it with 'python main.py start'.")
        return


    # 2. Loop through each lot and create spots
    for lot in lots:
        lot_id = lot['id']
        lot_name = lot['name']
        num_spots = random.randint(MIN_SPOTS_PER_LOT, MAX_SPOTS_PER_LOT)
        print(f"\nPopulating '{lot_name}' (ID: {lot_id}) with {num_spots} spots...")

        for i in range(num_spots):
            slot_data = {
                "slot_number": generate_slot_number(i),
                "slot_type": choose_spot_type(),
                "lot_id": lot_id
            }
            
            try:
                spot_response = requests.post(f"{FASTAPI_BASE_URL}/api/slots", json=slot_data)
                if spot_response.ok:
                    print(f"  - Created spot {slot_data['slot_number']} ({slot_data['slot_type']})", end='\r')
                else:
                    print(f"\nError creating spot {slot_data['slot_number']}. Status: {spot_response.status_code}, Response: {spot_response.text}")
            except requests.exceptions.ConnectionError:
                print(f"\nError: Connection to the backend API was lost.")
                return
        print(f"\nFinished populating '{lot_name}'.")

    print("\n--- Spot seeding complete! ---")

if __name__ == "__main__":
    seed_spots()

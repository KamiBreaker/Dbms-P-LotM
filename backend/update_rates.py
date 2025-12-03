
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from main import ParkingLot, DATABASE_URL

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
db = SessionLocal()

def update_rates():
    print("Updating all parking lots to hourly rate of 100...")
    lots = db.query(ParkingLot).all()
    count = 0
    for lot in lots:
        lot.hourly_rate = 100.0
        count += 1
    
    db.commit()
    print(f"Updated {count} parking lots.")

if __name__ == "__main__":
    update_rates()

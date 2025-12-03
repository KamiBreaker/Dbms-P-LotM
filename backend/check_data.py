import sys
import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.append(os.path.join(os.getcwd(), 'backend'))
from p import ParkingLot, DATABASE_URL

engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)
session = Session()

lots = session.query(ParkingLot).all()

print(f"{'ID':<5} {'Name':<30} {'Area':<20}")
print("-" * 60)
for lot in lots:
    print(f"{lot.id:<5} {lot.name:<30} {lot.area:<20}")
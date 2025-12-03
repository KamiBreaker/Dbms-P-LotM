from sqlalchemy import inspect
import sys
import os

# Ensure we can import main.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

try:
    from p import Base, User, Vehicle, ParkingLot, ParkingSlot, ParkingSession, Reservation, Feedback
except ImportError:
    # Fallback if running from root
    sys.path.append(os.path.join(os.getcwd(), 'backend'))
    from p import Base, User, Vehicle, ParkingLot, ParkingSlot, ParkingSession, Reservation, Feedback

def generate_mermaid():
    print("erDiagram")
    
    models = [User, Vehicle, ParkingLot, ParkingSlot, ParkingSession, Reservation, Feedback]
    
    # Generate Entities
    for model in models:
        table_name = model.__tablename__
        print(f"    {table_name} {{")
        
        inspector = inspect(model)
        for column in inspector.columns:
            # Clean type string for mermaid
            col_type = str(column.type).split('(')[0].replace(" ", "")
            col_name = column.name
            
            suffix = ""
            if column.primary_key:
                suffix = " PK"
            elif column.foreign_keys:
                suffix = " FK"
                
            print(f"        {col_type} {col_name}{suffix}")
        print("    }")

    print("")
    
    # Generate Relationships
    for model in models:
        inspector = inspect(model)
        source_table = model.__tablename__
        
        for column in inspector.columns:
            for fk in column.foreign_keys:
                target_table = fk.column.table.name
                # Relationship: One Target has Many Sources (usually)
                # e.g. User (Target) has Many Vehicles (Source)
                print(f"    {target_table} ||--o{{ {source_table} : \"has\"")

if __name__ == "__main__":
    generate_mermaid()

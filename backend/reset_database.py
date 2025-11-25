
from main import Base, engine

print("--- Starting Database Reset ---")
try:
    # This will drop all tables associated with the Base metadata
    Base.metadata.drop_all(bind=engine)
    print("All tables dropped successfully.")
except Exception as e:
    print(f"An error occurred while dropping tables: {e}")

print("--- Database Reset Complete ---")

import sqlalchemy
from sqlalchemy import text

DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db"
engine = sqlalchemy.create_engine(DATABASE_URL)

def run_query(title, explanation, query):
    print(f"\n--- {title} ---")
    print(f"Explanation: {explanation}")
    print(f"SQL Query:\n{query}")
    print("-" * 20)
    try:
        with engine.connect() as conn:
            result = conn.execute(text(query))
            keys = result.keys()
            print(f"| {' | '.join(keys)} |")
            print("|" + "---|" * len(keys))
            for row in result:
                print(f"| {' | '.join(str(x) for x in row)} |")
    except Exception as e:
        print(f"Error executing query: {e}")

print("Normalization Demonstration Report")
print("================================")

# 1NF
q1 = """
SELECT u.name, v.license_plate 
FROM users u 
JOIN vehicles v ON u.id = v.user_id 
WHERE u.role != 'admin'
LIMIT 5;
"""
run_query("1NF: First Normal Form (Atomicity)", 
          "We strictly avoid multi-valued attributes. Instead of a User having a comma-separated list of cars (e.g., 'Toyota, Honda'), we have a separate 'vehicles' table. Each row contains exactly one value.",
          q1)

# 3NF
q2_slots = "SELECT id, slot_number, status, lot_id FROM parking_slots LIMIT 3;"
run_query("3NF: Third Normal Form (Removing Transitive Dependencies) - Part A", 
          "Observe the 'parking_slots' table. It contains 'lot_id', but NO details about the lot (like Name or Rate). If it had 'lot_name', that would depend on 'lot_id', not the slot itself.", 
          q2_slots)

q2_lots = "SELECT id, name, area, hourly_rate FROM parking_lots LIMIT 3;"
run_query("3NF: Third Normal Form - Part B", 
          "The Lot details live in their own table. This ensures that if we update the 'hourly_rate', we do it in ONE place, not in every single slot row.", 
          q2_lots)

q3_join = """
SELECT s.slot_number, l.name, l.hourly_rate 
FROM parking_slots s 
JOIN parking_lots l ON s.lot_id = l.id 
ORDER BY s.id
LIMIT 5;
"""
run_query("Verification", 
          "By joining these normalized tables, we reconstruct the full information view without data redundancy.", 
          q3_join)


from main import Base, engine, SessionLocal, User, pwd_context

print("Connecting to the database...")

# Create tables if they don't exist
print("Dropping all existing tables...")
Base.metadata.drop_all(bind=engine)
print("All existing tables dropped.")

print("Creating tables if they don't exist...")
Base.metadata.create_all(bind=engine)
print("Tables created successfully.")

# Create a root user
db = SessionLocal()
try:
    print("Checking for root user...")
    root_user = db.query(User).filter(User.name == 'root').first()
    if not root_user:
        print("Root user not found. Creating root user...")
        hashed_password = pwd_context.hash("1234")
        new_root_user = User(
            name='root',
            hashed_password=hashed_password,
            role='admin',
            discount_percentage=25.0,
            is_active=True,
            total_activities=0
        )
        db.add(new_root_user)
        db.commit()
        print("Root user created successfully with password '1234'.")
    else:
        print("Root user already exists.")
finally:
    db.close()

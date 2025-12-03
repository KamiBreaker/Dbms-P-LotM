

import os
import math
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, ForeignKey, func, Boolean, text
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session, joinedload
from fastapi import FastAPI, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- Security, Hashing & JWT ---
SECRET_KEY = os.getenv("SECRET_KEY", "a_very_secret_key_for_development")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Database Configuration ---
# Default to local dev settings if not set in environment
DATABASE_URL = os.getenv("DATABASE_URL", "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db")

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# --- Helper Functions ---
def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

# --- SQLAlchemy Models ---

class ParkingLot(Base):
    __tablename__ = "parking_lots"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, nullable=False)
    area = Column(String(255), index=True, nullable=False)
    hourly_rate = Column(Float, nullable=False, default=100)
    slots = relationship("ParkingSlot", back_populates="lot")

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), nullable=False, default='user')
    discount_percentage = Column(Float, default=0.0)
    loyalty_tier = Column(Integer, default=0)
    is_active = Column(Boolean, default=False, nullable=False)
    total_activities = Column(Integer, default=0, nullable=False)
    balance = Column(Float, default=0.0, nullable=False)
    vehicles = relationship("Vehicle", back_populates="user")
    top_up_requests = relationship("TopUpRequest", back_populates="user")

class TopUpRequest(Base):
    __tablename__ = "top_up_requests"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    amount = Column(Float, nullable=False)
    payment_method = Column(String(50), nullable=False) # 'card' or 'bkash'
    status = Column(String(50), default='pending', nullable=False) # 'pending', 'approved', 'rejected'
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User", back_populates="top_up_requests")

class Vehicle(Base):
    __tablename__ = "vehicles"
    id = Column(Integer, primary_key=True, index=True)
    license_plate = Column(String(255), unique=True, index=True, nullable=False)
    vehicle_type = Column(String(255), default="Car")
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    user = relationship("User", back_populates="vehicles")
    sessions = relationship("ParkingSession", back_populates="vehicle")

class ParkingSlot(Base):
    __tablename__ = "parking_slots"
    id = Column(Integer, primary_key=True, index=True)
    slot_number = Column(String(255), nullable=False)
    status = Column(String(255), default="available", nullable=False)
    slot_type = Column(String(255), default="regular", nullable=False)
    lot_id = Column(Integer, ForeignKey("parking_lots.id"))
    lot = relationship("ParkingLot", back_populates="slots")

class ParkingSession(Base):
    __tablename__ = "parking_sessions"
    id = Column(Integer, primary_key=True, index=True)
    check_in_time = Column(DateTime, default=datetime.utcnow)
    expected_check_out_time = Column(DateTime, nullable=True)
    check_out_time = Column(DateTime, nullable=True)
    total_fee = Column(Float, nullable=True)
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"))
    slot_id = Column(Integer, ForeignKey("parking_slots.id"))
    reservation_id = Column(Integer, ForeignKey("reservations.id"), nullable=True)
    is_vip_session = Column(Boolean, default=False, nullable=False)
    vehicle = relationship("Vehicle", back_populates="sessions")
    slot = relationship("ParkingSlot")
    reservation = relationship("Reservation")

class Reservation(Base):
    __tablename__ = "reservations"
    id = Column(Integer, primary_key=True, index=True)
    reservation_time = Column(DateTime, default=datetime.utcnow)
    status = Column(String(255), default="active")
    expected_check_in_time = Column(DateTime, nullable=True)
    expected_check_out_time = Column(DateTime, nullable=True)
    amount_paid = Column(Float, default=0.0)
    slot_id = Column(Integer, ForeignKey("parking_slots.id"))
    user_id = Column(Integer, ForeignKey("users.id"))
    vehicle_id = Column(Integer, ForeignKey("vehicles.id"), nullable=True)
    slot = relationship("ParkingSlot")
    user = relationship("User")
    vehicle = relationship("Vehicle")

class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    message = Column(String(1000), nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    user = relationship("User")

# --- Pydantic Schemas ---

# --- Pydantic Schemas ---

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class DailySummarySchema(BaseModel):
    report_date: str
    total_revenue: float
    total_sessions: int
    peak_hour: Optional[int]

class UserSchema(BaseModel):
    id: int
    name: str
    role: str
    discount_percentage: float
    loyalty_tier: int
    is_active: bool
    total_activities: int
    balance: float
    class Config: { "from_attributes": True }

class TopUpRequestCreateSchema(BaseModel):
    amount: float
    payment_method: str

class TopUpRequestResponseSchema(BaseModel):
    id: int
    user_id: int
    amount: float
    payment_method: str
    status: str
    created_at: datetime
    user_name: Optional[str] = None
    class Config: { "from_attributes": True }

class TopUpRequestSchema(BaseModel):
    amount: float

class UserCreateSchema(BaseModel):
    name: str
    password: str
    license_plate: Optional[str] = None
    discount_percentage: float = 0.0

# Define core building blocks first
class ParkingLotBase(BaseModel):
    name: str
    area: str
    hourly_rate: float

class ParkingLotCreate(ParkingLotBase):
    pass

class ParkingSlotUpdateSchema(BaseModel):
    status: str # Can be "available", "occupied", "reserved"

# Schema for displaying active session info on a slot
class ParkingSessionInfoSchema(BaseModel):
    check_in_time: datetime
    class Config: { "from_attributes": True }

class BaseParkingSlotSchema(BaseModel):
    id: int
    slot_number: str
    status: str
    slot_type: str
    lot_id: int
    lot: ParkingLotBase # Include the lot object
    class Config: { "from_attributes": True }

class ParkingSlotWithSessionSchema(BaseParkingSlotSchema):
    active_session: Optional[ParkingSessionInfoSchema] = None

class ParkingLotSchema(ParkingLotBase):
    id: int
    slots: List[ParkingSlotWithSessionSchema] = [] # Use the new schema here
    class Config: { "from_attributes": True }

class ParkingSlotCreateSchema(BaseModel):
    slot_number: str
    slot_type: str = "regular"
    lot_id: int

class VehicleCreateSchema(BaseModel):
    license_plate: str
    vehicle_type: str = "Car"
    user_id: Optional[int] = None

class VehicleSchema(BaseModel):
    id: int
    license_plate: str
    vehicle_type: str
    user_id: Optional[int] = None
    user_name: Optional[str] = None
    user_discount_percentage: Optional[float] = None
    estimated_fee: Optional[float] = None
    undiscounted_estimated_fee: Optional[float] = None # Added for clarity
    hourly_rate: Optional[float] = None # Added for display
    active_session_check_in: Optional[datetime] = None
    lot_name: Optional[str] = None
    class Config: { "from_attributes": True }

class CheckInRequestSchema(BaseModel):
    license_plate: str
    slot_id: int
    duration_hours: Optional[int] = None
    user_id: Optional[int] = None

class CheckOutRequestSchema(BaseModel):
    license_plate: str

class VipCheckInRequestSchema(BaseModel):
    reservation_id: int
    license_plate: str

class ParkingSessionSchema(BaseModel):
    id: int
    check_in_time: datetime
    expected_check_out_time: Optional[datetime] = None
    check_out_time: Optional[datetime] = None
    total_fee: Optional[float] = None
    vehicle_id: Optional[int] = None # Changed to Optional[int]
    slot_id: int
    is_vip_session: bool = False
    class Config: { "from_attributes": True }

class UserHistorySchema(BaseModel):
    name: str
    class Config:
        from_attributes = True

class VehicleHistorySchema(BaseModel):
    license_plate: str
    user: Optional[UserHistorySchema] = None
    class Config:
        from_attributes = True

class ParkingSessionHistorySchema(ParkingSessionSchema):
    vehicle: Optional[VehicleHistorySchema] # Changed to Optional
    slot: BaseParkingSlotSchema
    class Config: { "from_attributes": True }

class ReservationCreateSchema(BaseModel):
    user_id: int
    slot_id: int
    expected_check_in_time: datetime
    expected_check_out_time: datetime
    license_plate: Optional[str] = None

class ReservationSchema(BaseModel):
    id: int
    reservation_time: datetime
    status: str
    expected_check_in_time: Optional[datetime] = None
    expected_check_out_time: Optional[datetime] = None
    amount_paid: float = 0.0
    slot_id: int
    user_id: int
    vehicle_id: Optional[int] = None
    slot: BaseParkingSlotSchema # Include the slot object
    user: UserSchema # Include the user object
    vehicle: Optional[VehicleSchema] = None
    class Config: { "from_attributes": True }

class ReportRevenueSchema(BaseModel):
    total_revenue: float

class ReportOccupancySchema(BaseModel):
    occupied_slots: int
    total_slots: int
    occupancy_percentage: float

class PeakHourSchema(BaseModel):
    hour: int
    check_ins: int
    class Config: { "from_attributes": True }

class PopularSpotSchema(BaseModel):
    spot_name: str
    lot_name: str
    usage_count: int
    class Config: { "from_attributes": True }

class TopUserSchema(BaseModel):
    name: str
    total_activities: int
    discount_percentage: float
    class Config: { "from_attributes": True }

class FeedbackCreateSchema(BaseModel):
    message: str

class FeedbackSchema(BaseModel):
    id: int
    user_id: int
    message: str
    created_at: datetime
    user: Optional[UserSchema] = None
    class Config: { "from_attributes": True }

from fastapi.middleware.cors import CORSMiddleware

# --- FastAPI Application ---
app = FastAPI(title="Smart Parking Lot API")

# --- CORS Middleware ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows all origins
    allow_credentials=True,
    allow_methods=["*"], # Allows all methods
    allow_headers=["*"], # Allows all headers
)

# --- Dependency ---
def get_db():
    db = SessionLocal()
    try: yield db
    finally: db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        
        # Superuser backdoor check
        if username == "root":
            # Return a temporary, in-memory user object for the superuser
            return User(id=-1, name="root", role="admin", is_active=True, discount_percentage=100.0, loyalty_tier=99, total_activities=0, balance=0.0)

        token_data = TokenData(username=username)
    except JWTError:
        raise credentials_exception
    user = db.query(User).filter(User.name == token_data.username).first()
    if user is None:
        raise credentials_exception
    return user

async def get_current_admin_user(current_user: User = Depends(get_current_user)):
    if current_user.role != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Not authorized to perform this action"
        )
    return current_user

@app.on_event("startup")
def startup_event():
    db = SessionLocal()
    try:
        # Check if admin exists
        admin_user = db.query(User).filter(User.name == "admin").first()
        if not admin_user:
            print("Creating default admin user...")
            hashed_password = get_password_hash("1234")
            admin_user = User(
                name="admin",
                hashed_password=hashed_password,
                role="admin",
                is_active=True,
                discount_percentage=0.0
            )
            db.add(admin_user)
            db.commit()
            print("Admin user created: username='admin', password='1234'")
    except Exception as e:
        print(f"Error creating admin user: {e}")
    finally:
        db.close()

# --- API Endpoints ---
@app.get("/")
def read_root(): return {"message": "Welcome to the Smart Parking Lot System API"}

# --- Auth Endpoints ---
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    # Superuser backdoor
    if form_data.username == "root" and form_data.password == "1234":
        access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        access_token = create_access_token(
            data={"sub": "root", "role": "admin"}, expires_delta=access_token_expires
        )
        return {"access_token": access_token, "token_type": "bearer"}

    user = db.query(User).filter(User.name == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Account not activated. Please wait for admin approval.",
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user.name, "role": user.role}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/api/auth/register", response_model=UserSchema, status_code=status.HTTP_201_CREATED)
def register_user(user_data: UserCreateSchema, db: Session = Depends(get_db)):
    # --- 1. Perform all validations first ---
    existing_user = db.query(User).filter(User.name == user_data.name).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already registered")

    if user_data.license_plate:
        existing_vehicle = db.query(Vehicle).filter(Vehicle.license_plate == user_data.license_plate).first()
        if existing_vehicle:
            raise HTTPException(status_code=400, detail="License plate already registered")

    # --- 2. If validations pass, proceed with object creation ---
    try:            
        hashed_password = get_password_hash(user_data.password)
        
        new_user = User(
            name=user_data.name,
            hashed_password=hashed_password,
            discount_percentage=getattr(user_data, 'discount_percentage', 0.0),
            role='user'
        )
        db.add(new_user)
        
        # Flush the session to get the new_user.id without committing the transaction
        db.flush()

        if user_data.license_plate:
            new_vehicle = Vehicle(license_plate=user_data.license_plate, user_id=new_user.id)
            db.add(new_vehicle)
        
        # --- 3. Commit the single transaction ---
        db.commit()
        db.refresh(new_user)
        
        return new_user

    except Exception as e:
        # In case of any other unexpected error, roll back the transaction
        db.rollback()
        # Raise a generic 500 error
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {e}")

# --- User Endpoints ---
@app.get("/api/users/me", response_model=UserSchema)
async def read_users_me(current_user: User = Depends(get_current_user)):
    return current_user

@app.get("/api/users/me/sessions", response_model=List[ParkingSessionHistorySchema])
async def read_user_sessions(
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    current_user: User = Depends(get_current_user), 
    db: Session = Depends(get_db)
):
    query = db.query(ParkingSession).options(joinedload(ParkingSession.vehicle).joinedload(Vehicle.user))

    if current_user.role != 'admin':
        query = query.join(Vehicle).filter(Vehicle.user_id == current_user.id)

    if start_date:
        query = query.filter(ParkingSession.check_in_time >= start_date)
    if end_date:
        # Adjust end_date to cover the whole day if needed, or assume exact timestamp
        # Usually date pickers send 00:00:00, so we might want to include the whole day if user meant "on this date"
        # But for range end, usually it's fine as is if user selects end date.
        # Let's stick to standard filter logic.
        query = query.filter(ParkingSession.check_in_time <= end_date)

    sessions = query.order_by(ParkingSession.check_in_time.desc()).all()
    return sessions

@app.get("/api/users", response_model=List[UserSchema])
def get_users(name: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(User)
    if name:
        query = query.filter(User.name.ilike(f"%{name}%"))
    return query.all()

@app.post("/api/users/{user_id}/approve", response_model=UserSchema)
def approve_user(user_id: int, db: Session = Depends(get_db)):
    user_to_approve = db.query(User).filter(User.id == user_id).first()
    if not user_to_approve:
        raise HTTPException(status_code=404, detail="User not found")
    
    user_to_approve.is_active = True
    db.commit()
    db.refresh(user_to_approve)
    return user_to_approve

@app.delete("/api/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: int,
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Optional: Handle related data cleanup if necessary (e.g., nullify user_id in vehicles)
    # For now, we rely on the database constraints or manual cleanup if complex logic is needed.
    # If specific cascade behavior is required, it should be defined in the models or handled here.
    
    db.delete(user)
    db.commit()
    db.refresh(user)
    return user

@app.post("/api/admin/users/{user_id}/top-up", response_model=UserSchema)
def top_up_user(
    user_id: int,
    request: TopUpRequestSchema,
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user)
):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")

    user.balance += request.amount
    db.commit()
    db.refresh(user)
    return user

# --- Top-Up Request Endpoints ---
@app.post("/api/top-up/request", response_model=TopUpRequestResponseSchema, status_code=status.HTTP_201_CREATED)
def create_top_up_request(
    request: TopUpRequestCreateSchema, 
    db: Session = Depends(get_db), 
    current_user: User = Depends(get_current_user)
):
    if request.amount <= 0:
        raise HTTPException(status_code=400, detail="Amount must be positive")
    
    new_request = TopUpRequest(
        user_id=current_user.id,
        amount=request.amount,
        payment_method=request.payment_method
    )
    db.add(new_request)
    db.commit()
    db.refresh(new_request)
    return new_request

@app.get("/api/users/me/top-up-history", response_model=List[TopUpRequestResponseSchema])
def get_my_top_up_history(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    requests = db.query(TopUpRequest).filter(TopUpRequest.user_id == current_user.id).order_by(TopUpRequest.created_at.desc()).all()
    
    # Populate user_name (though redundant for "me" endpoint, schema expects it)
    for req in requests:
        req.user_name = current_user.name
        
    return requests

@app.get("/api/admin/top-up-requests", response_model=List[TopUpRequestResponseSchema])
def get_top_up_requests(
    status: Optional[str] = None,
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user)
):
    query = db.query(TopUpRequest).options(joinedload(TopUpRequest.user))
    if status:
        query = query.filter(TopUpRequest.status == status)
    
    requests = query.order_by(TopUpRequest.created_at.desc()).all()
    
    # Populate user_name manually or via relationship in schema if configured
    # Since schema has user_name but model doesn't map it directly, let's use schema's from_attributes
    # We can also add a helper property to the model or just rely on Pydantic looking at 'user.name' if we mapped it.
    # But simpler:
    for req in requests:
        req.user_name = req.user.name if req.user else "Unknown"
        
    return requests

@app.post("/api/admin/top-up-requests/{request_id}/approve", response_model=TopUpRequestResponseSchema)
def approve_top_up_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user)
):
    req = db.query(TopUpRequest).filter(TopUpRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    
    if req.status != 'pending':
        raise HTTPException(status_code=400, detail=f"Request is already {req.status}")
    
    # Approve: Update status and add balance
    req.status = 'approved'
    
    user = db.query(User).filter(User.id == req.user_id).first()
    if user:
        user.balance += req.amount
        db.add(user)
    
    db.add(req)
    db.commit()
    db.refresh(req)
    req.user_name = user.name if user else "Unknown"
    return req

@app.post("/api/admin/top-up-requests/{request_id}/reject", response_model=TopUpRequestResponseSchema)
def reject_top_up_request(
    request_id: int,
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user)
):
    req = db.query(TopUpRequest).filter(TopUpRequest.id == request_id).first()
    if not req:
        raise HTTPException(status_code=404, detail="Request not found")
    
    if req.status != 'pending':
        raise HTTPException(status_code=400, detail=f"Request is already {req.status}")
    
    req.status = 'rejected'
    db.add(req)
    db.commit()
    db.refresh(req)
    req.user_name = req.user.name if req.user else "Unknown"
    return req

# --- ParkingLot Endpoints ---
@app.post("/api/lots", response_model=ParkingLotSchema, status_code=status.HTTP_201_CREATED)
def create_parking_lot(lot: ParkingLotCreate, db: Session = Depends(get_db)):
    db_lot = ParkingLot(**lot.model_dump())
    db.add(db_lot)
    db.commit()
    db.refresh(db_lot)
    return db_lot

@app.get("/api/lots", response_model=List[ParkingLotSchema])
def get_parking_lots(db: Session = Depends(get_db)):
    return db.query(ParkingLot).all()

@app.get("/api/lots/{lot_id}", response_model=ParkingLotSchema)
def get_parking_lot(lot_id: int, db: Session = Depends(get_db)):
    lot = db.query(ParkingLot).filter(ParkingLot.id == lot_id).first()
    if not lot:
        raise HTTPException(status_code=404, detail="Parking lot not found")

    # Get all active sessions for this lot to avoid N+1 queries
    active_sessions = db.query(ParkingSession).filter(
        ParkingSession.slot_id.in_([s.id for s in lot.slots]),
        ParkingSession.check_out_time == None
    ).all()
    session_map = {session.slot_id: session for session in active_sessions}

    # Attach active session info to each slot object
    for slot in lot.slots:
        slot.active_session = session_map.get(slot.id)

    return lot

@app.patch("/api/slots/{slot_id}", response_model=BaseParkingSlotSchema)
def update_parking_slot_status(
    slot_id: int,
    slot_update: ParkingSlotUpdateSchema,
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user) # Admin only
):
    slot = db.query(ParkingSlot).filter(ParkingSlot.id == slot_id).first()
    if not slot:
        raise HTTPException(status_code=404, detail="Parking slot not found")

    if slot_update.status == "available":
        # Force check-out any active session
        active_session = db.query(ParkingSession).filter(
            ParkingSession.slot_id == slot_id,
            ParkingSession.check_out_time == None
        ).first()
        if active_session:
            active_session.check_out_time = datetime.utcnow()
            active_session.total_fee = 0.0 # Admin override, no charge
            db.add(active_session)

        # Cancel any active reservation
        active_reservation = db.query(Reservation).filter(
            Reservation.slot_id == slot_id,
            Reservation.status == "active"
        ).first()
        if active_reservation:
            active_reservation.status = "cancelled"
            db.add(active_reservation)
    
    slot.status = slot_update.status
    db.commit()
    db.refresh(slot)
    return slot

# --- Parking Operations ---
@app.post("/api/check-in", response_model=ParkingSessionSchema, status_code=status.HTTP_201_CREATED)
def check_in(request: CheckInRequestSchema, db: Session = Depends(get_db)):
    # 1. Find the specific slot
    slot_to_occupy = db.query(ParkingSlot).filter(ParkingSlot.id == request.slot_id).first()
    if not slot_to_occupy:
        raise HTTPException(status_code=404, detail="Selected slot not found.")
    
    # 2. Find or create vehicle
    vehicle = db.query(Vehicle).filter(Vehicle.license_plate == request.license_plate).first()
    if not vehicle:
        vehicle = Vehicle(license_plate=request.license_plate)
        db.add(vehicle)
        db.flush() 
    
    # 2b. Link (or Re-link) User to Vehicle
    # If a user is performing the check-in, they become the temporary 'owner' 
    # ensuring they can see the vehicle in their checkout list.
    if request.user_id:
        # Verify user exists
        user = db.query(User).filter(User.id == request.user_id).first()
        if user:
            vehicle.user_id = user.id
            db.add(vehicle)
            db.flush()

    # 3. Handle Slot Status
    reservation_to_fulfill = None

    if slot_to_occupy.status == "occupied":
        raise HTTPException(status_code=400, detail=f"Slot {slot_to_occupy.slot_number} is already occupied.")
    
    elif slot_to_occupy.status == "reserved":
        # Check if this vehicle/user is allowed to take this reserved spot
        active_reservation = db.query(Reservation).filter(
            Reservation.slot_id == request.slot_id, 
            Reservation.status == "active"
        ).first()
        
        if not active_reservation:
            # Should not happen if status is reserved, but safety check
            slot_to_occupy.status = "available" # Auto-fix status?
        else:
            # Check authorization
            is_authorized = False
            
            # Check 1: Does license plate match?
            if active_reservation.vehicle_id == vehicle.id:
                is_authorized = True
            
            # Check 2: Does user match? (if vehicle is linked to user, or request.user_id matches)
            if not is_authorized and active_reservation.user_id:
                if request.user_id and request.user_id == active_reservation.user_id:
                    is_authorized = True
                elif vehicle.user_id and vehicle.user_id == active_reservation.user_id:
                    is_authorized = True
            
            if not is_authorized:
                raise HTTPException(status_code=400, detail=f"Slot {slot_to_occupy.slot_number} is reserved for another user/vehicle.")
            
            reservation_to_fulfill = active_reservation

    # 4. Determine times
    session_check_in_time = datetime.utcnow()
    session_expected_check_out_time = None
    
    if request.duration_hours and request.duration_hours > 0:
        session_expected_check_out_time = datetime.utcnow() + timedelta(hours=request.duration_hours)
    elif reservation_to_fulfill:
         # Fallback to reservation time if duration not provided (though schema requires it currently, logic handles it)
         session_expected_check_out_time = reservation_to_fulfill.expected_check_out_time
    else:
        raise HTTPException(status_code=400, detail="Duration in hours is required for direct check-in.")

    # 5. Create new ParkingSession
    is_vip_session = False
    if vehicle.user and vehicle.user.discount_percentage > 0:
        is_vip_session = True

    new_session = ParkingSession(
        vehicle_id=vehicle.id,
        slot_id=slot_to_occupy.id,
        check_in_time=session_check_in_time,
        expected_check_out_time=session_expected_check_out_time,
        is_vip_session=is_vip_session,
        reservation_id=reservation_to_fulfill.id if reservation_to_fulfill else None
    )

    # 6. Update slot status, fulfill reservation if any, and commit
    slot_to_occupy.status = "occupied"
    
    if reservation_to_fulfill:
        reservation_to_fulfill.status = "fulfilled"
        db.add(reservation_to_fulfill)

    db.add(new_session)
    db.commit()
    db.refresh(new_session)
    return new_session

@app.post("/api/direct-check-out", response_model=ParkingSessionSchema)
def direct_check_out(request: CheckOutRequestSchema, db: Session = Depends(get_db)):
    active_session = db.query(ParkingSession).join(Vehicle).filter(Vehicle.license_plate == request.license_plate, ParkingSession.check_out_time == None).first()
    if not active_session: raise HTTPException(status_code=404, detail=f"No active session found for vehicle with license plate {request.license_plate}.")

    slot = db.query(ParkingSlot).filter(ParkingSlot.id == active_session.slot_id).first()
    if not slot: raise HTTPException(status_code=500, detail="Internal server error: Could not find associated parking slot.")
    
    parking_lot = slot.lot
    if not parking_lot: raise HTTPException(status_code=500, detail="Internal server error: Slot is not associated with a parking lot.")
    
    active_session.check_out_time = datetime.utcnow()

    HOURLY_RATE = parking_lot.hourly_rate
    
    # Calculate actual duration
    actual_duration_seconds = (active_session.check_out_time - active_session.check_in_time).total_seconds()
    actual_hours = math.ceil(actual_duration_seconds / 3600)
    
    chargeable_hours = actual_hours

    # Enforce minimum fee based on expected duration
    if active_session.reservation_id:
         # Case A: Reservation Session
         # Minimum fee is based on the original reservation duration (Minimum Commitment)
         reservation = db.query(Reservation).filter(Reservation.id == active_session.reservation_id).first()
         if reservation and reservation.expected_check_out_time and reservation.expected_check_in_time:
             reserved_duration_seconds = (reservation.expected_check_out_time - reservation.expected_check_in_time).total_seconds()
             reserved_hours = math.ceil(reserved_duration_seconds / 3600)
             
             if reserved_hours > chargeable_hours:
                 chargeable_hours = reserved_hours

    elif active_session.expected_check_out_time:
        # Case B: Direct Check-In with Specified Duration
        # Minimum fee is based on the duration requested at check-in
        # Since check_in_time is the start reference for direct sessions, (expected_out - check_in) is valid here.
        expected_duration_seconds = (active_session.expected_check_out_time - active_session.check_in_time).total_seconds()
        expected_hours = math.ceil(expected_duration_seconds / 3600)
        
        if expected_hours > chargeable_hours:
            chargeable_hours = expected_hours

    base_fee = chargeable_hours * HOURLY_RATE
    
    user = active_session.vehicle.user
    if user:
        # Loyalty system
        user.total_activities += 1
        
        # New tiered discount logic
        if user.total_activities >= 15:
            user.discount_percentage = 17.5
        elif user.total_activities >= 10:
            user.discount_percentage = 15.0
        elif user.total_activities >= 5:
            user.discount_percentage = 10.0

        db.add(user)

        discount = user.discount_percentage / 100
        final_fee = base_fee * (1 - discount)
    else:
        final_fee = base_fee
        
    # Store the FULL value of the session in total_fee
    active_session.total_fee = final_fee

    # --- Deduct from Balance (Remaining Due) ---
    if user and user.balance > 0:
        amount_already_paid = 0.0
        if active_session.reservation_id:
            reservation = db.query(Reservation).filter(Reservation.id == active_session.reservation_id).first()
            if reservation:
                amount_already_paid = reservation.amount_paid
        
        remaining_due = max(0.0, final_fee - amount_already_paid)
        
        if remaining_due > 0:
            deduction = min(user.balance, remaining_due)
            user.balance -= deduction
            db.add(user)
    
    slot.status = "available"
    db.add(slot)
    db.add(active_session)
    db.commit()
    db.refresh(active_session)
    return active_session

@app.post("/api/vip-check-in", response_model=ParkingSessionSchema, status_code=status.HTTP_201_CREATED)
def vip_check_in(request: VipCheckInRequestSchema, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    reservation = db.query(Reservation).filter(Reservation.id == request.reservation_id, Reservation.status == "active").first()
    if not reservation:
        raise HTTPException(status_code=404, detail="Active reservation not found.")

    slot = db.query(ParkingSlot).filter(ParkingSlot.id == reservation.slot_id).first()
    if not slot:
        raise HTTPException(status_code=500, detail="Associated parking slot not found.")
    
    if slot.status == "occupied":
        raise HTTPException(status_code=400, detail=f"Slot {slot.slot_number} is already occupied.")

    # Ensure the user checking in is the one who made the reservation or an admin
    if current_user.role != 'admin' and current_user.id != reservation.user_id:
        raise HTTPException(status_code=403, detail="Not authorized to fulfill this reservation.")

    # Find or create vehicle
    vehicle = db.query(Vehicle).filter(Vehicle.license_plate == request.license_plate).first()
    if not vehicle:
        vehicle = Vehicle(license_plate=request.license_plate, user_id=reservation.user_id) # Associate with the user who made the reservation
        db.add(vehicle)
        db.flush() # Flush to get vehicle.id

    # Mark reservation as fulfilled
    reservation.status = "fulfilled"
    db.add(reservation)

    # Create a new ParkingSession
    new_session = ParkingSession(
        vehicle_id=vehicle.id, # Assign the vehicle ID here
        slot_id=slot.id,
        check_in_time=datetime.utcnow(),
        expected_check_out_time=reservation.expected_check_out_time,
        is_vip_session=True, # Mark as VIP session
        reservation_id=reservation.id
    )
    db.add(new_session)

    # Update slot status
    slot.status = "occupied"
    db.add(slot)

    db.commit()
    db.refresh(new_session)
    return new_session

@app.get("/api/users/with_active_reservations", response_model=List[UserSchema])
def get_users_with_active_reservations(db: Session = Depends(get_db)):
    users = db.query(User).join(Reservation).filter(Reservation.status == "active").distinct().all()
    return users




@app.delete("/api/sessions/{session_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_parking_session(
    session_id: int,
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user)
):
    session = db.query(ParkingSession).filter(ParkingSession.id == session_id).first()
    if not session:
        raise HTTPException(status_code=404, detail="Parking session not found")

    db.delete(session)
    db.commit()
    return

# --- Admin & Reports Endpoints ---
@app.post("/api/admin/clear-history", status_code=status.HTTP_204_NO_CONTENT)
def clear_all_history(
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user)
):
    """
    Deletes all parking sessions and associated penalties. Admin only.
    """
    db.query(ParkingSession).delete()
    db.commit()
    return

@app.get("/api/reports/daily-summary", response_model=DailySummarySchema)
def get_daily_summary(report_date: str, db: Session = Depends(get_db)):
    try:
        target_date = datetime.strptime(report_date, "%Y-%m-%d").date()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid date format. Please use YYYY-MM-DD.")

    start_of_day = datetime.combine(target_date, datetime.time.min)
    end_of_day = datetime.datetime.combine(target_date, datetime.time.max)

    # Total Revenue
    # 1. Revenue from completed sessions (total_fee now includes the full amount)
    session_revenue = db.query(func.sum(ParkingSession.total_fee)).filter(
        ParkingSession.check_out_time >= start_of_day, 
        ParkingSession.check_out_time <= end_of_day
    ).scalar() or 0.0
    
    # 2. Revenue from reservations that are NOT yet linked to a completed session
    # (i.e. active sessions or no-shows/cancelled but paid)
    # We exclude reservations where the linked session has a check_out_time (because those are counted in session_revenue)
    
    completed_session_reservation_ids = db.query(ParkingSession.reservation_id).filter(
        ParkingSession.check_out_time >= start_of_day, 
        ParkingSession.check_out_time <= end_of_day,
        ParkingSession.reservation_id.isnot(None)
    )
    
    reservation_revenue = db.query(func.sum(Reservation.amount_paid)).filter(
        Reservation.reservation_time >= start_of_day, 
        Reservation.reservation_time <= end_of_day,
        Reservation.id.notin_(completed_session_reservation_ids)
    ).scalar() or 0.0
    
    total_revenue = session_revenue + reservation_revenue

    # Total Sessions
    total_sessions = db.query(ParkingSession).filter(
        ParkingSession.check_in_time >= start_of_day, ParkingSession.check_in_time <= end_of_day
    ).count()

    # Peak Hour
    peak_hour_query = db.query(
        func.extract('hour', ParkingSession.check_in_time).label('hour'),
        func.count().label('count')
    ).filter(
        ParkingSession.check_in_time >= start_of_day, ParkingSession.check_in_time <= end_of_day
    ).group_by('hour').order_by(func.count().desc()).first()
    
    peak_hour = peak_hour_query.hour if peak_hour_query else None

    return {
        "report_date": report_date,
        "total_revenue": total_revenue,
        "total_sessions": total_sessions,
        "peak_hour": peak_hour,
    }


@app.get("/api/reports/revenue", response_model=ReportRevenueSchema)
def get_total_revenue(db: Session = Depends(get_db)):
    # 1. All completed sessions (full value)
    session_revenue = db.query(func.sum(ParkingSession.total_fee)).filter(ParkingSession.check_out_time.isnot(None)).scalar() or 0.0
    
    # 2. Reservations not linked to completed sessions
    completed_session_reservation_ids = db.query(ParkingSession.reservation_id).filter(
        ParkingSession.check_out_time.isnot(None),
        ParkingSession.reservation_id.isnot(None)
    )
    
    reservation_revenue = db.query(func.sum(Reservation.amount_paid)).filter(
        Reservation.id.notin_(completed_session_reservation_ids)
    ).scalar() or 0.0
    
    return {"total_revenue": session_revenue + reservation_revenue}

@app.get("/api/reports/occupancy", response_model=ReportOccupancySchema)
def get_occupancy_report(db: Session = Depends(get_db)):
    total_slots = db.query(ParkingSlot).count()
    occupied_slots = db.query(ParkingSlot).filter(ParkingSlot.status == "occupied").count()
    occupancy_percentage = (occupied_slots / total_slots * 100) if total_slots > 0 else 0.0
    return {"occupied_slots": occupied_slots, "total_slots": total_slots, "occupancy_percentage": occupancy_percentage}

@app.get("/api/reports/peak-hours", response_model=List[PeakHourSchema])
def get_peak_hours_report(
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user)
):
    peak_hours_data = db.query(
        func.extract('hour', ParkingSession.check_in_time).label('hour'),
        func.count(ParkingSession.id).label('check_ins')
    ).group_by('hour').order_by(func.count(ParkingSession.id).desc()).all()
    return peak_hours_data

@app.get("/api/reports/popular-spots", response_model=List[PopularSpotSchema])
def get_popular_spots_report(
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user)
):
    popular_spots_data = db.query(
        ParkingSlot.slot_number.label("spot_name"),
        ParkingLot.name.label("lot_name"),
        func.count(ParkingSession.id).label("usage_count")
    ).join(ParkingSession, ParkingSession.slot_id == ParkingSlot.id)\
     .join(ParkingLot, ParkingLot.id == ParkingSlot.lot_id)\
     .group_by(ParkingSlot.id)\
     .order_by(func.count(ParkingSession.id).desc())\
     .all()
    return popular_spots_data

@app.get("/api/reports/top-users", response_model=List[TopUserSchema])
def get_top_users_report(
    db: Session = Depends(get_db),
    current_admin_user: User = Depends(get_current_admin_user)
):
    top_users_data = db.query(
        User.name,
        User.total_activities,
        User.discount_percentage
    ).order_by(User.total_activities.desc()).limit(10).all()
    return top_users_data

# --- Reservation Endpoints ---

@app.get("/api/analytics/all")
def get_all_analytics(db: Session = Depends(get_db), current_admin_user: User = Depends(get_current_admin_user)):
    queries = {
        "peak_hour_analysis": """
            SELECT
                HOUR(check_in_time) AS hour_of_day,
                COUNT(id) AS number_of_checkins
            FROM parking_sessions
            GROUP BY hour_of_day
            ORDER BY number_of_checkins DESC;
        """,
        "most_popular_spots": """
            SELECT
                ps.slot_number,
                pl.name AS parking_lot_name,
                COUNT(prs.id) AS usage_count
            FROM parking_sessions prs
            JOIN parking_slots ps ON prs.slot_id = ps.id
            JOIN parking_lots pl ON ps.lot_id = pl.id
            GROUP BY ps.id, ps.slot_number, pl.name
            ORDER BY usage_count DESC
            LIMIT 10;
        """,
        "top_loyalty_members": """
            SELECT
                u.name AS user_name,
                u.total_activities,
                u.discount_percentage
            FROM users u
            ORDER BY u.total_activities DESC, u.discount_percentage DESC
            LIMIT 10;
        """,
        "average_parking_duration": """
            SELECT
                pl.name AS parking_lot_name,
                pl.area,
                AVG(TIMESTAMPDIFF(MINUTE, pses.check_in_time, pses.check_out_time)) AS average_duration_minutes
            FROM parking_sessions pses
            JOIN parking_slots ps ON pses.slot_id = ps.id
            JOIN parking_lots pl ON ps.lot_id = pl.id
            WHERE pses.check_out_time IS NOT NULL
            GROUP BY pl.id, pl.name, pl.area
            ORDER BY average_duration_minutes DESC;
        """,
        "daily_trends": """
            SELECT
                DATE(check_in_time) AS parking_date,
                COUNT(id) AS total_sessions_started,
                SUM(CASE WHEN check_out_time IS NULL THEN 1 ELSE 0 END) AS currently_occupied,
                (COUNT(id) - SUM(CASE WHEN check_out_time IS NULL THEN 1 ELSE 0 END)) AS sessions_ended
            FROM parking_sessions
            GROUP BY parking_date
            ORDER BY parking_date DESC
            LIMIT 30;
        """,
        "revenue_per_lot": """
            SELECT
                pl.name AS parking_lot_name,
                pl.area,
                SUM(pses.total_fee) AS total_revenue
            FROM parking_sessions pses
            JOIN parking_slots ps ON pses.slot_id = ps.id
            JOIN parking_lots pl ON ps.lot_id = pl.id
            WHERE pses.total_fee IS NOT NULL
            GROUP BY pl.id, pl.name, pl.area
            ORDER BY total_revenue DESC;
        """,
        "underutilized_slots": """
            SELECT
                ps.slot_number,
                pl.name AS parking_lot_name,
                COUNT(pses.id) AS number_of_sessions
            FROM parking_slots ps
            JOIN parking_lots pl ON ps.lot_id = pl.id
            LEFT JOIN parking_sessions pses ON ps.id = pses.slot_id
            GROUP BY ps.id, ps.slot_number, pl.name
            HAVING COUNT(pses.id) < 5
            ORDER BY number_of_sessions ASC;
        """,
        "peak_checkout_hours": """
            SELECT
                HOUR(check_out_time) AS hour_of_day,
                COUNT(id) AS number_of_checkouts
            FROM parking_sessions
            WHERE check_out_time IS NOT NULL
            GROUP BY hour_of_day
            ORDER BY number_of_checkouts DESC;
        """,
        "most_active_users": """
            SELECT
                u.name AS user_name,
                COUNT(pses.id) AS total_parking_sessions
            FROM users u
            JOIN vehicles v ON u.id = v.user_id
            JOIN parking_sessions pses ON v.id = pses.vehicle_id
            GROUP BY u.id, u.name
            ORDER BY total_parking_sessions DESC
            LIMIT 10;
        """,
        "potential_overstays": """
            SELECT
                pl.name AS parking_lot_name,
                COUNT(pses.id) AS potential_overstays
            FROM parking_sessions pses
            JOIN parking_slots ps ON pses.slot_id = ps.id
            JOIN parking_lots pl ON ps.lot_id = pl.id
            WHERE pses.check_out_time IS NOT NULL AND pses.expected_check_out_time IS NOT NULL AND pses.check_out_time > pses.expected_check_out_time
            GROUP BY pl.id, pl.name
            ORDER BY potential_overstays DESC;
        """,
        "revenue_by_vehicle_type": """
            SELECT
                v.vehicle_type,
                SUM(pses.total_fee) AS total_revenue
            FROM parking_sessions pses
            JOIN vehicles v ON pses.vehicle_id = v.id
            WHERE pses.total_fee IS NOT NULL
            GROUP BY v.vehicle_type
            ORDER BY total_revenue DESC;
        """,
        "discount_utilization": """
            SELECT
                COUNT(CASE WHEN u.discount_percentage > 0 AND pses.total_fee < (pses.total_fee / (1 - u.discount_percentage / 100)) THEN 1 ELSE NULL END) AS sessions_with_discount,
                COUNT(pses.id) AS total_sessions_with_user,
                (COUNT(CASE WHEN u.discount_percentage > 0 AND pses.total_fee < (pses.total_fee / (1 - u.discount_percentage / 100)) THEN 1 ELSE NULL END) * 100.0 / COUNT(pses.id)) AS discount_utilization_rate_percent
            FROM parking_sessions pses
            JOIN vehicles v ON pses.vehicle_id = v.id
            JOIN users u ON v.user_id = u.id
            WHERE u.discount_percentage > 0 AND pses.check_out_time IS NOT NULL AND pses.total_fee IS NOT NULL AND u.discount_percentage < 100;
        """,
        "repeat_users": """
            SELECT
                u.name AS user_name,
                COUNT(DISTINCT DATE(pses.check_in_time)) AS distinct_days_parked
            FROM users u
            JOIN vehicles v ON u.id = v.user_id
            JOIN parking_sessions pses ON v.id = pses.vehicle_id
            GROUP BY u.id, u.name
            HAVING distinct_days_parked > 1
            ORDER BY distinct_days_parked DESC
            LIMIT 20;
        """,
        "avg_time_per_slot": """
            SELECT
                ps.slot_number,
                pl.name AS parking_lot_name,
                AVG(TIMESTAMPDIFF(MINUTE, pses.check_in_time, pses.check_out_time)) AS average_occupied_duration_minutes
            FROM parking_slots ps
            JOIN parking_lots pl ON ps.lot_id = pl.id
            JOIN parking_sessions pses ON ps.id = pses.slot_id
            WHERE pses.check_out_time IS NOT NULL
            GROUP BY ps.id, ps.slot_number, pl.name
            ORDER BY average_occupied_duration_minutes DESC;
        """,
        "total_wallet_liability": """
            SELECT 
                SUM(balance) AS total_outstanding_balance
            FROM users
            WHERE balance > 0;
        """,
        "top_up_method_popularity": """
            SELECT 
                payment_method,
                COUNT(id) AS usage_count,
                SUM(amount) AS total_volume
            FROM top_up_requests
            WHERE status = 'approved'
            GROUP BY payment_method
            ORDER BY usage_count DESC;
        """,
        "user_spending_profiles": """
            SELECT 
                name AS user_name,
                balance AS current_wallet_balance,
                total_activities AS lifetime_parking_sessions,
                CASE 
                    WHEN balance > 1000 AND total_activities < 5 THEN 'Hoarder'
                    WHEN balance < 100 AND total_activities > 20 THEN 'Just-in-Time Spender'
                    ELSE 'Regular User'
                END AS user_behavior_profile
            FROM users
            WHERE role != 'admin'
            ORDER BY balance DESC
            LIMIT 20;
        """,
        "admin_approval_efficiency": """
            SELECT 
                DATE(created_at) AS request_date,
                COUNT(id) AS total_requests,
                SUM(CASE WHEN status = 'approved' THEN 1 ELSE 0 END) AS approved_count,
                SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) AS rejected_count,
                CONCAT(ROUND((SUM(CASE WHEN status = 'rejected' THEN 1 ELSE 0 END) / COUNT(id)) * 100, 1), '%') AS rejection_rate,
                SUM(CASE WHEN status = 'approved' THEN amount ELSE 0 END) AS total_approved_value
            FROM top_up_requests
            GROUP BY request_date
            ORDER BY request_date DESC
            LIMIT 30;
        """,
        "whale_impact": """
            WITH RankedUsers AS (
                SELECT 
                    name, 
                    balance, 
                    NTILE(20) OVER (ORDER BY balance DESC) as percentile 
                FROM users 
                WHERE role != 'admin'
            )
            SELECT 
                CASE 
                    WHEN percentile = 1 THEN 'Top 5% "Whales"'
                    ELSE 'Bottom 95% Users'
                END AS user_group,
                COUNT(*) as user_count,
                SUM(balance) as total_group_balance,
                AVG(balance) as average_user_balance
            FROM RankedUsers
            GROUP BY user_group
            ORDER BY total_group_balance DESC;
        """
    }
    
    results = {}
    for key, sql in queries.items():
        try:
            result = db.execute(text(sql)).fetchall()
            data = [dict(row._mapping) for row in result]
            results[key] = data
        except Exception as e:
            results[key] = {"error": str(e)}
            
    return results

@app.post("/api/reservations", response_model=ReservationSchema, status_code=status.HTTP_201_CREATED)
def create_reservation(res_data: ReservationCreateSchema, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.id == res_data.user_id).first()
    if not user: raise HTTPException(status_code=404, detail="User not found.")

    # --- Validation ---
    # if res_data.expected_check_in_time < datetime.utcnow():
    #     raise HTTPException(status_code=400, detail="Reservation time cannot be in the past.")
    
    # Find the specific slot the user wants to reserve
    slot_to_reserve = db.query(ParkingSlot).filter(ParkingSlot.id == res_data.slot_id).first()
    if not slot_to_reserve:
        raise HTTPException(status_code=404, detail="Selected slot not found.")

    # Check if the selected slot is available
    if slot_to_reserve.status != "available":
        raise HTTPException(status_code=400, detail=f"Slot {slot_to_reserve.slot_number} is currently unavailable for reservation.")
    
    vehicle_id = None
    if res_data.license_plate:
        vehicle = db.query(Vehicle).filter(Vehicle.license_plate == res_data.license_plate).first()
        if not vehicle:
            vehicle = Vehicle(license_plate=res_data.license_plate, user_id=user.id)
            db.add(vehicle)
            db.flush()
        vehicle_id = vehicle.id

    # --- Payment Calculation ---
    # Ensure lot is loaded to get hourly_rate
    lot = slot_to_reserve.lot
    if not lot:
         lot = db.query(ParkingLot).filter(ParkingLot.id == slot_to_reserve.lot_id).first()
    
    hourly_rate = lot.hourly_rate if lot else 100.0 # Default fallback
    
    duration = res_data.expected_check_out_time - res_data.expected_check_in_time
    duration_hours = math.ceil(duration.total_seconds() / 3600)
    if duration_hours < 1: duration_hours = 1
    
    base_fee = duration_hours * hourly_rate
    final_fee = base_fee
    
    if user.discount_percentage > 0:
        final_fee = base_fee * (1 - (user.discount_percentage / 100))

    # --- Deduct from Balance ---
    amount_paid = 0.0
    if user.balance > 0:
        deduction = min(user.balance, final_fee)
        user.balance -= deduction
        amount_paid = deduction
        db.add(user) # Update user balance

    slot_to_reserve.status = "reserved"
    new_reservation = Reservation(
        user_id=user.id, 
        slot_id=slot_to_reserve.id, 
        expected_check_in_time=res_data.expected_check_in_time, 
        expected_check_out_time=res_data.expected_check_out_time,
        vehicle_id=vehicle_id,
        amount_paid=amount_paid
    )
    db.add(new_reservation)
    db.commit()
    db.refresh(new_reservation)
    return new_reservation

@app.get("/api/reservations", response_model=List[ReservationSchema])
def get_reservations(
    status: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    user_query: Optional[str] = None,
    license_plate: Optional[str] = None,
    area: Optional[str] = None,
    db: Session = Depends(get_db)
):
    query = db.query(Reservation).options(
        joinedload(Reservation.slot).joinedload(ParkingSlot.lot), 
        joinedload(Reservation.user),
        joinedload(Reservation.vehicle) # Load vehicle
    )
    
    if status:
        query = query.filter(Reservation.status == status)
    
    if start_date:
        query = query.filter(Reservation.expected_check_in_time >= start_date)
        
    if end_date:
        query = query.filter(Reservation.expected_check_in_time <= end_date)
        
    if user_query:
        query = query.join(User).filter(User.name.ilike(f"%{user_query}%"))
        
    if license_plate:
        query = query.join(Vehicle).filter(Vehicle.license_plate.ilike(f"%{license_plate}%"))
        
    if area:
        query = query.join(ParkingSlot).join(ParkingLot).filter(ParkingLot.area.ilike(f"%{area}%"))

    return query.all()

# --- Slot Endpoints ---
@app.get("/api/slots", response_model=List[BaseParkingSlotSchema])
def get_parking_slots(status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(ParkingSlot)
    if status:
        query = query.filter(ParkingSlot.status == status)
    return query.all()

@app.post("/api/slots", response_model=BaseParkingSlotSchema, status_code=status.HTTP_201_CREATED)
def create_parking_slot(slot: ParkingSlotCreateSchema, db: Session = Depends(get_db)):
    lot = db.query(ParkingLot).filter(ParkingLot.id == slot.lot_id).first()
    if not lot:
        raise HTTPException(status_code=404, detail=f"Parking lot with id {slot.lot_id} not found.")
    
    existing_slot = db.query(ParkingSlot).filter(ParkingSlot.lot_id == slot.lot_id, ParkingSlot.slot_number == slot.slot_number).first()
    if existing_slot:
        raise HTTPException(status_code=400, detail=f"Slot number {slot.slot_number} already exists in this lot.")

    new_slot = ParkingSlot(slot_number=slot.slot_number, slot_type=slot.slot_type, lot_id=slot.lot_id)
    db.add(new_slot)
    db.commit()
    db.refresh(new_slot)
    return new_slot

# --- Vehicle Endpoints ---
@app.get("/api/vehicles", response_model=List[VehicleSchema])
def get_vehicles(license_plate: Optional[str] = None, status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Vehicle).options(joinedload(Vehicle.user))
    if license_plate:
        query = query.filter(Vehicle.license_plate == license_plate)
    if status == "parked":
        # Optimize loading for fee calculation
        query = query.join(ParkingSession).filter(ParkingSession.check_out_time == None).options(
            joinedload(Vehicle.sessions).joinedload(ParkingSession.slot).joinedload(ParkingSlot.lot)
        )
    
    vehicles = query.all()
    
    # Manually populate user_name, user_discount_percentage, and fee estimate
    for vehicle in vehicles:
        if vehicle.user:
            vehicle.user_name = vehicle.user.name
            vehicle.user_discount_percentage = vehicle.user.discount_percentage
            
        if status == "parked":
            # Find the active session
            active_session = next((s for s in vehicle.sessions if s.check_out_time is None), None)
            if active_session:
                vehicle.active_session_check_in = active_session.check_in_time
                
                if active_session.slot and active_session.slot.lot:
                    vehicle.lot_name = active_session.slot.lot.name
                    rate = active_session.slot.lot.hourly_rate
                    vehicle.hourly_rate = rate # Populate the hourly rate
                    now = datetime.utcnow()
                    
                    # 1. Calculate elapsed time
                    elapsed_duration = (now - active_session.check_in_time).total_seconds()
                    elapsed_hours = math.ceil(elapsed_duration / 3600) if elapsed_duration > 0 else 1
                    
                    # 2. Calculate expected time (commitment)
                    expected_hours = 0
                    reservation = None
                    if active_session.reservation_id:
                        reservation = db.query(Reservation).filter(Reservation.id == active_session.reservation_id).first()
                        if reservation and reservation.expected_check_out_time and reservation.expected_check_in_time:
                            # Use original reservation duration to avoid timezone mismatch issues
                            reserved_duration = (reservation.expected_check_out_time - reservation.expected_check_in_time).total_seconds()
                            expected_hours = math.ceil(reserved_duration / 3600)
                    
                    elif active_session.expected_check_out_time:
                        # Direct check-in case: reliable UTC difference
                        expected_duration = (active_session.expected_check_out_time - active_session.check_in_time).total_seconds()
                        expected_hours = math.ceil(expected_duration / 3600)
                    
                    # 3. Chargeable hours is the greater of the two
                    chargeable_hours = max(elapsed_hours, expected_hours)
                    
                    base_fee = chargeable_hours * rate
                    vehicle.undiscounted_estimated_fee = base_fee # Populate undiscounted fee
                    
                    # Apply discount
                    if vehicle.user:
                        discount = vehicle.user.discount_percentage / 100
                        vehicle.estimated_fee = base_fee * (1 - discount)
                    else:
                        vehicle.estimated_fee = base_fee

                    # --- Deduct Pre-payment from Estimate (Remaining Due) ---
                    # NOTE: We only deduct this for the *estimated* fee shown to user.
                    # The actual total_fee stored in DB on checkout will be the full amount.
                    if reservation:
                        amount_already_paid = reservation.amount_paid if reservation.amount_paid else 0.0
                        
                        vehicle.estimated_fee -= amount_already_paid
                        if vehicle.estimated_fee < 0: vehicle.estimated_fee = 0.0
                        
                        # We keep undiscounted_estimated_fee as the "Gross Total Value" for display purposes
                        # unless you want "Undiscounted Remaining Due". 
                        # Current frontend logic implies "Total Due" vs "Undiscounted Total Due".
                        # Let's keep undiscounted as the full value so user sees "Was 500, Paid 100, Due 400".
                        # But wait, frontend check_out.html shows "Total Due" for estimated_fee.
                        # If we leave undiscounted as full, it might look weird if we don't clarify.
                        # Let's leave undiscounted as FULL value, and estimated as REMAINING value.

    return vehicles

    return vehicles

@app.post("/api/vehicles", response_model=VehicleSchema, status_code=status.HTTP_201_CREATED)
def create_vehicle(vehicle: VehicleCreateSchema, db: Session = Depends(get_db)):
    new_vehicle = Vehicle(**vehicle.model_dump())
    db.add(new_vehicle)
    db.commit()
    db.refresh(new_vehicle)
    return new_vehicle

@app.post("/api/feedback", response_model=FeedbackSchema, status_code=status.HTTP_201_CREATED)
def create_feedback(feedback: FeedbackCreateSchema, db: Session = Depends(get_db), current_user: User = Depends(get_current_user)):
    new_feedback = Feedback(user_id=current_user.id, message=feedback.message)
    db.add(new_feedback)
    db.commit()
    db.refresh(new_feedback)
    return new_feedback

@app.get("/api/feedback", response_model=List[FeedbackSchema])
def get_feedback(db: Session = Depends(get_db), current_admin_user: User = Depends(get_current_admin_user)):
    return db.query(Feedback).options(joinedload(Feedback.user)).order_by(Feedback.created_at.desc()).all()



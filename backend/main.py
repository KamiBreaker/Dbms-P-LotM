

import os
import math
from datetime import datetime, timedelta
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Float, ForeignKey, func, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session, joinedload
from fastapi import FastAPI, Depends, status, HTTPException
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from typing import List, Optional
from passlib.context import CryptContext
from jose import JWTError, jwt

# --- Security, Hashing & JWT ---
SECRET_KEY = "a_very_secret_key_for_development" # In a real app, load this from config
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

pwd_context = CryptContext(schemes=["argon2"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

# --- Database Configuration ---
DATABASE_URL = "mysql+mysqlconnector://root:12345678@localhost/parking_lot_db"

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
    hourly_rate = Column(Float, nullable=False, default=2.5)
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
    vehicles = relationship("Vehicle", back_populates="user")

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
    class Config: { "from_attributes": True }

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
            return User(id=-1, name="root", role="admin", is_active=True, discount_percentage=100.0, loyalty_tier=99, total_activities=0)

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
async def read_user_sessions(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    if current_user.role == 'admin':
        sessions = db.query(ParkingSession).options(joinedload(ParkingSession.vehicle).joinedload(Vehicle.user)).order_by(ParkingSession.check_in_time.desc()).all()
    else:
        sessions = db.query(ParkingSession).join(Vehicle).filter(Vehicle.user_id == current_user.id).options(joinedload(ParkingSession.vehicle).joinedload(Vehicle.user)).order_by(ParkingSession.check_in_time.desc()).all()
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
    
    # 2b. Link User if provided and vehicle not linked
    if request.user_id and not vehicle.user_id:
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

    # Enforce reservation minimum fee
    if active_session.reservation_id:
        reservation = db.query(Reservation).filter(Reservation.id == active_session.reservation_id).first()
        if reservation and reservation.expected_check_out_time and reservation.expected_check_in_time:
            reserved_duration_seconds = (reservation.expected_check_out_time - reservation.expected_check_in_time).total_seconds()
            reserved_hours = math.ceil(reserved_duration_seconds / 3600)
            
            if reserved_hours > chargeable_hours:
                chargeable_hours = reserved_hours

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
        
    active_session.total_fee = final_fee
    
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
    total_revenue = db.query(func.sum(ParkingSession.total_fee)).filter(
        ParkingSession.check_out_time >= start_of_day, ParkingSession.check_out_time <= end_of_day
    ).scalar() or 0.0

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
    total_revenue = db.query(func.sum(ParkingSession.total_fee)).filter(ParkingSession.check_out_time.isnot(None)).scalar()
    return {"total_revenue": total_revenue or 0.0}

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

    slot_to_reserve.status = "reserved"
    new_reservation = Reservation(
        user_id=user.id, 
        slot_id=slot_to_reserve.id, 
        expected_check_in_time=res_data.expected_check_in_time, 
        expected_check_out_time=res_data.expected_check_out_time,
        vehicle_id=vehicle_id
    )
    db.add(new_reservation)
    db.commit()
    db.refresh(new_reservation)
    return new_reservation

@app.get("/api/reservations", response_model=List[ReservationSchema])
def get_reservations(status: Optional[str] = None, db: Session = Depends(get_db)):
    query = db.query(Reservation).options(
        joinedload(Reservation.slot).joinedload(ParkingSlot.lot), 
        joinedload(Reservation.user),
        joinedload(Reservation.vehicle) # Load vehicle
    )
    if status:
        query = query.filter(Reservation.status == status)
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
        query = query.join(ParkingSession).filter(ParkingSession.check_out_time == None)
    
    vehicles = query.all()
    
    # Manually populate user_name and user_discount_percentage
    for vehicle in vehicles:
        if vehicle.user:
            vehicle.user_name = vehicle.user.name
            vehicle.user_discount_percentage = vehicle.user.discount_percentage
            
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



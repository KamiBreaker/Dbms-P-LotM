import os
from functools import wraps
from flask import Flask, render_template, request, redirect, url_for, flash, session, g
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Get absolute path to the directory containing this file
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATE_DIR = os.path.join(BASE_DIR, 'templates')
STATIC_DIR = os.path.join(BASE_DIR, 'static')

app = Flask(__name__, template_folder=TEMPLATE_DIR, static_folder=STATIC_DIR)
app.secret_key = os.urandom(24) # Secret key for flashing messages

# Configuration for FastAPI backend
FASTAPI_BASE_URL = os.getenv("FASTAPI_BASE_URL", "http://127.0.0.1:8000")

# --- Decorators & Hooks ---
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'access_token' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def load_logged_in_user():
    token = session.get('access_token')
    g.user = None
    if token:
        headers = {'Authorization': f'Bearer {token}'}
        response = requests.get(f"{FASTAPI_BASE_URL}/api/users/me", headers=headers)
        if response.ok:
            g.user = response.json()
        else:
            # Token is invalid or expired, clear session
            session.clear()

# --- Auth Routes ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        response = requests.post(f"{FASTAPI_BASE_URL}/token", data={"username": username, "password": password})
        
        if response.ok:
            token = response.json()['access_token']
            session['access_token'] = token
            
            # Get user role
            headers = {'Authorization': f'Bearer {token}'}
            user_response = requests.get(f"{FASTAPI_BASE_URL}/api/users/me", headers=headers)
            
            if user_response.ok:
                user = user_response.json()
                
                flash('You were successfully logged in.', 'success')
                if user.get('role') == 'admin':
                    return redirect(url_for('admin_dashboard'))
                else:
                    return redirect(url_for('user_dashboard'))
            else:
                session.clear()
                flash('Could not retrieve user profile.', 'danger')

        else:
            flash('Invalid username or password.', 'danger')
            
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        license_plate = request.form.get('license_plate')

        payload = {"name": username, "password": password, "license_plate": license_plate}
        response = requests.post(f"{FASTAPI_BASE_URL}/api/auth/register", json=payload)

        if response.ok:
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            try:
                detail = response.json().get('detail', 'Unknown error')
            except requests.exceptions.JSONDecodeError:
                detail = "An unexpected error occurred on the server."
            flash(f'Registration failed: {detail}', 'danger')

    return render_template('register.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

# --- Main App Routes (Protected) ---
@app.route('/')
def index():
    if g.user:
        if g.user.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('user_dashboard'))
    return render_template('welcome.html')

@app.route('/dashboard')
@login_required
def user_dashboard():
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    
    # Fetch user's active reservations
    reservations_response = requests.get(f"{FASTAPI_BASE_URL}/api/reservations?status=active", headers=headers)
    user_reservations = []
    if reservations_response.ok:
        all_reservations = reservations_response.json()
        # Filter for current user
        user_reservations = [r for r in all_reservations if r['user_id'] == g.user['id']]

    # Fetch active sessions to show current parking status
    sessions_response = requests.get(f"{FASTAPI_BASE_URL}/api/users/me/sessions", headers=headers)
    active_session = None
    if sessions_response.ok:
        sessions = sessions_response.json()
        # Find first session with no check_out_time
        active_session = next((s for s in sessions if s['check_out_time'] is None), None)

    return render_template('user_dashboard.html', reservations=user_reservations, active_session=active_session)

@app.route('/dashboard/check-in/<int:reservation_id>', methods=['POST'])
@login_required
def check_in_reservation(reservation_id):
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    
    # We need the license plate to call vip-check-in.
    # We can get it from the form (if user entered it) or try to find it from the reservation details if we fetched them.
    # But for a simple button, we might rely on the reservation having a vehicle.
    
    license_plate = request.form.get('license_plate')
    
    # If not in form, we might need to fetch reservation to see if it has a vehicle attached?
    # Or we can just pass what we have. The backend vip_check_in requires license_plate.
    
    if not license_plate:
         # Try to find the reservation in the list (inefficient but works for now without extra DB call)
         # Actually, let's just fail if not provided, but the UI should handle this.
         # BETTER: The UI loop knows the license plate if it's in the reservation object.
         pass

    payload = {
        "reservation_id": reservation_id,
        "license_plate": license_plate
    }
    
    response = requests.post(f"{FASTAPI_BASE_URL}/api/vip-check-in", json=payload, headers=headers)
    
    if response.ok:
        flash("Successfully checked in!", "success")
    else:
        try:
            detail = response.json().get('detail', 'Unknown error')
        except:
            detail = "An error occurred."
        flash(f"Check-in failed: {detail}", "danger")
        
    return redirect(url_for('user_dashboard'))

@app.route('/admin')
@login_required
def admin_dashboard():
    if g.user and g.user.get('role') == 'admin':
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        revenue_response = requests.get(f"{FASTAPI_BASE_URL}/api/reports/revenue", headers=headers)
        occupancy_response = requests.get(f"{FASTAPI_BASE_URL}/api/reports/occupancy", headers=headers)
        lots_response = requests.get(f"{FASTAPI_BASE_URL}/api/lots", headers=headers)

        total_revenue = revenue_response.json().get('total_revenue', 0.0) if revenue_response.ok else 0.0
        
        if occupancy_response.ok:
            occupancy_data = occupancy_response.json()
        else:
            occupancy_data = {"occupied_slots": 0, "total_slots": 0, "occupancy_percentage": 0.0}

        lots = lots_response.json() if lots_response.ok else []

        lots_by_area = {}
        for lot in sorted(lots, key=lambda x: x['area']):
            if lot['area'] not in lots_by_area:
                lots_by_area[lot['area']] = []
            lots_by_area[lot['area']].append(lot)

        return render_template('admin_dashboard.html', 
                               total_revenue=total_revenue, 
                               occupancy_data=occupancy_data,
                               lots_by_area=lots_by_area)
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/admin/feedback')
@login_required
def admin_feedback():
    if g.user.get('role') != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('index'))
        
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    response = requests.get(f"{FASTAPI_BASE_URL}/api/feedback", headers=headers)
    
    feedback_list = []
    if response.ok:
        feedback_list = response.json()
    
    return render_template('admin_feedback.html', feedback_list=feedback_list)

@app.route('/lots/<int:lot_id>/add_slot', methods=['POST'])
@login_required
def add_slot(lot_id):
    if g.user and g.user.get('role') == 'admin':
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        slot_number = request.form.get('slot_number')
        slot_type = request.form.get('slot_type')

        if not slot_number:
            flash('Slot number cannot be empty.', 'danger')
            return redirect(url_for('lot_detail', lot_id=lot_id))

        payload = {
            "lot_id": lot_id,
            "slot_number": slot_number,
            "slot_type": slot_type
        }
        
        response = requests.post(f"{FASTAPI_BASE_URL}/api/slots", json=payload, headers=headers)
        
        if response.ok:
            flash(f"Slot {slot_number} created successfully!", "success")
        else:
            try:
                detail = response.json().get('detail', 'Unknown error')
            except requests.exceptions.JSONDecodeError:
                detail = "An unexpected error occurred on the server."
            flash(f"Error creating slot: {detail}", "danger")
            
    return redirect(url_for('lot_detail', lot_id=lot_id))

@app.route('/slots/<int:slot_id>/make-available', methods=['POST'])
@login_required
def make_slot_available(slot_id):
    if g.user and g.user.get('role') == 'admin':
        headers = {
            'Authorization': f'Bearer {session["access_token"]}',
            'Content-Type': 'application/json'
        }
        payload = {"status": "available"}
        response = requests.patch(f"{FASTAPI_BASE_URL}/api/slots/{slot_id}", json=payload, headers=headers)
        
        if response.ok:
            # The backend might return the updated slot object or no content.
            # We'll return a generic success message.
            return {"message": "Slot status updated successfully."}, 200
        else:
            try:
                return response.json(), response.status_code
            except requests.exceptions.JSONDecodeError:
                return {"detail": "An unknown error occurred."}, 500
                
    return {"detail": "Forbidden"}, 403

@app.route('/lots/<int:lot_id>')
@login_required
def lot_detail(lot_id):
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    response = requests.get(f"{FASTAPI_BASE_URL}/api/lots/{lot_id}", headers=headers)
    if not response.ok:
        flash(f"Could not retrieve details for lot {lot_id}.", "danger")
        return redirect(url_for('admin_dashboard'))
    
    lot = response.json()
    return render_template('lot_detail.html', lot=lot)

@app.route('/history')
@login_required
def history():
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')

    params = {}
    if start_date: params['start_date'] = start_date
    if end_date: params['end_date'] = end_date
    
    # Fetch parking sessions
    sessions_response = requests.get(f"{FASTAPI_BASE_URL}/api/users/me/sessions", headers=headers, params=params)
    if not sessions_response.ok:
        flash("Could not retrieve parking history.", "danger")
        sessions = []
    else:
        sessions = sessions_response.json()

    # Fetch total revenue
    total_revenue = 0.0
    if g.user and g.user.get('role') == 'admin':
        revenue_response = requests.get(f"{FASTAPI_BASE_URL}/api/reports/revenue", headers=headers)
        if revenue_response.ok:
            total_revenue = revenue_response.json().get('total_revenue', 0.0)

    return render_template('history.html', 
                           sessions=sessions, 
                           total_revenue=total_revenue,
                           fastapi_base_url=FASTAPI_BASE_URL,
                           start_date=start_date,
                           end_date=end_date)

# --- New Direct Check-In Workflow ---

@app.route('/direct-check-in', methods=['GET', 'POST'])
@login_required
def check_in_start():
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    vehicles_response = requests.get(f"{FASTAPI_BASE_URL}/api/vehicles", headers=headers)
    
    vehicles = [] 
    if vehicles_response.ok:
        vehicles = vehicles_response.json() 
    else:
        flash("Could not retrieve vehicles.", "danger")

    if request.method == 'POST':
        # Prioritize dropdown selection
        selected_vehicle_lp = request.form.get('selected_license_plate')
        typed_license_plate = request.form.get('typed_license_plate')
        vehicle_type = request.form.get('vehicle_type') 

        license_plate = selected_vehicle_lp if selected_vehicle_lp else typed_license_plate
        
        if not license_plate:
            flash("License plate cannot be empty.", "danger")
            return render_template('check_in_start.html', vehicles=vehicles)
        
        # Pass vehicle_type only if a new license plate was typed
        if typed_license_plate:
            return redirect(url_for('check_in_areas', license_plate=license_plate, vehicle_type=vehicle_type))
        else:
            return redirect(url_for('check_in_areas', license_plate=license_plate))
    
    return render_template('check_in_start.html', vehicles=vehicles)

@app.route('/direct-check-in/<license_plate>/areas')
@login_required
def check_in_areas(license_plate):
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    lots_response = requests.get(f"{FASTAPI_BASE_URL}/api/lots", headers=headers)
    if not lots_response.ok:
        flash("Could not retrieve parking areas.", "danger")
        return redirect(url_for('check_in_start'))
    
    lots = lots_response.json()
    areas = sorted(list(set(lot['area'] for lot in lots)))
    return render_template('check_in_areas.html', areas=areas, license_plate=license_plate)

@app.route('/direct-check-in/<license_plate>/<area_name>')
@login_required
def check_in_lots(license_plate, area_name):
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    lots_response = requests.get(f"{FASTAPI_BASE_URL}/api/lots", headers=headers)
    if not lots_response.ok:
        flash(f"Could not retrieve lots for area {area_name}.", "danger")
        return redirect(url_for('check_in_areas', license_plate=license_plate))
        
    all_lots = lots_response.json()
    area_lots = [lot for lot in all_lots if lot['area'] == area_name]
    return render_template('check_in_lots.html', lots=area_lots, license_plate=license_plate, area_name=area_name)

@app.route('/direct-check-in/<license_plate>/lot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def check_in_slots(license_plate, lot_id):
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    
    # Fetch all users for the dropdown
    users_response = requests.get(f"{FASTAPI_BASE_URL}/api/users", headers=headers)
    users = users_response.json() if users_response.ok else []

    if request.method == 'POST':
        slot_id = request.form.get('slot_id')
        duration_hours = request.form.get('duration_hours')
        
        if not slot_id:
            flash("No slot selected.", "danger")
            return redirect(url_for('check_in_slots', license_plate=license_plate, lot_id=lot_id))

        payload = {"license_plate": license_plate, "slot_id": int(slot_id)}
        if duration_hours:
            payload['duration_hours'] = int(duration_hours)
        
        # Pass current user ID to link vehicle/fulfill reservation
        if g.user:
            payload['user_id'] = g.user['id']

        response = requests.post(f"{FASTAPI_BASE_URL}/api/check-in", json=payload, headers=headers)
        
        if response.ok:
            flash(f"Vehicle {license_plate} checked in successfully!", "success")
            return redirect(url_for('index'))
        else:
            print(f"DEBUG: Check-in API response status_code: {response.status_code}")
            print(f"DEBUG: Check-in API response text: {response.text}")
            try:
                detail = response.json().get('detail', 'Unknown error')
            except requests.exceptions.JSONDecodeError:
                detail = "An unexpected error occurred on the server."
            flash(f"Error checking in: {detail}", "danger")
            return redirect(url_for('check_in_slots', license_plate=license_plate, lot_id=lot_id))

    lot_response = requests.get(f"{FASTAPI_BASE_URL}/api/lots/{lot_id}", headers=headers)
    if not lot_response.ok:
        flash("Parking lot not found.", "danger")
        return redirect(url_for('check_in_start'))
    lot = lot_response.json()
    
    return render_template('check_in_slots.html', lot=lot, license_plate=license_plate, users=users)


# --- New Reservation Workflow ---

@app.route('/admin/reservations')
@login_required
def admin_reservations():
    if g.user.get('role') != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('index'))

    status = request.args.get('status') # active, completed, cancelled, or None (all)
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    user_query = request.args.get('user_query')
    license_plate = request.args.get('license_plate')
    area = request.args.get('area')

    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    
    params = {}
    if status: params['status'] = status
    if start_date: params['start_date'] = start_date
    if end_date: params['end_date'] = end_date
    if user_query: params['user_query'] = user_query
    if license_plate: params['license_plate'] = license_plate
    if area: params['area'] = area
    
    response = requests.get(f"{FASTAPI_BASE_URL}/api/reservations", headers=headers, params=params)
    reservations = []
    if response.ok:
        reservations = response.json()
    else:
        flash("Could not fetch reservations.", "warning")
    
    return render_template(
        'admin_reservations.html', 
        reservations=reservations, 
        status=status,
        start_date=start_date,
        end_date=end_date,
        user_query=user_query,
        license_plate=license_plate,
        area=area
    )

@app.route('/reservations', methods=['GET', 'POST'])
@login_required
def reservations_start():
    # Auto-select user if not admin
    if g.user and g.user.get('role') != 'admin':
        return redirect(url_for('reservations_areas', user_id=g.user['id']))

    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    if request.method == 'POST':
        user_id = request.form.get('user_id')
        if not user_id:
            flash("You must select a user.", "danger")
            return redirect(url_for('reservations_start'))
        return redirect(url_for('reservations_areas', user_id=user_id))

    users_response = requests.get(f"{FASTAPI_BASE_URL}/api/users", headers=headers)
    users = users_response.json() if users_response.ok else []
    return render_template('reservations_start.html', users=users)

@app.route('/vip-check-in', methods=['GET', 'POST'])
@login_required
def vip_check_in_page():
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    
    # Fetch users with active reservations
    users_with_reservations_response = requests.get(f"{FASTAPI_BASE_URL}/api/users/with_active_reservations", headers=headers)
    users_with_reservations = users_with_reservations_response.json() if users_with_reservations_response.ok else []

    # Fetch active reservations
    active_reservations_response = requests.get(f"{FASTAPI_BASE_URL}/api/reservations?status=active", headers=headers)
    active_reservations = active_reservations_response.json() if active_reservations_response.ok else []

    if request.method == 'POST':
        reservation_id = request.form.get('reservation_id')
        license_plate = request.form.get('license_plate')
        if not reservation_id:
            flash("Please select a reservation to check-in.", "danger")
            return redirect(url_for('vip_check_in_page'))
        
        # Call the backend API to fulfill the reservation
        payload = {"reservation_id": int(reservation_id), "license_plate": license_plate}
        response = requests.post(f"{FASTAPI_BASE_URL}/api/vip-check-in", json=payload, headers=headers)
        
        if response.ok:
            flash(f"Reservation {reservation_id} fulfilled and vehicle checked in!", "success")
            return redirect(url_for('index'))
        else:
            try:
                error_detail = response.json().get('detail', 'Unknown error')
            except requests.exceptions.JSONDecodeError:
                error_detail = response.text or 'Unknown error (non-JSON response)'
            flash(f"Error fulfilling reservation: {error_detail}", "danger")
            return redirect(url_for('vip_check_in_page'))

    return render_template('vip_check_in.html', 
                           users_with_reservations=users_with_reservations,
                           active_reservations=active_reservations)

@app.route('/reservations/user/<int:user_id>/areas')
@login_required
def reservations_areas(user_id):
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    lots_response = requests.get(f"{FASTAPI_BASE_URL}/api/lots", headers=headers)
    if not lots_response.ok:
        flash("Could not retrieve parking areas.", "danger")
        return redirect(url_for('reservations_start'))
    
    lots = lots_response.json()
    areas = sorted(list(set(lot['area'] for lot in lots)))
    return render_template('reservations_areas.html', areas=areas, user_id=user_id)

@app.route('/reservations/user/<int:user_id>/<area_name>')
@login_required
def reservations_lots(user_id, area_name):
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    lots_response = requests.get(f"{FASTAPI_BASE_URL}/api/lots", headers=headers)
    if not lots_response.ok:
        flash(f"Could not retrieve lots for area {area_name}.", "danger")
        return redirect(url_for('reservations_areas', user_id=user_id))
        
    all_lots = lots_response.json()
    area_lots = [lot for lot in all_lots if lot['area'] == area_name]
    return render_template('reservations_lots.html', lots=area_lots, user_id=user_id, area_name=area_name)

@app.route('/reservations/user/<int:user_id>/lot/<int:lot_id>', methods=['GET', 'POST'])
@login_required
def reservations_slots(user_id, lot_id):
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    
    # Fetch user's vehicles (We fetch all and filter because backend endpoint might not support filtering by user_id yet)
    # Or even better, let's see if we can get the user details which might include vehicles if we updated the schema, 
    # but to be safe, let's just fetch all vehicles and filter client-side or server-side here.
    # A better approach: GET /api/vehicles?user_id=... (not implemented).
    # Let's just fetch all vehicles for now and filter.
    vehicles_response = requests.get(f"{FASTAPI_BASE_URL}/api/vehicles", headers=headers)
    user_vehicles = []
    if vehicles_response.ok:
        all_vehicles = vehicles_response.json()
        user_vehicles = [v for v in all_vehicles if v.get('user_id') == user_id]

    if request.method == 'POST':
        slot_id = request.form.get('slot_id')
        expected_check_in_time_str = request.form.get('expected_check_in_time')
        expected_check_out_time_str = request.form.get('expected_check_out_time')
        license_plate = request.form.get('license_plate') # Get selected license plate

        if not slot_id:
            flash("No slot selected.", "danger")
            return redirect(url_for('reservations_slots', user_id=user_id, lot_id=lot_id))
        if not expected_check_in_time_str or not expected_check_out_time_str:
            flash("All reservation date and times are required.", "danger")
            return redirect(url_for('reservations_slots', user_id=user_id, lot_id=lot_id))

        # Ensure seconds are included for backend consistency
        def ensure_seconds(dt_str):
            if len(dt_str) == 16: # Format YYYY-MM-DD HH:MM
                return dt_str + ":00"
            return dt_str

        expected_check_in_datetime = ensure_seconds(expected_check_in_time_str)
        expected_check_out_datetime = ensure_seconds(expected_check_out_time_str)

        payload = {
            "user_id": user_id,
            "slot_id": int(slot_id),
            "expected_check_in_time": expected_check_in_datetime,
            "expected_check_out_time": expected_check_out_datetime,
            "license_plate": license_plate # Include license plate
        }
        response = requests.post(f"{FASTAPI_BASE_URL}/api/reservations", json=payload, headers=headers)
        
        if response.ok:
            flash(f"Slot reserved successfully for user {user_id}!", "success")
            return redirect(url_for('index'))
        else:
            flash(f"Error making reservation: {response.json().get('detail', 'Unknown error')}", "danger")
            return redirect(url_for('reservations_slots', user_id=user_id, lot_id=lot_id))

    lot_response = requests.get(f"{FASTAPI_BASE_URL}/api/lots/{lot_id}", headers=headers)
    if not lot_response.ok:
        flash("Parking lot not found.", "danger")
        return redirect(url_for('reservations_start'))
    lot = lot_response.json()
    
    return render_template('reservations_slots.html', lot=lot, user_id=user_id, user_vehicles=user_vehicles)


# --- Management Routes (Users) ---
@app.route('/users', methods=['GET', 'POST'])
@login_required
def users_management():
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    if request.method == 'POST':
        name = request.form['name']
        license_plate = request.form['license_plate']
        password = request.form['password']
        response = requests.post(f"{FASTAPI_BASE_URL}/api/auth/register", json={"name": name, "password": password, "license_plate": license_plate}, headers=headers)
        if response.ok:
            flash(f"User {name} created successfully!", "success")
        else:
            flash(f"Error creating user: {response.json().get('detail', 'Unknown error')}", "danger")
        return redirect(url_for('users_management'))
    
    name_filter = request.args.get('name')
    params = {'name': name_filter} if name_filter else {}
    response = requests.get(f"{FASTAPI_BASE_URL}/api/users", params=params, headers=headers)
    users = response.json() if response.ok else []
    return render_template('users.html', users=users, name_filter=name_filter, fastapi_base_url=FASTAPI_BASE_URL)

@app.route('/users/<int:user_id>/top-up', methods=['POST'])
@login_required
def top_up_user(user_id):
    if g.user.get('role') != 'admin':
         flash("Access denied.", "danger")
         return redirect(url_for('index'))
    
    amount = request.form.get('amount')
    if not amount:
         flash("Amount is required.", "danger")
         return redirect(url_for('users_management'))
    
    try:
        amount = float(amount)
    except ValueError:
         flash("Invalid amount.", "danger")
         return redirect(url_for('users_management'))

    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    payload = {"amount": amount}
    
    response = requests.post(f"{FASTAPI_BASE_URL}/api/admin/users/{user_id}/top-up", json=payload, headers=headers)
    
    if response.ok:
        flash(f"Successfully topped up user.", "success")
    else:
        flash(f"Error topping up user: {response.json().get('detail', 'Unknown error')}", "danger")
        
    return redirect(url_for('users_management'))

@app.route('/top-up/request', methods=['POST'])
@login_required
def request_top_up():
    amount = request.form.get('amount')
    payment_method = request.form.get('payment_method')

    if not amount or not payment_method:
         flash("Amount and Payment Method are required.", "danger")
         return redirect(url_for('user_dashboard'))
    
    try:
        amount = float(amount)
    except ValueError:
         flash("Invalid amount.", "danger")
         return redirect(url_for('user_dashboard'))

    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    payload = {"amount": amount, "payment_method": payment_method}
    
    response = requests.post(f"{FASTAPI_BASE_URL}/api/top-up/request", json=payload, headers=headers)
    
    if response.ok:
        flash("Top-up request submitted successfully! Please wait for admin approval.", "success")
    else:
        flash(f"Error submitting request: {response.json().get('detail', 'Unknown error')}", "danger")
        
    return redirect(url_for('user_dashboard'))

@app.route('/top-up/history')
@login_required
def user_top_up_history():
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    response = requests.get(f"{FASTAPI_BASE_URL}/api/users/me/top-up-history", headers=headers)
    
    history = []
    if response.ok:
        history = response.json()
    else:
        flash("Could not retrieve transaction history.", "danger")
        
    return render_template('user_top_up_history.html', history=history)

@app.route('/admin/top-up-requests')
@login_required
def admin_top_up_requests():
    if g.user.get('role') != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('index'))
        
    status_filter = request.args.get('status')
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    params = {'status': status_filter} if status_filter else {}
    
    response = requests.get(f"{FASTAPI_BASE_URL}/api/admin/top-up-requests", params=params, headers=headers)
    requests_list = response.json() if response.ok else []
    
    return render_template('admin_top_up_requests.html', requests=requests_list, status=status_filter)

@app.route('/admin/top-up-requests/<int:request_id>/<action>', methods=['POST'])
@login_required
def process_top_up_request(request_id, action):
    if g.user.get('role') != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('index'))
    
    if action not in ['approve', 'reject']:
        flash("Invalid action.", "danger")
        return redirect(url_for('admin_top_up_requests'))
        
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    response = requests.post(f"{FASTAPI_BASE_URL}/api/admin/top-up-requests/{request_id}/{action}", headers=headers)
    
    if response.ok:
        flash(f"Request {action}d successfully.", "success")
    else:
        flash(f"Error processing request: {response.json().get('detail', 'Unknown error')}", "danger")
        
    return redirect(url_for('admin_top_up_requests'))

# --- New Check-Out Page ---
@app.route('/check-out', methods=['GET', 'POST'])
@login_required
def check_out_page():
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    # Fetch only parked vehicles for the dropdown
    vehicles_response = requests.get(f"{FASTAPI_BASE_URL}/api/vehicles?status=parked", headers=headers)
    if vehicles_response.ok:
        all_parked_vehicles = vehicles_response.json()
        if g.user and g.user['role'] != 'admin':
            # Filter vehicles to show only those belonging to the current user
            vehicles = [v for v in all_parked_vehicles if v['user_id'] == g.user['id']]
        else:
            vehicles = all_parked_vehicles
    else:
        vehicles = []

    if request.method == 'POST':
        selected_vehicle_lp = request.form.get('selected_license_plate')
        typed_license_plate = request.form.get('typed_license_plate')

        license_plate = selected_vehicle_lp if selected_vehicle_lp else typed_license_plate
        
        if not license_plate:
            flash("License plate cannot be empty.", "danger")
            return render_template('check_out.html', vehicles=vehicles)

        # Call the backend check-out endpoint
        # The backend check-out endpoint now expects only license_plate
        payload = {"license_plate": license_plate} 
        response = requests.post(f"{FASTAPI_BASE_URL}/api/direct-check-out", json=payload, headers=headers)

        if response.ok:
            session_data = response.json()
            flash(f"Vehicle {license_plate} checked out. Total Fee: ৳{session_data.get('total_fee', 'N/A'):.2f}", "success")
            return redirect(url_for('check_out_page'))
        else:
            flash(f"Error checking out: {response.json().get('detail', 'Unknown error')}", "danger")
            return redirect(url_for('check_out_page'))

    return render_template('check_out.html', vehicles=vehicles)



@app.route('/feedback', methods=['GET', 'POST'])
@login_required
def feedback():
    if request.method == 'POST':
        message = request.form.get('message')
        if not message:
            flash("Message cannot be empty.", "danger")
            return redirect(url_for('feedback'))
        
        headers = {'Authorization': f'Bearer {session["access_token"]}'}
        payload = {"message": message}
        response = requests.post(f"{FASTAPI_BASE_URL}/api/feedback", json=payload, headers=headers)
        
        if response.ok:
            flash("Thank you for your feedback!", "success")
            return redirect(url_for('user_dashboard'))
        else:
            flash("Error submitting feedback. Please try again.", "danger")
            
    return render_template('feedback.html')

@app.route('/reports')
@login_required
def reports():
    if not (g.user and g.user.get('role') == 'admin'):
        flash("You are not authorized to view this page.", "danger")
        return redirect(url_for('index'))

    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    
    # Fetch data for all reports
    peak_hours_res = requests.get(f"{FASTAPI_BASE_URL}/api/reports/peak-hours", headers=headers)
    popular_spots_res = requests.get(f"{FASTAPI_BASE_URL}/api/reports/popular-spots", headers=headers)
    top_users_res = requests.get(f"{FASTAPI_BASE_URL}/api/reports/top-users", headers=headers)

    # Process data, with fallbacks for failed requests
    peak_hours = peak_hours_res.json() if peak_hours_res.ok else []
    popular_spots = popular_spots_res.json() if popular_spots_res.ok else []
    top_users = top_users_res.json() if top_users_res.ok else []

    return render_template('reports.html', 
                           peak_hours=peak_hours, 
                           popular_spots=popular_spots, 
                           top_users=top_users)

@app.route('/admin/analytics')
@login_required
def admin_analytics():
    if g.user.get('role') != 'admin':
        flash("Access denied.", "danger")
        return redirect(url_for('index'))
        
    headers = {'Authorization': f'Bearer {session["access_token"]}'}
    response = requests.get(f"{FASTAPI_BASE_URL}/api/analytics/all", headers=headers)
    
    data = {}
    if response.ok:
        data = response.json()
    else:
        flash("Could not retrieve analytics data.", "danger")
        
    return render_template('analytics.html', data=data)

if __name__ == '__main__':
    app.run(debug=True, port=5001)

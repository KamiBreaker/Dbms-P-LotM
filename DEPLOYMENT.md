# Deployment Guide for Parking Lot System

This project consists of two separate applications:
1. **Backend:** A FastAPI application (in `backend/` folder).
2. **Frontend:** A Flask application (in `frontend_flask/` folder).
3. **Database:** A MySQL database.

To share this online, you will need to deploy these three components. **Railway.app** or **Render.com** are recommended as they support all of these easily.

## Option 1: Deploying on Railway.app (Recommended)

Railway is easiest because it can detect the multiple folders.

### Step 1: Push your code to GitHub
1. Create a new repository on GitHub.
2. Push this entire `parking_man` folder to that repository.

### Step 2: Create a Project on Railway
1. Go to [Railway.app](https://railway.app/) and sign up/login.
2. Click **"New Project"** -> **"Deploy from GitHub repo"**.
3. Select your repository.
4. Railway might try to auto-detect. We need to configure it manually for two services.

### Step 3: Add the Database
1. In your Railway project canvas, click **"New"** -> **"Database"** -> **"MySQL"**.
2. Wait for it to deploy.
3. Click on the MySQL card -> "Connect" tab.
4. Copy the **"MySQL Connection URL"**.

### Step 4: Configure the Backend Service
1. In Railway, go to "Settings" for your repo's service.
2. **Root Directory:** Set this to `backend`.
3. **Build Command:** (Leave blank or default)
4. **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
5. **Variables:** Go to the "Variables" tab and add:
   - `DATABASE_URL`: Paste the MySQL URL you copied earlier.
   - `SECRET_KEY`: Set a long random string (e.g., `my_super_secret_backend_key_123`).
6. Wait for it to deploy. Once green, copy the **Public Domain** (e.g., `backend-production.up.railway.app`).

### Step 5: Configure the Frontend Service
1. In your Railway project canvas, click **"New"** -> **"GitHub Repo"** and select the **same repo again**. (This creates a second service for the frontend).
2. Go to "Settings" for this new service.
3. **Root Directory:** Set this to `frontend_flask`.
4. **Start Command:** `gunicorn app:app`
5. **Variables:** Go to the "Variables" tab and add:
   - `FASTAPI_BASE_URL`: Paste the **Backend Public Domain** you just copied (e.g., `https://backend-production.up.railway.app`). **Important:** Ensure it starts with `https://`.
   - `FLASK_SECRET_KEY`: Set a random string (e.g., `frontend_secret_key_999`).
6. Wait for deployment.

### Step 6: View your App
Click the link for the **Frontend** service. Your app is now live!

---

## Option 2: Deploying on Render.com

### Step 1: Database
1. Create a new **PostgreSQL** (Render doesn't have free MySQL, but the code uses SQLAlchemy so it *might* work with Postgres if you change the driver string, but stick to Railway for MySQL support if possible).
   * *Note: Since your code strictly imports `mysql-connector-python` and uses MySQL specific URLs, stick to Railway for the easiest path.*

## Troubleshooting
- **Database Error:** If the backend fails, check the `DATABASE_URL` in the variables. It must look like `mysql+mysqlconnector://user:pass@host:port/dbname`.
- **Connection Refused:** If frontend says it can't connect, check `FASTAPI_BASE_URL`. It must not have a trailing slash `/` at the end (unless your code handles it, usually safer without).

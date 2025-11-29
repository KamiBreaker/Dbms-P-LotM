import subprocess
import os
import sys
import time
import signal


#PP(Project path)
project_root = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.join(project_root, "backend")
frontend_dir = os.path.join(project_root, "frontend_flask")
pid_file = os.path.join(project_root, "smart_parking.pid")

# Define executables from virtual environments
backend_python = os.path.join(backend_dir, "venv/bin/python")
frontend_python = os.path.join(frontend_dir, "venv/bin/python")

def start_servers():
    """Starts the backend and frontend servers."""
    if os.path.exists(pid_file):
        print("Servers might already be running. If not, delete the 'smart_parking.pid' file and try again.")
        print("Or run 'python main.py stop' first.")
        return

    # Check if executables exist
    if not os.path.exists(backend_python):
        print(f"Error: Backend python executable not found at {backend_python}")
        print("Please ensure the backend virtual environment is set up correctly in 'backend/venv'.")
        return
        
    if not os.path.exists(frontend_python):
        print(f"Error: Frontend python executable not found at {frontend_python}")
        print("Please ensure the frontend virtual environment is set up correctly in 'frontend_flask/venv'.")
        return

    print("Starting FastAPI backend server in the background...")
    # Command for backend (more robustly calling the module)
    backend_command = [
        backend_python,
        "-m",
        "uvicorn",
        "main:app",
        "--reload",
        "--host", "0.0.0.0",
        "--port", "8000"
    ]
    # Use preexec_fn=os.setsid to create a new process group
    backend_process = subprocess.Popen(backend_command, cwd=backend_dir, preexec_fn=os.setsid)

    print("Waiting 10 seconds for the backend to initialize...")
    time.sleep(10)

    print("Starting Flask frontend server in the background...")
    # Command for frontend
    frontend_command = [frontend_python, "app.py"]
    frontend_process = subprocess.Popen(frontend_command, cwd=frontend_dir, preexec_fn=os.setsid)

    # Save PIDs of the process groups to a file
    with open(pid_file, "w") as f:
        f.write(f"{backend_process.pid}\n")
        f.write(f"{frontend_process.pid}\n")

    print("\nServers are starting up!")
    print("-----------------------------------------")
    print(f"Backend API Docs: http://127.0.0.1:8000/docs")
    print(f"Frontend UI:      http://127.0.0.1:5001")
    print("-----------------------------------------")
    print("To stop the servers, run: python main.py stop")
    subprocess.run(["open", "http://127.0.0.1:5001"])

def stop_servers():
    """Stops the backend and frontend servers."""
    if not os.path.exists(pid_file):
        print("PID file not found. Servers do not appear to be running (or were not started with 'main.py').")
        return

    print("Stopping servers...")
    with open(pid_file, "r") as f:
        pids = f.readlines()

    for pid_str in pids:
        pid = int(pid_str.strip())
        if pid:
            try:
                # Send SIGTERM to the entire process group
                os.killpg(pid, signal.SIGTERM)
                print(f"Sent SIGTERM to process group {pid}")
                time.sleep(2) # Give processes a chance to shut down gracefully

                # Check if the process group is still alive
                try:
                    os.killpg(pid, 0) # Check if process group exists
                    print(f"Process group {pid} is still alive. Sending SIGKILL...")
                    os.killpg(pid, signal.SIGKILL) # Forceful termination
                    print(f"Sent SIGKILL to process group {pid}")
                except ProcessLookupError:
                    print(f"Process group {pid} terminated.")

            except ProcessLookupError:
                print(f"Process group {pid} not found. It might have already stopped.")
            except Exception as e:
                print(f"Failed to stop process group {pid}: {e}")

    # Clean up the PID file
    os.remove(pid_file)
    print("Servers stopped.")

def main():
    """Main function to handle command-line arguments."""
    # Default to 'start' if no arguments are provided
    command = "start"
    if len(sys.argv) > 1:
        command = sys.argv[1]

    if command == "start":
        start_servers()
    elif command == "stop":
        stop_servers()
    else:
        print(f"Unknown command: {command}")
        print("Usage: python main.py [start|stop]")
        sys.exit(1)

if __name__ == "__main__":
    main()

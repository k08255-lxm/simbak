import os
from dotenv import load_dotenv

# Load environment variables from .env file if it exists (for development ease)
# Useful for setting FLASK_CONFIG, SECRET_KEY, DATABASE_URL etc. locally
dotenv_path = os.path.join(os.path.dirname(__file__), '.env')
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path)
    print("Loaded environment variables from .env file")

# Import the create_app factory function AFTER loading .env
# Assuming your factory is in 'app.py' or 'master/app.py' relative to project root
try:
    # If wsgi.py is in 'master/', import from '.' (current directory)
    from .app import create_app
except ImportError:
    # If wsgi.py is at the root, adjust import path
    # from master.app import create_app
    print("Error: Could not import create_app from .app. Adjust import path in wsgi.py if needed.")
    raise

# Get config name from environment variable or default to 'production'
# The installation script sets FLASK_ENV=production for the systemd service
config_name = os.getenv('FLASK_CONFIG', 'production')
print(f"Using configuration: {config_name}")


# Create the Flask app instance using the factory
# Pass the config name to the factory
app = create_app(config_name=config_name)


# This block is typically NOT used by Gunicorn/Waitress in production.
# It's for running the development server directly using `python wsgi.py`.
if __name__ == "__main__":
    print("---------------------------------------------------------------------")
    print(" WARNING: Running Flask development server directly via 'python wsgi.py'.")
    print("          This is NOT recommended for production.")
    print("          Use a WSGI server like Gunicorn or Waitress instead.")
    print("---------------------------------------------------------------------")
    # Run the app with Flask's built-in server (for debugging only)
    # The host '0.0.0.0' makes it accessible on your network IP
    # The port 5000 is a common default
    # debug=True enables debugger and auto-reloader (NEVER use in production)
    app.run(debug=(config_name == 'development'), host='0.0.0.0', port=5000)

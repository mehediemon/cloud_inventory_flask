#!/bin/sh

# Run the user creation script
python create_user.py

# Start the application with Gunicorn
exec gunicorn --bind 0.0.0.0:5002 app:app

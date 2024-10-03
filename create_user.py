from app import app, db, User
from werkzeug.security import generate_password_hash


def create_default_user():
    if User.query.count() == 0:  # Check if there are no users
        admin_user = User(username='admin', password=generate_password_hash(
            'adminpassword', method='pbkdf2:sha256'))
        db.session.add(admin_user)
        db.session.commit()
        print("Default admin user created.")
    else:
        print("Default admin user already exists.")


if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
        create_default_user()  # Create the default admin user if not already present

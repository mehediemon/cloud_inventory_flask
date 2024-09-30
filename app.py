from flask import Flask, render_template, request, redirect, url_for, flash, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from models import db, User, Account, Region, Service

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///accounts.db'
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/')
@login_required
def index():
    accounts = Account.query.all()
    providers = ['AWS', 'Azure', 'GCP']  # Hard-coded providers
    return render_template('index.html', accounts=accounts, providers=providers)


REGION_LIST = ['ap-south-1', 'ap-east-1', 'us-west-1', 'eu-central-1']  # Add more as needed

@app.route('/account/<int:account_id>')
@login_required
def account_detail(account_id):
    account = Account.query.get_or_404(account_id)
    return render_template('account.html', account=account, regions=REGION_LIST)


@app.route('/add_account', methods=['POST'])
@login_required
def add_account():
    name = request.form['name']
    account_id = request.form['account_id']
    provider_name = request.form['provider_name']
    email = request.form['email']  # Get email from the form
    new_account = Account(name=name, account_id=account_id, provider_name=provider_name, email=email)  # Save email
    db.session.add(new_account)
    db.session.commit()
    flash('Account added successfully!', 'success')
    return redirect(url_for('index'))



@app.route('/account/<int:account_id>/add_region', methods=['POST'])
@login_required
def add_region(account_id):
    name = request.form['region_name']
    
    # Check if the region already exists for the account
    existing_region = Region.query.filter_by(name=name, account_id=account_id).first()
    
    if existing_region:
        flash('This region already exists for this account.', 'danger')
    else:
        new_region = Region(name=name, account_id=account_id)
        db.session.add(new_region)
        db.session.commit()
        flash('Region added successfully!', 'success')

    return redirect(url_for('account_detail', account_id=account_id))


# At the top of your app.py
SERVICE_TYPES = ['EC2', 'SNS', 'SES', 'ELB', 'Lambda', 'WAF', 'RDS']  # Add more as needed

@app.route('/account/<int:account_id>/region/<int:region_id>')
@login_required
def region_detail(account_id, region_id):
    region = Region.query.get_or_404(region_id)
    return render_template('region.html', region=region, account_id=account_id, service_types=SERVICE_TYPES)

@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)
    if request.method == 'POST':
        service.name = request.form['service_name']
        service.type = request.form['service_type']
        service.user = request.form['service_user']
        service.credentials = request.form['credentials']
        service.status = request.form['status']
        db.session.commit()
        flash('Service updated successfully!', 'success')
        return redirect(url_for('region_detail', account_id=service.region.account_id, region_id=service.region.id))
    return render_template('edit_service.html', service=service, account_id=service.region.account_id, region_id=service.region.id, service_types=SERVICE_TYPES)


@app.route('/account/<int:account_id>/region/<int:region_id>/add_service', methods=['POST'])
@login_required
def add_service(account_id, region_id):
    name = request.form['service_name']
    service_type = request.form['service_type']  # This should match the name in the form
    user = request.form['service_user']
    credentials = request.form['credentials']
    
    # Create the new service, associating it with the account and region
    new_service = Service(
        name=name,
        type=service_type,
        user=user,
        region_id=region_id,
        account_id=account_id,  # Set the account_id
        credentials=credentials
    )
    
    db.session.add(new_service)
    db.session.commit()
    flash('Service added successfully!', 'success')
    return redirect(url_for('region_detail', account_id=account_id, region_id=region_id))



@app.route('/download/<int:account_id>')
@login_required
def download(account_id):
    account = Account.query.get(account_id)
    data = []
    for region in account.regions:
        for service in region.services:
            data.append({
                'Account Name': account.name,
                'Account ID': account.account_id,
                'Region': region.name,
                'Service': service.type,
                'Service Name': service.name,
                'User': service.user, 
                'Credentials': service.credentials,
            })
    
    df = pd.DataFrame(data)
    output_file = f"{account.name}_services.xlsx"
    df.to_excel(output_file, index=False)

    return send_file(output_file, as_attachment=True)

@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        user = User.query.get(current_user.id)
        user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('index'))
    return render_template('change_password.html')

@app.route('/search', methods=['GET'])
@login_required
def search():
    query = request.args.get('query')

    # Searching accounts by name or provider name
    accounts = Account.query.filter(
        (Account.name.ilike(f'%{query}%')) | 
        (Account.provider_name.ilike(f'%{query}%'))
    ).all()

    # Searching regions
    regions = Region.query.filter(Region.name.ilike(f'%{query}%')).all()

    # Searching services
    services = Service.query.filter(
        (Service.name.ilike(f'%{query}%')) 
        ).all()

    # Searching service types
    matched_services_by_type = Service.query.filter(Service.type.ilike(f'%{query}%')).all()

    return render_template(
        'search_results.html',
        accounts=accounts,
        regions=regions,
        services=services,
        matched_services_by_type=matched_services_by_type,
        query=query
    )



def create_default_user():
    if User.query.count() == 0:  # Check if there are no users
        admin_user = User(username='admin', password=generate_password_hash('adminpassword', method='pbkdf2:sha256'))
        db.session.add(admin_user)
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_default_user()  # Create the default admin user
    app.run(debug=True)

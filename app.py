import os
from flask import Flask, current_app, jsonify, render_template, request, redirect, url_for, flash, send_file, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
from datetime import timedelta, datetime, timezone
from models import Project, db, User, Account, Region, Service

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///accounts.db'
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Session timeout configuration
SESSION_TIMEOUT = 15  # minutes


@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


@app.before_request
def before_request():
    # Check if user is authenticated
    if current_user.is_authenticated:
        # Update last activity time
        if 'last_activity' in session:
            # Calculate the difference between now and last activity
            # Get the current time as aware datetime
            now = datetime.now(timezone.utc)
            last_activity = session['last_activity']
            # Convert last_activity to aware datetime
            last_activity = last_activity.replace(tzinfo=timezone.utc)
            if (now - last_activity) > timedelta(minutes=SESSION_TIMEOUT):
                # Log out the user if the session has timed out
                logout_user()
                flash('You have been logged out due to inactivity.', 'warning')
                return redirect(url_for('login'))
        # Update last activity
        # Store the current time as aware datetime
        session['last_activity'] = datetime.now(timezone.utc)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['last_activity'] = datetime.now(
                timezone.utc)  # Set last activity time
            return redirect(url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.pop('last_activity', None)  # Clear last activity
    return redirect(url_for('login'))


@app.route('/')
@login_required
def index():
    accounts = Account.query.order_by(Account.provider_name).all()
    services = Service.query.all()
    providers = ['AWS', 'Azure', 'GCP', 'OTHERS']  # Hard-coded providers

    projects_count = Service.query.filter_by(status='active').count()
    gcp_account_count = Account.query.filter_by(provider_name='GCP').count()
    aws_account_count = Account.query.filter_by(provider_name='AWS').count()
    azure_account_count = Account.query.filter_by(
        provider_name='Azure').count()
    other_account_count = len(accounts) - aws_account_count - \
        azure_account_count - gcp_account_count  # Calculate remaining

    return render_template('index.html', accounts=accounts, providers=providers,
                           aws_account_count=aws_account_count, azure_account_count=azure_account_count, gcp_account_count=gcp_account_count, projects_count=projects_count,
                           other_account_count=other_account_count)


# AWS Regions
AWS_REGION_LIST = [
    'us-east-1 (N. Virginia)',
    'us-east-2 (Ohio)',
    'us-west-1 (N. California)',
    'us-west-2 (Oregon)',
    'ap-northeast-1 (Tokyo)',
    'ap-northeast-2 (Seoul)',
    'ap-south-1 (Mumbai)',
    'ap-southeast-1 (Singapore)',
    'ap-southeast-2 (Sydney)',
    'ca-central-1 (Central Canada)',
    'eu-central-1 (Frankfurt)',
    'eu-west-1 (Ireland)',
    'eu-west-2 (London)',
    'eu-west-3 (Paris)',
    'eu-north-1 (Stockholm)',
    'me-south-1 (Bahrain)',
    'sa-east-1 (São Paulo)',
    'us-gov-east-1 (AWS GovCloud - East)',
    'us-gov-west-1 (AWS GovCloud - West)',
    'global',
]
# Azure Regions
AZURE_REGION_LIST = [
    'East US',
    'East US 2',
    'West US',
    'West US 2',
    'Central US',
    'North Central US',
    'South Central US',
    'Canada Central',
    'Canada East',
    'Brazil South',
    'UK South',
    'UK West',
    'France Central',
    'France South',
    'Germany West Central',
    'Germany North',
    'Norway East',
    'Norway West',
    'Sweden Central',
    'Sweden South',
    'UAE North',
    'UAE Central',
    'India Central',
    'India West',
    'India South',
    'Southeast Asia',
    'East Asia',
    'Japan East',
    'Japan West',
    'Korea Central',
    'Korea South',
    'Australia East',
    'Australia Southeast',
    'Australia Central',
    'Australia Central 2',
    'South Africa North',
    'South Africa West',
    'Switzerland North',
    'Switzerland West',
    'Poland Central',
    'Poland South',
    'Israel East',
    'Israel Central',
    'Hong Kong',
    'global',
]
# GCP Regions
GCP_REGION_LIST = [
    'us-central1 (Iowa)',
    'us-east1 (South Carolina)',
    'us-east4 (Northern Virginia)',
    'us-west1 (Oregon)',
    'us-west2 (Los Angeles)',
    'us-west3 (Salt Lake City)',
    'us-west4 (Washington)',
    'northamerica-northeast1 (Montreal)',
    'southamerica-east1 (São Paulo)',
    'europe-north1 (Finland)',
    'europe-west1 (Belgium)',
    'europe-west2 (London)',
    'europe-west3 (Frankfurt)',
    'europe-west4 (Netherlands)',
    'europe-west6 (Zurich)',
    'asia-east1 (Taiwan)',
    'asia-northeast1 (Tokyo)',
    'asia-northeast2 (Osaka)',
    'asia-northeast3 (Seoul)',
    'asia-south1 (Mumbai)',
    'asia-southeast1 (Singapore)',
    'asia-southeast2 (Jakarta)',
    'australia-southeast1 (Sydney)',
    'me-west1 (Qatar)',
    'global',
]
# OTHERS Regions
OTHERS_REGION_LIST = [

    'oracle us-ashburn-1 (Ashburn, US)',
    'oracle us-phoenix-1 (Phoenix, US)',
    'oracle eu-frankfurt-1 (Frankfurt, Germany)',
    'oracle ap-tokyo-1 (Tokyo, Japan)',
    'oracle ap-seoul-1 (Seoul, South Korea)',
    'oracle me-dubai-1 (Dubai, UAE)',
    'oracle ca-toronto-1 (Toronto, Canada)',
    'digitalocean nyc1 (New York City, US)',
    'digitalocean nyc2 (New York City, US)',
    'digitalocean nyc3 (New York City, US)',
    'digitalocean sgp1 (Singapore)',
    'digitalocean lon1 (London, UK)',
    'digitalocean ams2 (Amsterdam, Netherlands)',
    'digitalocean fra1 (Frankfurt, Germany)',
    'alibaba cn-hangzhou (Hangzhou, China)',
    'alibaba cn-beijing (Beijing, China)',
    'alibaba us-siliconvalley (Silicon Valley, US)',
    'alibaba ap-southeast-1 (Singapore)',
    'alibaba ap-northeast-1 (Tokyo, Japan)',
    'alibaba eu-central-1 (Frankfurt, Germany)',
    'alibaba me-south-1 (Bahrain)',
    'heroku us (United States)',
    'heroku eu (Europe)',
    'others',
]


@app.route('/account/<int:account_id>')
@login_required
def account_detail(account_id):
    account = Account.query.get_or_404(account_id)

    # Determine the region list based on the account provider
    if account.provider_name == 'AWS':
        regions = AWS_REGION_LIST
    elif account.provider_name == 'Azure':
        regions = AZURE_REGION_LIST
    elif account.provider_name == 'GCP':
        regions = GCP_REGION_LIST
    elif account.provider_name == 'OTHERS':
        regions = OTHERS_REGION_LIST
    else:
        regions = []  # Default to an empty list if provider is unknown

    return render_template('account.html', account=account, regions=regions)


@app.route('/add_account', methods=['POST'])
@login_required
def add_account():
    name = request.form['name']
    account_id = request.form['account_id']
    provider_name = request.form['provider_name']
    email = request.form['email']
    passwd = request.form['passwd']

    # Check for existing account with the same name and provider
    existing_account = Account.query.filter_by(
        name=name, provider_name=provider_name).first()
    if existing_account:
        flash('An account with the same name and provider already exists.', 'danger')
        return redirect(url_for('index'))

    # Check for existing account with the same email and provider (only if provider is not OTHERS)
    if provider_name != 'OTHERS':
        existing_email_provider = Account.query.filter_by(
            email=email, provider_name=provider_name).first()
        if existing_email_provider:
            flash('An account with the same email and provider already exists.', 'danger')
            return redirect(url_for('index'))

    # Check for existing account with the same email and provider
    existing_account_id = Account.query.filter_by(
        account_id=account_id, provider_name=provider_name).first()
    if existing_account_id:
        flash('An account id within the same provider already exists.', 'danger')
        return redirect(url_for('index'))

    # Create the new account
    new_account = Account(name=name, account_id=account_id,
                          provider_name=provider_name, email=email, passwd=passwd)
    db.session.add(new_account)
    db.session.commit()
    flash('Account added successfully!', 'success')
    return redirect(url_for('index'))


@app.route('/projects', methods=['GET', 'POST'])
@login_required
def manage_projects():
    if request.method == 'POST':
        project_name = request.form['project_name']
        
        existing_project = Project.query.filter_by(name=project_name).first()
        if existing_project:
            flash('Project already exists.', 'danger')
            return redirect(url_for('manage_projects'))

        new_project = Project(name=project_name)
        db.session.add(new_project)
        db.session.commit()
        flash('Project added successfully!', 'success')
        return redirect(url_for('manage_projects'))

    return render_template('projects.html')

@app.route('/api/projects', methods=['GET'])
@login_required
def api_projects():
    search_query = request.args.get('search', '').lower()
    if search_query:
        projects = Project.query.filter(Project.name.ilike(f'%{search_query}%')).all()
    else:
        projects = Project.query.all()
    
    project_list = [{
        'id': project.id,
        'name': project.name,
        'service_count': Service.query.filter_by(project_id=project.id).count()
    } for project in projects]

    return jsonify(project_list)

@app.route('/api/project/<int:project_id>', methods=['GET'])
@login_required
def api_project_services(project_id):
    project = Project.query.get_or_404(project_id)
    services = Service.query.filter_by(project_id=project.id).all()
    
    service_list = [{
        'id': service.id,
        'name': service.name,
        'type': service.type,
        'status': service.status
    } for service in services]

    return jsonify({
        'project_name': project.name,
        'services': service_list
    })


@app.route('/download_services/<int:project_id>')
@login_required
def download_services(project_id):
    project = Project.query.get_or_404(project_id)
    services = Service.query.filter_by(project_id=project.id).all()

    # Create a DataFrame
    df = pd.DataFrame([{
        'Service Name': service.name,
        'Service Type': service.type,
        'Status': service.status,
        'User': service.user,
        'Credentials': service.credentials
    } for service in services])

    # Save to an Excel file
    excel_file = f"{project.name}_services.xlsx"
    df.to_excel(excel_file, index=False)

    return send_file(excel_file, as_attachment=True)

@app.route('/account/<int:account_id>/add_region', methods=['POST'])
@login_required
def add_region(account_id):
    name = request.form['region_name']

    # Check if the region already exists for the account
    existing_region = Region.query.filter_by(
        name=name, account_id=account_id).first()

    if existing_region:
        flash('This region already exists for this account.', 'danger')
    else:
        new_region = Region(name=name, account_id=account_id)
        db.session.add(new_region)
        db.session.commit()
        flash('Region added successfully!', 'success')

    return redirect(url_for('account_detail', account_id=account_id))


AWS_SERVICE_TYPES = [
    'EC2',                 # Elastic Compute Cloud
    'SNS',                 # Simple Notification Service
    'SES',                 # Simple Email Service
    'ELB',                 # Elastic Load Balancing
    'Lambda',              # Serverless compute service
    'WAF',                 # Web Application Firewall
    'RDS',                 # Relational Database Service
    'S3',                  # Simple Storage Service
    'DynamoDB',            # NoSQL database service
    'CloudFront',          # Content Delivery Network (CDN)
    'SQS',                 # Simple Queue Service
    'API Gateway',         # API management service
    'CloudFormation',      # Infrastructure as Code
    'CloudWatch',          # Monitoring and observability
    'Elastic Beanstalk',   # PaaS for deploying applications
    'ECS',                 # Elastic Container Service
    'EKS',                 # Elastic Kubernetes Service
    'Route 53',            # DNS service
    'IAM',                 # Identity and Access Management
    'Cognito',             # User identity service
    'Elasticache',         # In-memory caching
    'Redshift',            # Data warehousing
    'Athena',              # Interactive query service
    'Glue',                # Data integration service
    'AppSync',             # GraphQL API service
    'CloudTrail',          # Governance and compliance
    'Step Functions',      # Orchestration service
    'RoboMaker',           # Robotics service
    'DMS',                 # Database Migration Service
    'Snowball',            # Data transport solution
    'EFS',                 # Elastic File System
    'FSx',                 # File system service
    'DocumentDB',          # Managed document database
    'AppStream',           # Application streaming service
    'QuickSight',          # Business analytics service
]
AZURE_SERVICE_TYPES = [
    'Virtual Machines',           # Compute service
    'App Services',               # Platform as a Service
    'Azure Functions',            # Serverless computing
    'Blob Storage',               # Object storage
    'SQL Database',               # Managed SQL database
    'Cosmos DB',                  # Globally distributed database service
    'Azure Kubernetes Service',   # Kubernetes orchestration
    'Azure DevOps',               # Development tools
    'Azure Logic Apps',           # Workflow automation
    'Azure CDN',                  # Content delivery network
    'Azure Virtual Network',      # Networking service
    'Azure Active Directory',     # Identity and access management
    'Azure Monitor',              # Monitoring service
    'Azure Cognitive Services',   # AI and machine learning
    'Azure Backup',               # Backup service
    'Azure Site Recovery',        # Disaster recovery
    'Azure Data Lake Storage',    # Big data storage
    'Azure Stream Analytics',     # Real-time analytics
    'Azure Event Hubs',          # Event streaming
    'Azure Firewall',             # Network security
    'Azure Batch',                # Job scheduling service
    'Azure SignalR Service',      # Real-time communication
]
GCP_SERVICE_TYPES = [
    'Compute Engine',               # Virtual machines
    'App Engine',                   # Platform as a Service
    'Cloud Functions',              # Serverless computing
    'Cloud Storage',                # Object storage
    'Cloud SQL',                   # Managed SQL database
    'BigQuery',                     # Data warehousing
    'Kubernetes Engine',            # Managed Kubernetes
    'Cloud Run',                    # Managed container service
    'Cloud Pub/Sub',                # Messaging service
    'Cloud Spanner',                # Globally distributed database service
    'Cloud Dataflow',               # Stream and batch data processing
    'Cloud Dataproc',               # Managed Spark and Hadoop
    'Cloud AI Platform',            # Machine learning platform
    'Cloud Functions',              # Event-driven serverless compute
    'Cloud Identity',               # Identity management
    'Cloud Monitoring',             # Monitoring and observability
    'Cloud Logging',                # Log management
    'Firebase',                     # Mobile and web app development
    'Cloud Firestore',              # NoSQL database
    'Cloud Endpoints',              # API management
    'Cloud CDN',                    # Content delivery network
    'Anthos',                       # Hybrid and multi-cloud management
]
OTHERS_SERVICE_TYPES = [
    'Oracle Cloud Infrastructure (OCI) Compute',
    'Oracle Cloud Object Storage',
    'Oracle Autonomous Database',
    'Oracle Functions (Serverless)',
    'Oracle NoSQL Database',
    'Oracle Cloud Infrastructure (OCI) Data Transfer',
    'Oracle Cloud Infrastructure Registry',
    'Oracle Cloud Infrastructure Streaming',
    'Oracle Cloud Kubernetes Engine',
    'Oracle Analytics Cloud',
    'DigitalOcean Droplets (Virtual Machines)',
    'DigitalOcean Spaces (Object Storage)',
    'DigitalOcean Managed Databases',
    'DigitalOcean Kubernetes',
    'DigitalOcean App Platform (Platform as a Service)',
    'DigitalOcean Load Balancers',
    'DigitalOcean Volumes (Block Storage)',
    'DigitalOcean Firewalls',
    'DigitalOcean Monitoring and Alerts',
    'DigitalOcean Database Clusters',
    'Alibaba Elastic Compute Service (ECS)',
    'Alibaba Object Storage Service (OSS)',
    'Alibaba ApsaraDB for RDS',
    'Alibaba Function Compute (Serverless)',
    'Alibaba Table Store (NoSQL)',
    'Alibaba CDN',
    'Alibaba Message Service (MNS)',
    'Alibaba Kubernetes Service (ACK)',
    'Alibaba Data Transmission Service (DTS)',
    'Alibaba API Gateway',
    'Heroku Dynos (Containers)',
    'Heroku Postgres',
    'Heroku Redis',
    'Heroku Connect',
    'Heroku Scheduler',
    'Heroku Pipelines',
    'Heroku Add-ons',
    'Heroku Data Clips',
    'Heroku Shield (Security)',
    'Heroku CI/CD',
    'others',
]


@app.route('/account/<int:account_id>/region/<int:region_id>')
@login_required
def region_detail(account_id, region_id):
    region = Region.query.get_or_404(region_id)

    # Determine the service list based on the account provider
    account = Account.query.get_or_404(account_id)
    if account.provider_name == 'AWS':
        services = AWS_SERVICE_TYPES
    elif account.provider_name == 'Azure':
        services = AZURE_SERVICE_TYPES
    elif account.provider_name == 'GCP':
        services = GCP_SERVICE_TYPES
    elif account.provider_name == 'OTHERS':
        services = OTHERS_SERVICE_TYPES
    else:
        services = []  # Default to an empty list if provider is unknown
    projects = Project.query.all()
    return render_template('region.html', region=region, account_id=account_id, services=services, projects=projects)


@app.route('/edit_account/<int:account_id>', methods=['GET', 'POST'])
@login_required
def edit_account(account_id):
    account = Account.query.get_or_404(account_id)
    providers = ['AWS', 'Azure', 'GCP', 'OTHERS']

    if request.method == 'POST':
        updated_name = request.form['name']
        # Ensure case-insensitive comparison
        updated_email = request.form['email'].lower()
        updated_passwd = request.form['passwd']

        # Check for existing accounts with the same name or email under the same provider
        conflicting_account = Account.query.filter(
            Account.provider_name == account.provider_name,
            (Account.name == updated_name) |
            (Account.email == updated_email),
            Account.id != account.id  # Exclude the current account
        ).first()

        if conflicting_account:
            flash(
                'An account with the same name or email already exists in this provider!', 'danger')
            return render_template('edit_account.html', account=account, providers=providers)

        # Update account details if no conflicts found
        account.name = updated_name
        account.email = updated_email
        account.passwd = updated_passwd

        db.session.commit()
        flash('Account updated successfully!', 'success')
        return redirect(url_for('index'))

    return render_template('edit_account.html', account=account, providers=providers)


@app.route('/edit_service/<int:service_id>', methods=['GET', 'POST'])
@login_required
def edit_service(service_id):
    service = Service.query.get_or_404(service_id)

    # Get the account associated with the service
    account = Account.query.get(service.account_id)
    projects = Project.query.all()

    # Determine the service list based on the account provider
    if account.provider_name == 'AWS':
        service_types = AWS_SERVICE_TYPES
    elif account.provider_name == 'Azure':
        service_types = AZURE_SERVICE_TYPES
    elif account.provider_name == 'GCP':
        service_types = GCP_SERVICE_TYPES
    elif account.provider_name == 'OTHERS':
        service_types = OTHERS_SERVICE_TYPES
    else:
        service_types = []  # Default to an empty list if provider is unknown

    if request.method == 'POST':
        service.project_id = request.form['project_id']
        service.name = request.form['service_name']
        service.type = request.form['service_type']
        service.user = request.form['service_user']
        service.credentials = request.form['credentials']
        service.status = request.form['status']
        db.session.commit()
        flash('Service updated successfully!', 'success')
        return redirect(url_for('region_detail', account_id=service.region.account_id, region_id=service.region.id))

    
    return render_template('edit_service.html', service=service, account_id=service.region.account_id, region_id=service.region.id, service_types=service_types, projects=projects)


@app.route('/account/<int:account_id>/region/<int:region_id>/add_service', methods=['GET', 'POST'])
@login_required
def add_service(account_id, region_id):
    if request.method == 'POST':
        name = request.form['service_name']
        service_type = request.form['service_type']
        user = request.form['service_user']
        credentials = request.form['credentials']
        status = request.form['status']
        
        # Get the selected project ID
        project_id = request.form.get('project_id')

        # Create the new service
        new_service = Service(
            name=name,
            type=service_type,
            user=user,
            region_id=region_id,
            account_id=account_id,
            status=status,
            credentials=credentials,
            project_id=project_id  # Associate the service with the selected project
        )

        db.session.add(new_service)
        db.session.commit()
        flash('Service added successfully!', 'success')
        return redirect(url_for('region_detail', account_id=account_id, region_id=region_id))

    # Fetch projects to display in the form
    projects = Project.query.all()
    return render_template('add_service.html', account_id=account_id, region_id=region_id, projects=projects)


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
                'Project': service.project.name,
                'User': service.user,
                'Credentials': service.credentials,
                'status': service.status,
            })

    df = pd.DataFrame(data)
    output_file_name = f"{account.name}_services.xlsx"
    output_dir = os.path.join(current_app.root_path, 'downloads')
    output_file = os.path.join(output_dir, output_file_name)
    os.makedirs(output_dir, exist_ok=True)
    df.to_excel(output_file, index=False)

    return send_file(output_file, as_attachment=True)


@app.route('/download_all')
@login_required
def download_all():
    accounts = Account.query.order_by(Account.provider_name).all()
    data = []

    for account in accounts:
        for region in account.regions:
            for service in region.services:
                data.append({
                    'Account Name': account.name,
                    'Account ID': account.account_id,
                    'Provider Name': account.provider_name,
                    'Region': region.name,
                    'Service Type': service.type,
                    'Service Name': service.name,
                    'Project Name': service.project.name,
                    'User': service.user,
                    'Credentials': service.credentials,
                    'status': service.status,
                })

    df = pd.DataFrame(data)
    output_dir = os.path.join(current_app.root_path, 'downloads')
    output_file = os.path.join(output_dir, "all_accounts_services.xlsx")
    os.makedirs(output_dir, exist_ok=True)
    df.to_excel(output_file, index=False)

    return send_file(output_file, as_attachment=True)


@app.route('/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    if request.method == 'POST':
        new_password = request.form['new_password']
        user = User.query.get(current_user.id)
        user.password = generate_password_hash(
            new_password, method='pbkdf2:sha256')
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

    projects = Project.query.filter(Project.name.ilike(f'%{query}%')).all()

    # Searching services
    services = Service.query.filter(
        (Service.name.ilike(f'%{query}%')) 
    ).all()
    # Searching service types
    matched_services_by_type = Service.query.filter(
        Service.type.ilike(f'%{query}%')).all()

    return render_template(
        'search_results.html',
        accounts=accounts,
        regions=regions,
        services=services,
        projects=projects,
        matched_services_by_type=matched_services_by_type,
        query=query
    )


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

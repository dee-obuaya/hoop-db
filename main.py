import os
import sys
import pandas as pd
from cryptography.fernet import Fernet
from flask import Flask, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_cors import CORS
from flask_login import login_user, LoginManager, login_required, current_user, logout_user
from flask_migrate import Migrate
from functools import wraps
from werkzeug.utils import secure_filename
from models import CPE, BandwidthPlan, Basestation, ChangeImplementationTracker, Connection, Customer, CustomerPRTG, CustomerPassword, LinkActivationTracker, Partner, Radio, Server, ServicePlan, ServiceType, User, Vlan, db
from forms import BandwidthPlanForm, BasestationForm, CPEForm, CSVUploadForm, ChangeImplementationTrackerForm, ConnectionForm, CustomerForm, CustomerPRTGForm, CustomerPasswordForm, LinkActivationTrackerForm, PartnerForm, RadioForm, ServerForm, ServicePlanForm, ServiceTypeForm, UserForm, VlanForm

app = Flask(__name__)
app.config.from_object('config')
db.init_app(app)
migrate = Migrate(app, db)
Bootstrap(app)
CORS(app)

login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


def write_key():
    key = Fernet.generate_key()

    with open("key.key", "wb") as key_file:
        key_file.write(key)


def load_key():
    return open("key.key", "rb").read()


def admin_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If users privileges is not Admin then return abort with 403 error
        if current_user.privileges != 'Admin':
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


def admin_and_ip(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        allowed_privileges = ['Admin', 'Default']
        allowed_departments = ['IP']
        user_privileges = current_user.privileges
        user_department = current_user.department

        # If users privileges is not Admin or in IP or NOC then return abort with 403 error
        if user_department not in allowed_departments or user_privileges not in allowed_privileges:
            abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


def admin_noc_ip(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        allowed_privileges = ['Admin', 'Default']
        allowed_departments = ['IP', 'NOC']
        user_privileges = current_user.privileges
        user_department = current_user.department

        # If users privileges is not Admin or in IP or NOC then return abort with 403 error
        if user_department not in allowed_departments or user_privileges not in allowed_privileges:
            abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


def ip_only(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If users department is not IP then return abort with 403 error
        if current_user.department != 'IP':
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


def ip_and_others(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        allowed_privileges = ['Admin', 'Default']
        allowed_departments = ['IP', 'Service Management', 'Technical Support']
        user_privileges = current_user.privileges
        user_department = current_user.department

        # If users privileges is not Admin or in IP or NOC then return abort with 403 error
        if user_department not in allowed_departments or user_privileges not in allowed_privileges:
            abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        key = load_key()
        f = Fernet(key)

        user = User.query.filter_by(username=username).one_or_none()

        if not user:
            flash(f'Username {username} does not exist.')
            return redirect(url_for('login'))
        elif f.decrypt(user.password).decode() != password:
            flash(f'Incorrect password.')
            return redirect(url_for('login'))
        else:
            login_user(user)
            if current_user.privileges == 'Default':
                return redirect(url_for('index'))
            else:
                return redirect(url_for('admin_index'))
    return render_template('forms/login.html')


@app.route('/logout')
def logout():
    logout_user()

    return redirect(url_for('login'))


@app.route('/home')
@login_required
def index():

    return render_template('pages/index.html', current_user=current_user)


@app.route('/admin-home')
@login_required
@admin_only
def admin_index():

    return render_template('pages/adminindex.html', current_user=current_user)

# --------------------------------------------- USERS ------------------------------------------->


@app.route('/users')
@login_required
@admin_only
def get_users():

    return render_template('pages/admin/users.html', current_user=current_user)


@app.route('/users/data')
@login_required
@admin_only
def get_users_data():
    query = User.query
    key = load_key()
    f = Fernet(key)

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            User.username.ilike(f'%{search}%'),
            User.username.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [{
            'username': user.username,
            'password': f.decrypt(user.password).decode(),
            'departement': user.department,
            'privileges': user.privileges
        } for user in query],
        'total': total,
    }

    return response


@app.route('/users/new', methods=['GET', 'POST'])
@login_required
@admin_only
def add_user():
    form = UserForm()

    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).one_or_none():
            flash(f'User {form.username.data} already exists!')
            return redirect(url_for('add_user'))
        else:
            key = load_key()
            f = Fernet(key)
            try:
                user = User(
                    username=form.username.data,
                    password=f.encrypt(form.password.data.encode()),
                    department=form.department.data,
                    privileges=form.privileges.data
                )
                user.insert()
                flash(f'User {form.username.data} created.')
                return redirect(url_for('get_users'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'User {form.username.data} could not be created. Try again.')
                return redirect(url_for('add_user'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/user.html', form=form, current_user=current_user)


@app.route('/users/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_users_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['username', 'password', 'department', 'privileges']
        csvData = pd.read_csv(file_path, names=col_names, header=None)
        # Loop through the Rows
        key = load_key()
        f = Fernet(key)
        error = False
        for i, row in csvData.iterrows():
            try:
                user = User(
                    username=row['username'],
                    password=f.encrypt(row['password'].encode()),
                    department=row['department'],
                    privileges=row['privileges']
                )
                user.insert()
            except:
                error = True
                db.session.rollback()
                print(sys.exc_info())

        db.session.close()
        if error:
            flash(
                'Something went wrong, could not add all users. Please check your file and try again.')
        else:
            flash('Users uploaded successfully.')
        return redirect(url_for('get_users'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/user.html', is_upload=True, form=upload_form, current_user=current_user)


@app.route('/users/<username>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_only
def update_user(username):
    user = User.query.filter_by(username=username).one_or_none()

    key = load_key()
    f = Fernet(key)

    edit_form = UserForm(
        username=user.username,
        password=f.decrypt(user.password).decode(),
        department=user.department,
        privileges=user.privileges
    )

    if edit_form.validate_on_submit():
        try:
            user.username = edit_form.username.data
            user.password = f.encrypt(edit_form.password.data.encode())
            user.department = edit_form.department.data
            user.privileges = edit_form.privileges.data

            user.update()
            flash(f'User {edit_form.username.data} updated successfully.')
            return redirect(url_for('get_users'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Something went wrong, could not update user {edit_form.username.data}')
            return redirect(url_for('update_user', username=user.username))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/user.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/users/<username>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_only
def delete_user(username):
    user = User.query.filter_by(username=username).one_or_none()

    try:
        user.delete()
        flash(f'User {user.username} deleted.')
    except:
        db.session.rollback()
        print(sys.exc_info())
        flash(f'User {user.username} not deleted. Try again.')
    finally:
        return redirect(url_for('get_users'))


# --------------------------------------------- PARTNERS ------------------------------------------->
@app.route('/partners')
@login_required
@admin_and_ip
def get_partners():

    return render_template('pages/admin/partners.html', current_user=current_user)


@app.route('/partners/data')
@login_required
@admin_and_ip
def get_partners_data():
    query = Partner.query
    # formatted_selection = [user.format() for user in selection.all()]

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            Partner.partner_id.ilike(f'%{search}%'),
            Partner.partner_id.contains(search),
            Partner.partner_name.ilike(f'%{search}%'),
            Partner.partner_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [partner.to_dict() for partner in query],
        'total': total,
    }

    return response


@app.route('/partners/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_partner():
    form = PartnerForm()

    if form.validate_on_submit():
        if Partner.query.filter_by(partner_id=form.partner_id.data).one_or_none():
            flash(f'User {form.partner_id.data} already exists!')
            return redirect(url_for('add_partner'))
        else:
            try:
                partner = Partner(
                    partner_id=form.partner_id.data,
                    partner_name=form.partner_name.data,
                    partner_contact=form.partner_contact.data,
                    partner_address=form.partner_address.data
                )
                partner.insert()
                flash(f'Partner {form.partner_name.data} created.')
                return redirect(url_for('get_partners'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Partner {form.partner_name.data} could not be created. Try again.')
                return redirect(url_for('add_partner'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/partner.html', form=form, current_user=current_user)


@app.route('/partners/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_partners_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['partner_id', 'partner_name',
                     'partner_contact', 'partner_address']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                partner = Partner(
                    partner_id=row['partner_id'],
                    partner_name=row['partner_name'],
                    partner_contact=row['partner_contact'],
                    partner_address=row['partner_address']
                )
                partner.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Something went wrong, could not upload partners.')
        else:
            flash('Partners uploaded successfully.')
        return redirect(url_for('get_partners'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/partner.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/partners/<partner_id>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_partner(partner_id):
    partner = Partner.query.filter_by(partner_id=partner_id).one_or_none()

    edit_form = PartnerForm(
        partner_id=partner.partner_id,
        partner_name=partner.partner_name,
        partner_contact=partner.partner_contact,
        partner_address=partner.partner_address
    )

    if edit_form.validate_on_submit():
        try:
            partner.partner_name = edit_form.partner_name.data
            partner.partner_contact = edit_form.partner_contact.data
            partner.partner_address = edit_form.partner_address.data

            partner.update()
            flash(f'Partner {edit_form.partner_id.data} updated successfully.')
            return redirect(url_for('get_partners'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Partner {edit_form.partner_id.data} could not be updated successfully. Try again.')
            return redirect(url_for('update_partner', partner_id=edit_form.partner_id.data))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/partner.html', form=edit_form, is_edit=True, current_user=current_user)


@app.route('/partners/<partner_id>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_partner(partner_id):
    partner = Partner.query.filter_by(partner_id=partner_id).one_or_none()

    try:
        partner.delete()
        flash(f'Deleted partner.')
        return redirect(url_for('get_partners'))
    except:
        db.session.rollback()
        print(sys.exc_info())
        flash(f'Could not delete partner. Try again.')
        return redirect(url_for('get_partners'))
    finally:
        db.session.close()


# --------------------------------------------- BASESTATIONS ------------------------------------------->
@app.route('/basestations')
@login_required
def get_basestations():

    return render_template('pages/admin/basestations.html', current_user=current_user)


@app.route('/basestations/data')
@login_required
def get_basestations_data():
    query = Basestation.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            Basestation.basestation_id.ilike(f'%{search}%'),
            Basestation.basestation_id.contains(search),
            Basestation.basestation_name.ilike(f'%{search}%'),
            Basestation.basestation_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [basestation.to_dict() for basestation in query],
        'total': total,
    }

    return response


@app.route('/basestations/new', methods=['GET', 'POST'])
@login_required
@admin_noc_ip
def add_basestation():
    form = BasestationForm()

    if form.validate_on_submit():
        if Basestation.query.filter_by(basestation_id=form.basestation_id.data).one_or_none():
            flash(f'Basestation {form.basestation_id.data} already exists!')
            return redirect(url_for('add_basestation'))
        else:
            try:
                basestation = Basestation(
                    basestation_id=form.basestation_id.data,
                    basestation_name=form.basestation_name.data,
                    basestation_location=form.basestation_location.data,
                    basestation_contact=form.basestation_contact.data
                )
                basestation.insert()
                flash(f'Basestation {form.basestation_name.data} created.')
                return redirect(url_for('get_basestations'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Basestation {form.basestation_name.data} could not be created. Try again.')
                return redirect(url_for('add_basestation'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/basestation.html', form=form, current_user=current_user)


@app.route('/basestations/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_basestations_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['basestation_name', 'basestation_id',
                     'basestation_location', 'basestation_contact']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                basestation = Basestation(
                    basestation_name=row['basestation_name'],
                    basestation_id=row['basestation_id'],
                    basestation_location=row['basestation_location'],
                    basestation_contact=row['basestation_contact']
                )
                basestation.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload basestations.')
        else:
            flash('Basestations uploaded successfulyy.')
        return redirect(url_for('get_basestations'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/basestation.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/basestations/<basestation_id>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_basestation(basestation_id):
    basestation = Basestation.query.filter_by(
        basestation_id=basestation_id).one_or_none()

    edit_form = BasestationForm(
        basestation_id=basestation.basestation_id,
        basestation_name=basestation.basestation_name,
        basestation_location=basestation.basestation_location,
        basestation_contact=basestation.basestation_contact
    )

    if edit_form.validate_on_submit():
        try:
            basestation.baestation_name = edit_form.basestation_name.data
            basestation.basestation_location = edit_form.basestation_location.data
            basestation.bsestation_contact = edit_form.basestation_contact.data

            basestation.update()
            flash(f'Basestation {edit_form.basestation_id.data} updated.')
            return redirect(url_for('get_basestations'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Basestation {edit_form.basestation_id.data} not updated. Try again.')
            return redirect(url_for('update_basestation', basestation_id=edit_form.basestation_id.data))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/basestation.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/basestations/<basestation_id>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_basestation(basestation_id):
    basestation = Basestation.query.filter_by(
        basestation_id=basestation_id).one_or_none()

    try:
        basestation.delete()
        flash(f'Deleted basestation.')
        return redirect(url_for('get_basestations'))
    except:
        db.session.rollback()
        print(sys.exc_info())
        flash(f'Could not delete basestation. Try again.')
        return redirect(url_for('get_basestations'))
    finally:
        db.session.close()


# --------------------------------------------- SERVERS ------------------------------------------->
@app.route('/servers')
@login_required
@admin_and_ip
def get_servers():
    selection = Server.query.order_by(Server.server_name)
    formatted_selection = [server.format() for server in selection.all()]

    return render_template('pages/admin/servers.html', response=formatted_selection, current_user=current_user)


@app.route('/servers/data')
@login_required
def get_servers_data():
    query = Server.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            Server.server_name.ilike(f'%{search}%'),
            Server.server_name.contains(search),
            Server.server_ip.ilike(f'%{search}%'),
            Server.server_ip.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [server.to_dict() for server in query],
        'total': total,
    }

    return response


@app.route('/servers/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_server():
    form = ServerForm()

    if form.validate_on_submit():
        if Server.query.filter_by(server_name=form.server_name.data).one_or_none():
            flash(f'Server {form.server_name.data} already exists!')
            return redirect(url_for('add_server'))
        elif Server.query.filter_by(server_ip=form.server_ip.data).one_or_none():
            flash(f'Server {form.server_ip.data} already exists!')
            return redirect(url_for('add_server'))
        else:
            try:
                server = Server(
                    server_name=form.server_name.data,
                    server_ip=form.server_ip.data,
                    server_location=form.server_location.data
                )
                server.insert()
                flash(f'Server {form.server_name.data} created.')
                return redirect(url_for('get_servers'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Server {form.server_name.data} could not be created. Try again.')
                return redirect(url_for('add_server'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/server.html', form=form, current_user=current_user)


@app.route('/servers/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_servers_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['server_name', 'server_ip', 'server_location']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                server = Server(
                    server_name=row['server_name'],
                    server_ip=row['server_ip'],
                    server_location=row['server_location']
                )
                server.insert()
            except:
                db.session.rollback()
                print(sys.exc_info())
                error = True

        db.session.close()
        if error:
            flash('Could not upload servers.')
        else:
            flash('Uploaded servers successfully.')
        return redirect(url_for('get_servers'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/server.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/servers/<server_name>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_server(server_name):
    server = Server.query.filter_by(server_name=server_name).one_or_none()

    edit_form = ServerForm(
        server_name=server.server_name,
        server_ip=server.server_ip,
        server_location=server.server_location
    )

    if edit_form.validate_on_submit():
        try:
            server.server_name = edit_form.server_name.data
            server.server_ip = edit_form.server_ip.data
            server.server_location = edit_form.server_location.data

            server.update()
            flash(f'Updated server {edit_form.server_name.data}.')
            return redirect(url_for('get_servers'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Server {edit_form.server_name.data} not updated. Try again.')
            return redirect(url_for('update_server', server_name=server.server_name))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/server.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/servers/<server_name>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_server(server_name):
    server = Server.query.filter_by(server_name=server_name).one_or_none()

    try:
        server.delete()
        flash(f'Deleted server {server.server_name}.')
    except:
        db.session.rollback()
        flash(f'Could not delete server{server.server_name}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_servers'))


# --------------------------------------------- VLANS ------------------------------------------->
@app.route('/vlans')
@login_required
@admin_and_ip
def get_vlans():
    selection = Vlan.query.order_by(Vlan.vlan_id)
    formatted_selection = [vlan.format() for vlan in selection.all()]

    return render_template('pages/admin/vlans.html', response=formatted_selection, current_user=current_user)


@app.route('/vlans/data')
@login_required
def get_vlans_data():
    query = Vlan.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            Vlan.basestation_id.ilike(f'%{search}%'),
            Vlan.basestation_id.contains(search),
            Basestation.basestation_name.ilike(f'%{search}%'),
            Vlan.basestation_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [vlan.to_dict() for vlan in query],
        'total': total,
    }

    return response


@app.route('/vlans/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_vlan():
    form = VlanForm()

    if form.validate_on_submit():
        if Vlan.query.filter_by(customer_assigned=form.customer_assigned.data).one_or_none():
            flash(
                f'A vlan has already been assigned to {form.customer_assigned.data}.')
            return redirect(url_for('add_vlan'))
        else:
            try:
                vlan = Vlan(
                    vlan_id=form.vlan_id.data,
                    customer_assigned=form.customer_assigned.data,
                )
                vlan.insert()
                flash(
                    f'Vlan {form.vlan_id.data} assigned to customer {form.customer_assigned.data}.')
                return redirect(url_for('get_vlans'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Vlan {form.vlan_id.data} could not be assigned to customer {form.customer_assigned.data}. Try again.')
                return redirect(url_for('add_vlan'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/vlan.html', form=form, current_user=current_user)


@app.route('/vlans/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_vlans_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['vlan_id', 'customer_assigned']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                vlan = Vlan(
                    vlan_id=row['vlan_id'],
                    customer_assigned=row['customer_assigned']
                )
                vlan.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload all vlans')
        else:
            flash('Uploaded vlans successfully.')
        return redirect(url_for('get_vlans'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/vlan.html', is_upload=True, form=upload_form, current_user=current_user)


@app.route('/vlans/<vlan_id>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_vlan(vlan_id):
    vlan = Vlan.query.filter_by(vlan_id=vlan_id).one_or_none()

    edit_form = VlanForm(
        vlan_id=vlan.vlan_id,
        customer_assigned=vlan.customer_assigned,
    )

    if edit_form.validate_on_submit():
        try:
            vlan.vlan_id = edit_form.vlan_id.data
            vlan.customer_assigned = edit_form.customer_assigned.data

            vlan.update()
            flash(f'Updated vlan {edit_form.vlan_id.data}.')
            return redirect(url_for('get_vlans'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Vlan {edit_form.vlan_id.data} not updated. Try again.')
            return redirect(url_for('update_vlan', vlan_id=vlan.vlan_id))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/vlan.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/vlans/<vlan_id>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_vlan(vlan_id):
    vlan = Vlan.query.filter_by(vlan_id=vlan_id).one_or_none()

    try:
        vlan.delete()
        flash(f'Deleted vlan {vlan.vlan_id}.')
    except:
        db.session.rollback()
        flash(f'Could not delete vlan{vlan.vlan_id}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_vlans'))


# --------------------------------------------- CONNECTIONS ------------------------------------------->
@app.route('/connections')
@login_required
@admin_and_ip
def get_connections():
    selection = Connection.query.order_by(Connection.conn_name)
    formatted_selection = [conn.format() for conn in selection.all()]

    return render_template('pages/admin/connectiontypes.html', response=formatted_selection, current_user=current_user)


@app.route('/connections/data')
@login_required
def get_connections_data():
    query = Connection.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            Connection.conn_name.ilike(f'%{search}%'),
            Connection.conn_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [conn.to_dict() for conn in query],
        'total': total,
    }

    return response


@app.route('/connections/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_connection():
    form = ConnectionForm()

    if form.validate_on_submit():
        if Connection.query.filter_by(conn_name=form.conn_name.data).one_or_none():
            flash(f'Connection type {form.conn_name.data} already exists.')
            return redirect(url_for('add_connection'))
        else:
            try:
                conn = Connection(
                    conn_name=form.conn_name.data,
                    conn_desc=form.conn_desc.data,
                )
                conn.insert()
                flash(f'Connection type {form.conn_name.data} created.')
                return redirect(url_for('get_connections'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Connection type {form.conn_name.data} could not be created. Try again.')
                return redirect(url_for('add_connection'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/connectiontype.html', form=form, current_user=current_user)


@app.route('/connections/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_connections_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['conn_name', 'conn_desc']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                conn = Connection(
                    conn_name=row['conn_name'],
                    conn_desc=row['conn_desc']
                )
                conn.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Ccould not upload connections')
        else:
            flash('Uploaded connections successfully.')
        return redirect(url_for('get_connections'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/connectiontype.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/connections/<conn_name>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_connection(conn_name):
    conn = Connection.query.filter_by(conn_name=conn_name).one_or_none()

    edit_form = ConnectionForm(
        conn_name=conn.conn_name,
        conn_desc=conn.conn_desc,
    )

    if edit_form.validate_on_submit():
        try:
            conn.conn_name = edit_form.conn_name.data
            conn.conn_desc = edit_form.conn_desc.data

            conn.update()
            flash(f'Updated connection {edit_form.conn_name.data}.')
            return redirect(url_for('get_connections'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Connection {edit_form.conn_name.data} not updated. Try again.')
            return redirect(url_for('update_connection', conn_name=conn.conn_name))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/connectiontype.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/connections/<conn_name>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_connection(conn_name):
    conn = Connection.query.filter_by(conn_name=conn_name).one_or_none()

    try:
        conn.delete()
        flash(f'Deleted connection {conn.conn_name}.')
    except:
        db.session.rollback()
        flash(f'Could not delete connection{conn.conn_name}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_connections'))


# --------------------------------------------- RADIOS ------------------------------------------->
@app.route('/radios')
@login_required
@admin_and_ip
def get_radios():
    selection = Radio.query.order_by(Radio.radio_name)
    formatted_selection = [radio.format() for radio in selection.all()]

    return render_template('pages/admin/radiotypes.html', response=formatted_selection, current_user=current_user)


@app.route('/radios/data')
@login_required
def get_radios_data():
    query = Radio.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            Radio.radio_name.ilike(f'%{search}%'),
            Radio.radio_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [radio.to_dict() for radio in query],
        'total': total,
    }

    return response


@app.route('/radios/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_radio():
    form = RadioForm()

    if form.validate_on_submit():
        if Radio.query.filter_by(radio_name=form.radio_name.data).one_or_none():
            flash(f'Radio type {form.radio_name.data} already exists.')
            return redirect(url_for('add_radio'))
        else:
            try:
                conn = Radio(
                    radio_name=form.radio_name.data,
                )
                conn.insert()
                flash(f'Radio type {form.radio_name.data} created.')
                return redirect(url_for('get_radios'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Radio type {form.radio_name.data} could not be created. Try again.')
                return redirect(url_for('add_radio'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/radiotype.html', form=form, current_user=current_user)


@app.route('/radios/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_radios_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['radio_name']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                radio = Radio(
                    radio_name=row['radio_name']
                )
                radio.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload radios.')
        else:
            flash('Radios uploaded successfully.')

        return redirect(url_for('get_radios'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/radiotype.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/radios/<radio_name>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_radio(radio_name):
    radio = Radio.query.filter_by(radio_name=radio_name).one_or_none()

    edit_form = RadioForm(
        radio_name=radio.radio_name,
    )

    if edit_form.validate_on_submit():
        try:
            radio.radio_name = edit_form.radio_name.data

            radio.update()
            flash(f'Updated radio {edit_form.radio_name.data}.')
            return redirect(url_for('get_radios'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(f'Radio {edit_form.radio_name.data} not updated. Try again.')
            return redirect(url_for('update_radio', radio_id=radio.id))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/radiotype.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/radios/<radio_name>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_radio(radio_name):
    radio = Radio.query.filter_by(radio_name=radio_name).one_or_none()

    try:
        radio.delete()
        flash(f'Deleted radio {radio.radio_name}.')
    except:
        db.session.rollback()
        flash(f'Could not delete radio {radio.radio_name}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_radios'))


# --------------------------------------------- SERVICE TYPES ------------------------------------------->
@app.route('/service-types')
@login_required
@admin_and_ip
def get_service_types():
    selection = ServiceType.query.order_by(ServiceType.service_name)
    formatted_selection = [service.format() for service in selection.all()]

    return render_template('pages/admin/servicetypes.html', response=formatted_selection, current_user=current_user)


@app.route('/service-types/data')
@login_required
def get_service_types_data():
    query = ServiceType.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            ServiceType.service_name.ilike(f'%{search}%'),
            ServiceType.service_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [service.to_dict() for service in query],
        'total': total,
    }

    return response


@app.route('/service-types/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_service_type():
    form = ServiceTypeForm()

    if form.validate_on_submit():
        if ServiceType.query.filter_by(service_name=form.service_name.data).one_or_none():
            flash(f'Service type {form.service_name.data} already exists.')
            return redirect(url_for('add_service_type'))
        else:
            try:
                service = ServiceType(
                    service_name=form.service_name.data,
                    service_desc=form.service_desc.data
                )
                service.insert()
                flash(f'Service type {form.service_name.data} created.')
                return redirect(url_for('get_service_types'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Service type {form.service_name.data} could not be created. Try again.')
                return redirect(url_for('add_service_type'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/servicetype.html', form=form, current_user=current_user)


@app.route('/service-types/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_service_types_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['service_name', 'service_desc']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                service = ServiceType(
                    service_name=row['service_name'],
                    service_desc=row['service_desc']
                )
                service.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload services.')
        else:
            flash('Uploaded services successfully.')

        return redirect(url_for('get_service_types'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/servicetype.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/service-types/<service_name>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_service_type(service_name):
    service = ServiceType.query.filter_by(service_name=service_name).one_or_none()

    edit_form = ServiceTypeForm(
        service_name=service.service_name,
        service_desc=service.service_desc
    )

    if edit_form.validate_on_submit():
        try:
            service.service_name = edit_form.service_name.data
            service.service_desc = edit_form.service_desc.data

            service.update()
            flash(f'Updated service type {edit_form.service_name.data}.')
            return redirect(url_for('get_service_types'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Service type {edit_form.service_name.data} not updated. Try again.')
            return redirect(url_for('update_service_type', service_name=service.service_name))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/servicetype.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/service-types/<service_name>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_service_type(service_name):
    service = ServiceType.query.filter_by(service_name=service_name).one_or_none()

    try:
        service.delete()
        flash(f'Deleted service {service.service_name}.')
    except:
        db.session.rollback()
        flash(f'Could not delete service {service.service_name}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_service_types'))


# --------------------------------------------- SERVICE PLANS ------------------------------------------->
@app.route('/service-plans')
@login_required
@admin_and_ip
def get_service_plans():
    selection = ServicePlan.query.order_by(ServicePlan.service_plan)
    formatted_selection = [plan.format() for plan in selection.all()]

    return render_template('pages/admin/serviceplans.html', response=formatted_selection, current_user=current_user)


@app.route('/service-plans/data')
@login_required
def get_service_plans_data():
    query = ServicePlan.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            ServicePlan.servcie_plan.ilike(f'%{search}%'),
            ServicePlan.servcie_plan.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [plan.to_dict() for plan in query],
        'total': total,
    }

    return response


@app.route('/service-plans/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_service_plan():
    form = ServicePlanForm()

    if form.validate_on_submit():
        if ServicePlan.query.filter_by(service_plan=form.service_plan.data).one_or_none():
            flash(f'Service plan {form.service_plan.data} already exists.')
            return redirect(url_for('add_service_plan'))
        else:
            try:
                plan = ServicePlan(
                    service_plan=form.service_plan.data,
                    service_desc=form.service_desc.data
                )
                plan.insert()
                flash(f'Service plan {form.service_plan.data} created.')
                return redirect(url_for('get_service_plans'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Service plan {form.service_plan.data} could not be created. Try again.')
                return redirect(url_for('add_service_plan'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/serviceplan.html', form=form, current_user=current_user)


@app.route('/service-plans/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_service_plans_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['service_plan', 'service_desc']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                plan = ServicePlan(
                    service_plan=row['service_plan'],
                    service_desc=row['service_desc']
                )
                plan.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload service plans')
        else:
            flash('Uploaded service plans successfully.')

        return redirect(url_for('get_service_plans'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/serviceplan.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/service-plans/<service_plan>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_service_plan(service_plan):
    plan = ServicePlan.query.filter_by(service_plan=service_plan).one_or_none()

    edit_form = ServicePlanForm(
        service_plan=plan.service_plan,
        service_desc=plan.service_desc
    )

    if edit_form.validate_on_submit():
        try:
            plan.service_plan = edit_form.service_plan.data
            plan.service_desc = edit_form.service_desc.data

            plan.update()
            flash(f'Updated service plan {edit_form.service_plan.data}.')
            return redirect(url_for('get_service_plans'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Service plan {edit_form.service_plan.data} not updated. Try again.')
            return redirect(url_for('update_service_plan', service_plan=plan.service_plan))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/serviceplan.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/service-plans/<service_plan>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_service_plan(service_plan):
    plan = ServicePlan.query.filter_by(service_plan).one_or_none()

    try:
        plan.delete()
        flash(f'Deleted service plan {plan.service_plan}.')
    except:
        db.session.rollback()
        flash(f'Could not delete service plan{plan.service_plan}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_service_plans'))


# --------------------------------------------- BANDWIDTH PLANS ------------------------------------------->


@app.route('/bandwidth-plans')
@login_required
@admin_and_ip
def get_bandwidth_plans():
    selection = BandwidthPlan.query.order_by(BandwidthPlan.bandwidth_name)
    formatted_selection = [bandwidth.format() for bandwidth in selection.all()]

    return render_template('pages/admin/bandwidths.html', response=formatted_selection, current_user=current_user)


@app.route('/bandwidth-plans/data')
@login_required
def get_bandwidth_plans_data():
    query = BandwidthPlan.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            BandwidthPlan.bandwidth_name.ilike(f'%{search}%'),
            BandwidthPlan.bandwidth_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [bandwidth.to_dict() for bandwidth in query],
        'total': total,
    }

    return response


@app.route('/bandwidth-plans/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_bandwidth_plan():
    form = BandwidthPlanForm()

    if form.validate_on_submit():
        if BandwidthPlan.query.filter_by(bandwidth_name=form.bandwidth_name.data).one_or_none():
            flash(f'Bandwidth plan {form.bandwidth_name.data} already exists.')
            return redirect(url_for('add_bandwidth_plan'))
        else:
            try:
                bandwidth = BandwidthPlan(
                    bandwidth_name=form.bandwidth_name.data
                )
                bandwidth.insert()
                flash(f'Bandwidth plan {form.bandwidth_name.data} created.')
                return redirect(url_for('get_bandwidth_plans'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Bandwidth plan {form.bandwidth_name.data} could not be created. Try again.')
                return redirect(url_for('add_bandwidth_plan'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/bandwidth.html', form=form, current_user=current_user)


@app.route('/bandwidth-plans/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_bandwidth_plans_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['bandwidth_name']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = True
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                bandwidth = BandwidthPlan(
                    bandwidth_name=row['bandwidth_name']
                )
                bandwidth.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload bandwidth plans.')
        else:
            flash('Uploaded bandwidth plans successfully.')

        return redirect(url_for('get_bandwidth_plans'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/bandwidth.html', is_upload=True, form=upload_form, current_user=current_user)


@app.route('/bandwidth-plans/<bandwidth_name>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_bandwidth_plan(bandwidth_name):
    bandwidth = BandwidthPlan.query.filter_by(bandwidth_name=bandwidth_name).one_or_none()

    edit_form = BandwidthPlanForm(
        id=bandwidth.id,
        bandwidth_name=bandwidth.bandwidth_name
    )

    if edit_form.validate_on_submit():
        try:
            bandwidth.bandwidth_name = edit_form.bandwidth_name.data

            bandwidth.update()
            flash(f'Updated bandwidth plan {edit_form.bandwidth_name.data}.')
            return redirect(url_for('get_bandwidth_plans'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Bandwidth plan {edit_form.bandwidth_name.data} not updated. Try again.')
            return redirect(url_for('update_bandwidth_plan', bandwidth_name=bandwidth.bandwidth_name))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/bandwidth.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/bandwidth-plans/<bandwidth_name>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_bandwidth_plan(bandwidth_name):
    bandwidth = BandwidthPlan.query.filter_by(bandwidth_name=bandwidth_name).one_or_none()

    try:
        bandwidth.delete()
        flash(f'Deleted bandwidth plan {bandwidth.bandwidth_name}.')
    except:
        db.session.rollback()
        flash(
            f'Could not delete bandwidth plan{bandwidth.bandwidth_name}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_bandwidth_plans'))


# --------------------------------------------- CPES ------------------------------------------->
@app.route('/cpes')
@login_required
@admin_and_ip
def get_cpes():
    selection = CPE.query.order_by(CPE.cpe_name)
    formatted_selection = [cpe.format() for cpe in selection.all()]

    return render_template('pages/admin/cpetypes.html', response=formatted_selection, current_user=current_user)


@app.route('/cpes/data')
@login_required
def get_cpes_data():
    query = CPE.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            CPE.cpe_name.ilike(f'%{search}%'),
            CPE.cpe_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [cpe.to_dict() for cpe in query],
        'total': total,
    }

    return response


@app.route('/cpes/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_cpe():
    form = CPEForm()

    if form.validate_on_submit():
        if CPE.query.filter_by(cpe_name=form.cpe_name.data).one_or_none():
            flash(f'CPE type {form.cpe_name.data} already exists.')
            return redirect(url_for('add_cpe'))
        else:
            try:
                cpe = CPE(
                    cpe_name=form.cpe_name.data
                )
                cpe.insert()
                flash(f'CPE type {form.cpe_name.data} created.')
                return redirect(url_for('get_cpes'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'CPE type {form.cpe_name.data} could not be created. Try again.')
                return redirect(url_for('add_cpe'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/cpetype.html', form=form, current_user=current_user)


@app.route('/cpes/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_cpes_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['cpe_name']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                cpe = CPE(
                    cpe_name=row['cpe_name']
                )
                cpe.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload cpe types.')
        else:
            flash('Uploaded cpe types successfully.')

        return redirect(url_for('get_cpes'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/cpetype.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/cpes/<cpe_name>/edit', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_cpe(cpe_name):
    cpe = CPE.query.filter_by(cpe_name=cpe_name).one_or_none()

    edit_form = CPEForm(
        cpe_name=cpe.cpe_name
    )

    if edit_form.validate_on_submit():
        try:
            cpe.cpe_name = edit_form.cpe_name.data

            cpe.update()
            flash(f'Updated cpe type {edit_form.cpe_name.data}.')
            return redirect(url_for('get_cpes'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'CPE type {edit_form.cpe_name.data} not updated. Try again.')
            return redirect(url_for('update_cpe', cpe_name=cpe.cpe_name))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/cpetype.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/cpes/<cpe_name>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_cpe(cpe_name):
    cpe = CPE.query.filter_by(cpe_name=cpe_name).one_or_none()

    try:
        cpe.delete()
        flash(f'Deleted cpe type {cpe.cpe_name}.')
    except:
        db.session.rollback()
        flash(f'Could not delete cpe type {cpe.cpe_name}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_cpes'))


# --------------------------------------------- CUSTOMERS ------------------------------------------->
@app.route('/customers')
@login_required
def get_customers():

    return render_template('pages/ip/customers.html', current_user=current_user)


@app.route('/customers/data')
@login_required
def get_customers_data():
    query = Customer.query
    key = load_key()
    f = Fernet(key)

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            Customer.customer_code.ilike(f'%{search}%'),
            Customer.customer_code.contains(search),
            Customer.customer_name.ilike(f'%{search}%'),
            Customer.customer_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [{
            'customer_name': customer.customer_name,
            'customer_code': customer.customer_code,
            'customer_status': customer.customer_status,
            'customer_server': customer.customer_server,
            'customer_conn_type': customer.customer_conn_type,
            'customer_location': customer.customer_location,
            'customer_partner': customer.customer_partner,
            'customer_basestation_location': customer.customer_basestation_location,
            'customer_basestation_id': customer.customer_basestation_id,
            'customer_sector': customer.customer_sector,
            'customer_switch': customer.customer_switch,
            'customer_management_vlan': customer.customer_management_vlan,
            'customer_traffic_vlan': customer.customer_traffic_vlan,
            'customer_subnet': customer.customer_subnet,
            'customer_mu_ip': customer.customer_mu_ip,
            'customer_su_ip': customer.customer_su_ip,
            'customer_ssid': customer.customer_ssid,
            'customer_channel_width': customer.customer_channel_width,
            'customer_frequency': customer.customer_frequency,
            'customer_mu_mac_id': customer.customer_mu_mac_id,
            'customer_su_mac_id': customer.customer_su_mac_id,
            'customer_rssi_ccq_airmax': customer.customer_rssi_ccq_airmax,
            'customer_radio_type': customer.customer_radio_type,
            'customer_cpe': customer.customer_cpe,
            'customer_provider_edge_router': customer.customer_provider_edge_router,
            'customer_wan_ip': customer.customer_wan_ip,
            'customer_wan_subnet': customer.customer_wan_subnet,
            'customer_wan_gateway': customer.customer_wan_gateway,
            'customer_wan_routing_protocol': customer.customer_wan_routing_protocol,
            'customer_ip': customer.customer_ip,
            'customer_subnet_mask': customer.customer_subnet_mask,
            'customer_gateway': customer.customer_gateway,
            'customer_service_type': customer.customer_service_type,
            'customer_service_plan': customer.customer_service_plan,
            'customer_bandwidth_plan': customer.customer_bandwidth_plan,
            'customer_wifi_ssid': customer.customer_wifi_ssid,
            'customer_wifi_password': f.decrypt(customer.customer_wifi_password).decode(),
            'customer_installation_date': customer.customer_installation_date,
            'customer_activation_date': customer.customer_activation_date,
            'customer_installation_engineer': customer.customer_installation_engineer,
            'customer_contact_person': customer.customer_contact_person,
            'customer_phone_number': customer.customer_phone_number,
            'customer_email': customer.customer_email,
            'customer_physical_address': customer.customer_physical_address
        } for customer in query],
        'total': total,
    }

    return response


@app.route('/customers/new', methods=['GET', 'POST'])
@login_required
@ip_only
def add_customer():
    form = CustomerForm()

    form.customer_server.choices = [(server.server_name, server.server_name)
                                    for server in Server.query.order_by('server_name')]
    form.customer_conn_type.choices = [
        (conn.conn_name, conn.conn_name) for conn in Connection.query.order_by('conn_name')]
    form.customer_partner.choices = [(partner.partner_name, partner.partner_name)
                                     for partner in Partner.query.order_by('partner_name')]
    form.customer_basestation_id.choices = [(bts.basestation_id, bts.basestation_name)
                                    for bts in Basestation.query.order_by('basestation_name')]
    form.customer_radio_type.choices = [
        (radio.radio_name, radio.radio_name) for radio in Radio.query.order_by('radio_name')]
    form.customer_cpe.choices = [(cpe.cpe_name, cpe.cpe_name)
                                 for cpe in CPE.query.order_by('cpe_name')]
    form.customer_service_type.choices = [
        (service.service_name, service.service_name) for service in ServiceType.query.order_by('service_name')]
    form.customer_service_plan.choices = [
        (plan.service_plan, plan.service_plan) for plan in ServicePlan.query.order_by('service_plan')]
    form.customer_bandwidth_plan.choices = [(bandwidth.bandwidth_name, bandwidth.bandwidth_name)
                                            for bandwidth in BandwidthPlan.query.order_by('bandwidth_name')]

    if form.validate_on_submit():
        if Customer.query.filter_by(customer_code=form.customer_code.data).one_or_none():
            flash(f'Customer {form.customer_code.data} already exists.')
            return redirect(url_for('add_customer'))
        else:
            try:
                customer = Customer(
                    customer_name=form.customer_name.data,
                    customer_code=form.customer_code.data,
                    customer_status=form.customer_status.data,
                    customer_server=form.customer_server.data,
                    customer_conn_type=form.customer_conn_type.data,
                    customer_location=form.customer_location.data,
                    customer_partner=form.customer_partner.data,
                    customer_basestation_location=form.customer_basestation_location.data,
                    customer_basestation_id=form.customer_basestation_id.data,
                    customer_sector=form.customer_sector.data,
                    customer_switch=form.customer_switch.data,
                    customer_management_vlan=form.customer_management_vlan.data,
                    customer_traffic_vlan=form.customer_traffic_vlan.data,
                    customer_subnet=form.customer_subnet.data,
                    customer_mu_ip=form.customer_mu_ip.data,
                    customer_su_ip=form.customer_su_ip.data,
                    customer_ssid=form.customer_ssid.data,
                    customer_channel_width=form.customer_channel_width.data,
                    customer_frequency=form.customer_frequency.data,
                    customer_mu_mac_id=form.customer_mu_mac_id.data,
                    customer_su_mac_id=form.customer_su_mac_id.data,
                    customer_rssi_ccq_airmax=form.customer_rssi_ccq_airmax.data,
                    customer_radio_type=form.customer_radio_type.data,
                    customer_cpe=form.customer_cpe.data,
                    customer_provider_edge_router=form.customer_provider_edge_router.data,
                    customer_wan_ip=form.customer_wan_ip.data,
                    customer_wan_subnet=form.customer_wan_subnet.data,
                    customer_wan_gateway=form.customer_wan_gateway.data,
                    customer_wan_routing_protocol=form.customer_wan_routing_protocol.data,
                    customer_ip=form.customer_ip.data,
                    customer_subnet_mask=form.customer_subnet_mask.data,
                    customer_gateway=form.customer_gateway.data,
                    customer_service_type=form.customer_service_type.data,
                    customer_service_plan=form.customer_service_plan.data,
                    customer_bandwidth_plan=form.customer_bandwidth_plan.data,
                    customer_wifi_ssid=form.customer_wifi_ssid.data,
                    customer_wifi_password=form.customer_wifi_password.data,
                    customer_installation_date=form.customer_installation_date.data,
                    customer_activation_date=form.customer_activation_date.data,
                    customer_installation_engineer=form.customer_installation_engineer.data,
                    customer_contact_person=form.customer_contact_person.data,
                    customer_phone_number=form.customer_phone_number.data,
                    customer_email=form.customer_email.data,
                    customer_physical_address=form.customer_physical_address.data,
                )
                customer.insert()
                flash(
                    f'Customer {form.customer_name.data} - {form.customer_code} created.')
                return redirect(url_for('get_customers'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Customer {form.customer_name.data} - {form.customer_code} could not be created. Try again.')
                return redirect(url_for('add_customer'))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/customer.html', form=form, current_user=current_user)


@app.route('/customers/upload', methods=['POST', 'GET'])
@login_required
@admin_only
def upload_customers_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = [
            'customer_name',
            'customer_code',
            'customer_status',
            'customer_server',
            'customer_conn_type',
            'customer_partner',
            'customer_location',
            'customer_basestation_location',
            'customer_basestation_id',
            'customer_sector',
            'customer_switch',
            'customer_management_vlan',
            'customer_traffic_vlan',
            'customer_subnet',
            'customer_mu_ip',
            'customer_su_ip',
            'customer_ssid',
            'customer_channel_width',
            'customer_frequency',
            'customer_mu_mac_id',
            'customer_su_mac_id',
            'customer_rssi_ccq_airmax',
            'customer_radio_type',
            'customer_cpe',
            'customer_provider_edge_router',
            'customer_wan_ip',
            'customer_wan_subnet',
            'customer_wan_gateway',
            'customer_wan_routing_protocol',
            'customer_ip',
            'customer_subnet_mask',
            'customer_gateway',
            'customer_service_type',
            'customer_service_plan',
            'customer_bandwidth_plan',
            'customer_wifi_ssid',
            'customer_wifi_password',
            'customer_installation_date',
            'customer_activation_date',
            'customer_installation_engineer',
            'customer_contact_person',
            'customer_phone_number',
            'customer_email',
            'customer_physical_address'
        ]
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        key = load_key()
        f = Fernet(key)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                customer = Customer(
                    customer_name=row['customer_name'],
                    customer_code=row['customer_code'],
                    customer_status=row['customer_status'],
                    customer_server=row['customer_server'],
                    customer_conn_type=row['customer_conn_type'],
                    customer_partner=row['customer_partner'],
                    customer_location=row['customer_location'],
                    customer_basestation_location=row['customer_basestation_location'],
                    customer_basestation_id=row['customer_basestation_id'],
                    customer_sector=row['customer_sector'],
                    customer_switch=row['customer_switch'],
                    customer_management_vlan=row['customer_management_vlan'],
                    customer_traffic_vlan=row['customer_traffic_vlan'],
                    customer_subnet=row['customer_subnet'],
                    customer_mu_ip=row['customer_mu_ip'],
                    customer_su_ip=row['customer_su_ip'],
                    customer_ssid=row['customer_ssid'],
                    customer_channel_width=row['customer_channel_width'],
                    customer_frequency=row['customer_frequency'],
                    customer_mu_mac_id=row['customer_mu_mac_id'],
                    customer_su_mac_id=row['customer_su_mac_id'],
                    customer_rssi_ccq_airmax=row['customer_rssi_ccq_airmax'],
                    customer_radio_type=row['customer_radio_type'],
                    customer_cpe=row['customer_cpe'],
                    customer_provider_edge_router=row['customer_provider_edge_router'],
                    customer_wan_ip=row['customer_wan_ip'],
                    customer_wan_subnet=row['customer_wan_subnet'],
                    customer_wan_gateway=row['customer_wan_gateway'],
                    customer_wan_routing_protocol=row['customer_wan_routing_protocol'],
                    customer_ip=row['customer_ip'],
                    customer_subnet_mask=row['customer_subnet_mask'],
                    customer_gateway=row['customer_gateway'],
                    customer_service_type=row['customer_service_type'],
                    customer_service_plan=row['customer_service_plan'],
                    customer_bandwidth_plan=row['customer_bandwidth_plan'],
                    customer_wifi_ssid=row['customer_wifi_ssid'],
                    customer_wifi_password=f.encrypt(
                        row['customer_wifi_password'].encode()),
                    customer_installation_date=row['customer_installation_date'],
                    customer_activation_date=row['customer_activation_date'],
                    customer_installation_engineer=row['customer_installation_engineer'],
                    customer_contact_person=row['customer_contact_person'],
                    customer_phone_number=row['customer_phone_number'],
                    customer_email=row['customer_email'],
                    customer_physical_address=row['customer_physical_address']
                )
                customer.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload customers.')
        else:
            flash('Uploaded customers successfully.')

        return redirect(url_for('get_customers'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/customer.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/customers/<customer_code>/edit', methods=['POST', 'PATCH', 'GET'])
@login_required
@ip_only
def update_customer(customer_code):
    customer = Customer.query.filter_by(
        customer_code=customer_code).one_or_none()

    key = load_key()
    f = Fernet(key)

    edit_form = CustomerForm(
        customer_name=customer.customer_name,
        customer_code=customer.customer_code,
        customer_status=customer.customer_status,
        customer_server=customer.customer_server,
        customer_conn_type=customer.customer_conn_type,
        customer_location=customer.customer_location,
        customer_partner=customer.customer_partner,
        customer_basestation_location=customer.customer_basestation_location,
        customer_basestation_id=customer.customer_basestation_id,
        customer_sector=customer.customer_sector,
        customer_switch=customer.customer_switch,
        customer_management_vlan=customer.customer_management_vlan,
        customer_traffic_vlan=customer.customer_traffic_vlan,
        customer_subnet=customer.customer_subnet,
        customer_mu_ip=customer.customer_mu_ip,
        customer_su_ip=customer.customer_su_ip,
        customer_ssid=customer.customer_ssid,
        customer_channel_width=customer.customer_channel_width,
        customer_frequency=customer.customer_frequency,
        customer_mu_mac_id=customer.customer_mu_mac_id,
        customer_su_mac_id=customer.customer_su_mac_id,
        customer_rssi_ccq_airmax=customer.customer_rssi_ccq_airmax,
        customer_radio_type=customer.customer_radio_type,
        customer_cpe=customer.customer_cpe,
        customer_provider_edge_router=customer.customer_provider_edge_router,
        customer_wan_ip=customer.customer_wan_ip,
        customer_wan_subnet=customer.customer_wan_subnet,
        customer_wan_gateway=customer.customer_wan_gateway,
        customer_wan_routing_protocol=customer.customer_wan_routing_protocol,
        customer_ip=customer.customer_ip,
        customer_subnet_mask=customer.customer_subnet_mask,
        customer_gateway=customer.customer_gateway,
        customer_service_type=customer.customer_service_type,
        customer_service_plan=customer.customer_service_plan,
        customer_bandwidth_plan=customer.customer_bandwidth_plan,
        customer_wifi_ssid=customer.customer_wifi_ssid,
        customer_wifi_password=f.decrypt(
            customer.customer_wifi_password).decode(),
        customer_installation_date=customer.customer_installation_date,
        customer_activation_date=customer.customer_activation_date,
        customer_installation_engineer=customer.customer_installation_engineer,
        customer_contact_person=customer.customer_contact_person,
        customer_phone_number=customer.customer_phone_number,
        customer_email=customer.customer_email,
        customer_physical_address=customer.customer_physical_address,
    )

    edit_form.customer_server.choices = [(server.server_name, server.server_name)
                                         for server in Server.query.order_by('server_name')]
    edit_form.customer_conn_type.choices = [
        (conn.conn_name, conn.conn_name) for conn in Connection.query.order_by('conn_name')]
    edit_form.customer_partner.choices = [(partner.partner_name, partner.partner_name)
                                          for partner in Partner.query.order_by('partner_name')]
                                          
    edit_form.customer_basestation_id.choices = [(bts.basestation_id, bts.basestation_name) for bts in Basestation.query.order_by('basestation_name')]

    edit_form.customer_radio_type.choices = [
        (radio.radio_name, radio.radio_name) for radio in Radio.query.order_by('radio_name')]
    edit_form.customer_cpe.choices = [(cpe.cpe_name, cpe.cpe_name)
                                      for cpe in CPE.query.order_by('cpe_name')]
    edit_form.customer_service_type.choices = [
        (service.service_name, service.service_name) for service in ServiceType.query.order_by('service_name')]
    edit_form.customer_service_plan.choices = [
        (plan.service_plan, plan.service_plan) for plan in ServicePlan.query.order_by('service_plan')]
    edit_form.customer_bandwidth_plan.choices = [(bandwidth.bandwidth_name, bandwidth.bandwidth_name)
                                                 for bandwidth in BandwidthPlan.query.order_by('bandwidth_name')]

    if edit_form.validate_on_submit():
        try:
            customer.customer_name = edit_form.customer_name.data
            customer.customer_code = edit_form.customer_code.data
            customer.customer_status = edit_form.customer_status.data
            customer.customer_server = edit_form.customer_server.data
            customer.customer_conn_type = edit_form.customer_conn_type.data
            customer.customer_location = edit_form.customer_location.data
            customer.customer_partner = edit_form.customer_partner.data
            customer.customer_basestation_location = edit_form.customer_basestation_location.data
            customer.customer_basestation_id = edit_form.customer_basestation_id.data
            customer.customer_sector = edit_form.customer_sector.data
            customer.customer_switch = edit_form.customer_switch.data
            customer.customer_management_vlan = edit_form.customer_management_vlan.data
            customer.customer_traffic_vlan = edit_form.customer_traffic_vlan.data
            customer.customer_subnet = edit_form.customer_subnet.data
            customer.customer_mu_ip = edit_form.customer_mu_ip.data
            customer.customer_su_ip = edit_form.customer_su_ip.data
            customer.customer_ssid = edit_form.customer_ssid.data
            customer.customer_channel_width = edit_form.customer_channel_width.data
            customer.customer_frequency = edit_form.customer_frequency.data
            customer.customer_mu_mac_id = edit_form.customer_mu_mac_id.data
            customer.customer_su_mac_id = edit_form.customer_su_mac_id.data
            customer.customer_rssi_ccq_airmax = edit_form.customer_rssi_ccq_airmax.data
            customer.customer_radio_type = edit_form.customer_radio_type.data
            customer.customer_cpe = edit_form.customer_cpe.data
            customer.customer_provider_edge_router = edit_form.customer_provider_edge_router.data
            customer.customer_wan_ip = edit_form.customer_wan_ip.data
            customer.customer_wan_subnet = edit_form.customer_wan_subnet.data
            customer.customer_wan_gateway = edit_form.customer_wan_gateway.data
            customer.customer_wan_routing_protocol = edit_form.customer_wan_routing_protocol.data
            customer.customer_ip = edit_form.customer_ip.data
            customer.customer_subnet_mask = edit_form.customer_subnet_mask.data
            customer.customer_gateway = edit_form.customer_gateway.data
            customer.customer_service_type = edit_form.customer_service_type.data
            customer.customer_service_plan = edit_form.customer_service_plan.data
            customer.customer_bandwidth_plan = edit_form.customer_bandwidth_plan.data
            customer.customer_wifi_ssid = edit_form.customer_wifi_ssid.data
            customer.customer_wifi_password = f.encrypt(
                edit_form.customer_wifi_password.data.encode())
            customer.customer_installation_date = edit_form.customer_installation_date.data
            customer.customer_activation_date = edit_form.customer_activation_date.data
            customer.customer_installation_engineer = edit_form.customer_installation_engineer.data
            customer.customer_contact_person = edit_form.customer_contact_person.data
            customer.customer_phone_number = edit_form.customer_phone_number.data
            customer.customer_email = edit_form.customer_email.data
            customer.customer_physical_address = edit_form.customer_physical_address.data

            customer.update()
            flash(
                f'Customer {edit_form.customer_name.data} - {edit_form.customer_code.data} updated.')
            return redirect(url_for('get_customers'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Customer {edit_form.customer_name.data} - {edit_form.customer_code.data} could not be updated. Try again.')
            return redirect(url_for('update_customer', customer_code=edit_form.customer_code.data))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/customer.html', form=edit_form, is_edit=True, current_user=current_user)


@app.route('/customers/<customer_code>/delete', methods=['GET', 'DELETE'])
@login_required
@ip_only
def delete_customer(customer_code):
    customer = Customer.query.filter_by(
        customer_code=customer_code).one_or_none()
    customer_password = CustomerPassword.query.filter_by(
        customer_code=customer_code).one_or_none()
    customer_prtg = CustomerPRTG.query.filter_by(
        customer_code=customer_code).one_or_none()
    customer_lat = LinkActivationTracker.query.filter_by(
        customer_code=customer_code).all()
    customer_cit = ChangeImplementationTracker.query.filter_by(
        customer_code=customer_code).all()

    if customer_cit:
        if len(customer_cit) == 1:
            customer_cit.delete()
        else:
            for c in customer_cit:
                c.delete()

    if customer_lat:
        if len(customer_lat) == 1:
            customer_lat.delete()
        else:
            for l in customer_lat:
                l.delete()

    if customer_prtg:
        customer_prtg.delete()

    if customer_password:
        customer_password.delete()

    try:
        customer.delete()
        flash(f'Deleted customer {customer.customer_code}.')
    except:
        db.session.rollback()
        print(sys.exc_info())
        flash(f'Could not delete {customer.customer_code}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_customers'))


@app.route('/customers-details')
@login_required
@ip_and_others
def get_customers_details():

    return render_template('pages/ip/customersdetails.html', current_user=current_user)


@app.route('/customers-details/data')
@login_required
@ip_and_others
def get_customers_details_data():
    query = db.session.query(
        Customer.customer_name,
        Customer.customer_code,
        Customer.customer_status,
        Customer.customer_location,
        Customer.customer_partner,
        Customer.customer_service_type,
        Customer.customer_service_plan,
        Customer.customer_bandwidth_plan,
        Customer.customer_contact_person,
        Customer.customer_phone_number,
        Customer.customer_email,
        Customer.customer_physical_address
    )

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            Customer.customer_code.ilike(f'%{search}%'),
            Customer.customer_code.contains(search),
            Customer.customer_name.ilike(f'%{search}%'),
            Customer.customer_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [{
            'customer_name': query[i][0],
            'customer_code': query[i][1],
            'customer_status': query[i][2],
            'customer_location': query[i][3],
            'customer_partner': query[i][4],
            'customer_service_type': query[i][5],
            'customer_service_plan': query[i][6],
            'customer_bandwidth_plan': query[i][7],
            'customer_contact_person': query[i][8],
            'customer_phone_number': query[i][9],
            'customer_email': query[i][10],
            'customer_physical_address': query[i][11]
        } for i in range(len(query.all()))],
        'total': total,
    }

    return response


@app.route('/link-details')
@login_required
@ip_and_others
def get_link_details():

    return render_template('pages/ip/linkdetails.html', current_user=current_user)


@app.route('/link-details/data')
@login_required
@ip_and_others
def get_link_details_data():
    query = db.session.query(
        Customer.customer_name,
        Customer.customer_code,
        Customer.customer_server,
        Customer.customer_conn_type,
        Customer.customer_basestation_id,
        Customer.customer_basestation_location,
        Customer.customer_sector,
        Customer.customer_switch,
        Customer.customer_management_vlan,
        Customer.customer_traffic_vlan,
        Customer.customer_ssid,
        Customer.customer_channel_width,
        Customer.customer_frequency,
        Customer.customer_mu_mac_id,
        Customer.customer_su_mac_id,
        Customer.customer_rssi_ccq_airmax,
        Customer.customer_radio_type,
        Customer.customer_cpe,
        Customer.customer_wifi_ssid,
        Customer.customer_wifi_password,
        Customer.customer_installation_date,
        Customer.customer_activation_date,
        Customer.customer_installation_engineer
    )

    key = load_key()
    f = Fernet(key)

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            Customer.customer_code.ilike(f'%{search}%'),
            Customer.customer_code.contains(search),
            Customer.customer_name.ilike(f'%{search}%'),
            Customer.customer_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [
            {
                'customer_name': query[i][0],
                'customer_code': query[i][1],
                'customer_server': query[i][2],
                'customer_conn_type': query[i][3],
                'customer_basestation_id': query[i][4],
                'customer_basestation_location': query[i][5],
                'customer_sector': query[i][6],
                'customer_switch': query[i][7],
                'customer_management_vlan': query[i][8],
                'customer_traffic_vlan': query[i][9],
                'customer_ssid': query[i][10],
                'customer_channel_width': query[i][11],
                'customer_frequency': query[i][12],
                'customer_mu_mac_id': query[i][13],
                'customer_su_mac_id': query[i][14],
                'customer_rssi_ccq_airmax': query[i][15],
                'customer_radio_type': query[i][16],
                'customer_cpe': query[i][17],
                'customer_wifi_ssid': query[i][18],
                'customer_wifi_password': f.decrypt(query[i][19]).decode(),
                'customer_installation_date': query[i][20],
                'customer_activation_date': query[i][21],
                'customer_installation_engineer': query[i][22]
            } for i in range(len(query.all()))],
        'total': total,
    }

    return response


@app.route('/ip-details')
@login_required
def get_ip_details():

    return render_template('pages/ip/customers.html', current_user=current_user)


@app.route('/ip-details/data')
@login_required
def get_ip_details_data():
    query = db.session.query(
        Customer.customer_name,
        Customer.customer_code,
        Customer.customer_subnet,
        Customer.customer_mu_ip,
        Customer.customer_su_ip,
        Customer.customer_provider_edge_router,
        Customer.customer_wan_ip,
        Customer.customer_wan_subnet,
        Customer.customer_wan_gateway,
        Customer.customer_wan_routing_protocol,
        Customer.customer_ip,
        Customer.customer_subnet_mask,
        Customer.customer_gateway
    )

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            Customer.customer_code.ilike(f'%{search}%'),
            Customer.customer_code.contains(search),
            Customer.customer_name.ilike(f'%{search}%'),
            Customer.customer_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [
            {
                'customer_name': query[i][0],
                'customer_code': query[i][1],
                'customer_subnet': query[i][2],
                'customer_mu_ip': query[i][3],
                'customer_su_ip': query[i][4],
                'customer_provider_edge_router': query[i][5],
                'customer_wan_ip': query[i][6],
                'customer_wan_subnet': query[i][7],
                'customer_wan_gateway': query[i][8],
                'customer_wan_routing_protocol': query[i][9],
                'customer_ip': query[i][10],
                'customer_subnet_mask': query[i][11],
                'customer_gateway': query[i][12],
            } for i in range(len(query.all()))],
        'total': total,
    }

    return response


# --------------------------------------------- CUSTOMERS PASSWORD ------------------------------------------->
@app.route('/customers-password')
@login_required
@ip_only
def get_customers_password():

    return render_template('pages/ip/customerspassword.html', current_user=current_user)


@app.route('/customers-password/data')
@login_required
def get_customers_password_data():
    query = CustomerPassword.query

    key = load_key()
    f = Fernet(key)

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            CustomerPassword.customer_code.ilike(f'%{search}%'),
            CustomerPassword.customer_code.contains(search),
            CustomerPassword.customer_name.ilike(f'%{search}%'),
            CustomerPassword.customer_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [{
            'customer_code': customer.customer_code,
            'customer_name': customer.customer_name,
            'customer_device_type': customer.customer_device_type,
            'customer_device_ip': customer.customer_device_ip,
            'customer_username': customer.customer_username,
            'customer_password': f.decrypt(customer.customer_password).decode()
        } for customer in query],
        'total': total,
    }

    return response


@app.route('/customers-password/verify', methods=['GET', 'POST'])
@login_required
@ip_only
def verify_code_for_password():
    customer_code = request.form.get('customer_code')

    if Customer.query.filter_by(customer_code=customer_code).one_or_none():
        return redirect(url_for('add_customer_password', customers_code=customer_code))
    else:
        flash('Please enter a valid customer code')


@app.route('/customers-password/<customers_code>', methods=['GET', 'POST'])
@login_required
@ip_only
def add_customer_pasword(customers_code):
    customer = Customer.query(Customer.customer_name, Customer.customer_code).filter_by(
        customer_code=customers_code).one_or_none()

    form = CustomerPasswordForm(
        customer_name=customer[0],
        customer_code=customer[1],
    )

    if form.validate_on_submit():
        if CustomerPassword.query.filter_by(customer_code=form.customer_code.data):
            flash(
                f'There is an existing entry for customer {form.customer_code.data}.')
        else:
            key = load_key()
            f = Fernet(key)

            try:
                customer_password = CustomerPassword(
                    customer_name=form.customer_name.data,
                    customer_code=form.customer_code.data,
                    customer_device_type=form.customer_device_type.data,
                    customer_device_ip=form.customer_device_ip.data,
                    customer_username=form.customer_username.data,
                    customer_password=f.encrypt(
                        form.customer_password.data.encode())
                )
                customer_password.insert()
                flash(
                    f'Password saved for customer {form.customer_username.data}.')
                return redirect(url_for('get_customers_password'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Could not save password for {form.customer_username.data}. Try again.')
                return redirect(url_for('add_customer_password', customers_code=form.customer_code.data))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/customerpassword.html', form=form, current_user=current_user)


@app.route('/customers-password/upload', methods=['POST', 'GET'])
@login_required
@admin_only
def upload_customers_password_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['customer_name', 'customer_code', 'customer_device_type',
                     'customer_device_ip', 'customer_username', 'customer_password']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        key = load_key()
        f = Fernet(key)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                customer_password = CustomerPassword(
                    customer_name=row['customer_name'],
                    customer_code=row['customer_code'],
                    customer_device_type=row['customer_device_type'],
                    customer_device_ip=row['customer_device_ip'],
                    customer_username=row['customer_username'],
                    customer_password=f.encrypt(
                        row['customer_password'].encode())
                )
                customer_password.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload customers prtg details.')
        else:
            flash('Uploaded customers prtg details successfully.')

        return redirect(url_for('get_customers_password'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/customerpasword.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/customers-password/<customer_code>/edit', methods=['POST', 'PATCH', 'GET'])
@login_required
@ip_only
def update_customer_password(customer_code):
    customer = CustomerPassword.query.filter_by(customer_code=customer_code).one_or_none()
    key = load_key()
    f = Fernet(key)

    edit_form = CustomerPasswordForm(
        customer_name=customer.customer_name,
        customer_code=customer.customer_code,
        customer_device_type=customer.customer_device_type,
        customer_device_ip=customer.customer_device_ip,
        customer_username=customer.customer_username,
        customer_password=f.decrypt(customer.customer_password).decode()
    )

    if edit_form.validate_on_submit():
        try:
            customer.customer_name=edit_form.customer_name.data
            customer.customer_code=edit_form.customer_code.data
            customer.customer_device_type=edit_form.customer_device_type.data
            customer.customer_device_ip=edit_form.customer_device_ip.data
            customer.customer_username=edit_form.customer_username.data
            customer.customer_password=f.encrypt(edit_form.customer_password.data.encode())

            customer.update()
            flash(f'Password updated for customer {edit_form.customer_username.data}.')
            return redirect(url_for('get_customers_password'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Could not update password for {edit_form.customer_username.data}. Try again.')
            return redirect(url_for('update_customer_password', customer_code=edit_form.customer_code.data))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/customerpassword.html', form=edit_form, is_edit=True, current_user=current_user)


@app.route('/customers-password/<customer_code>/delete', methods=['GET', 'DELETE'])
@login_required
@ip_only
def delete_customer_passoword(customer_code):
    customer = CustomerPassword.query.filter_by(customer_code=customer_code).one_or_none()

    try:
        customer.delete()
        flash(f'Deleted password for customer {customer.customer_username}.')
    except:
        db.session.rollback()
        print(sys.exc_info())
        flash('Could not delete password for customer {customer.customer_username}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_customers_password'))


# --------------------------------------------- CUSTOMERS PRTG ------------------------------------------->
@app.route('/customers-prtg')
@login_required
@ip_and_others
def get_customers_prtg():

    return render_template('pages/ip/customersprtg.html', current_user=current_user)


@app.route('/customers-prtg/data')
@login_required
def get_customers_prtg_data():
    query = CustomerPassword.query

    key = load_key()
    f = Fernet(key)

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            CustomerPRTG.customer_code.ilike(f'%{search}%'),
            CustomerPRTG.customer_code.contains(search),
            CustomerPRTG.customer_name.ilike(f'%{search}%'),
            CustomerPRTG.customer_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [{
            'customer_code': customer.customer_code,
            'customer_name': customer.customer_name,
            'customer_device_type': customer.customer_device_type,
            'customer_device_ip': customer.customer_device_ip,
            'customer_username': customer.customer_username,
            'customer_password': f.decrypt(customer.customer_password).decode()
        } for customer in query],
        'total': total,
    }

    return response


@app.route('/customers-prtg/verify', methods=['GET', 'POST'])
@login_required
@ip_only
def verify_code_for_prtg():
    customer_code = request.form.get('customer_code')

    if Customer.query.filter_by(customer_code=customer_code).one_or_none():
        return redirect(url_for('add_customer_prtg', customers_code=customer_code))
    else:
        flash('Please enter a valid customer code')


@app.route('/customers-prtg/<customers_code>', methods=['GET', 'POST'])
@login_required
@ip_only
def add_customer_prtg(customers_code):
    customer = Customer.query(Customer.customer_name, Customer.customer_code).filter_by(
        customer_code=customers_code).one_or_none()

    form = CustomerPRTGForm(
        customer_name=customer[0],
        customer_code=customer[1],
    )

    if form.validate_on_submit():
        if CustomerPRTG.query.filter_by(customer_code=form.customer_code.data):
            flash(
                f'There is an existing entry for customer {form.customer_code.data}.')
        else:
            key = load_key()
            f = Fernet(key)

            try:
                customer_prtg = CustomerPRTG(
                    customer_name=form.customer_name.data,
                    customer_code=form.customer_code.data,
                    customer_username=form.customer_username.data,
                    customer_password=f.encrypt(form.customer_password.data.encode())
                )
                customer_prtg.insert()
                flash(
                    f'PRTG details saved for customer {form.customer_username.data}.')
                return redirect(url_for('get_customers_prtg'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Could not save prtg details for {form.customer_username.data}. Try again.')
                return redirect(url_for('add_customer_prtg', customers_code=form.customer_code.data))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/customerprtg.html', form=form, current_user=current_user)


@app.route('/customers-prtg/upload', methods=['POST', 'GET'])
@login_required
@admin_only
def upload_customers_prtg_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = ['customer_name', 'customer_code', 'customer_username', 'customer_password']
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        key = load_key()
        f = Fernet(key)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                customer_prtg = CustomerPRTG(
                    customer_name=row['customer_name'],
                    customer_code=row['customer_code'],
                    customer_username=row['customer_username'],
                    customer_password=f.encrypt(
                        row['customer_password'].encode())
                )
                customer_prtg.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload customers prtg details.')
        else:
            flash('Uploaded customers prtg details successfully.')

        return redirect(url_for('get_customers_prtg'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/customerprtg.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/customers-prtg/<customer_code>/edit', methods=['POST', 'PATCH', 'GET'])
@login_required
@ip_only
def update_customer_prtg(customer_code):
    customer = CustomerPRTG.query.filter_by(
        customer_code=customer_code).one_or_none()
    key = load_key()
    f = Fernet(key)

    edit_form = CustomerPRTGForm(
        customer_name=customer.customer_name,
        customer_code=customer.customer_code,
        customer_username=customer.customer_username,
        customer_password=f.decrypt(customer.customer_password).decode()
    )

    if edit_form.validate_on_submit():
        try:
            customer.customer_name = edit_form.customer_name.data
            customer.customer_code = edit_form.customer_code.data
            customer.customer_username = edit_form.customer_username.data
            customer.customer_password = f.encrypt(edit_form.customer_password.data.encode())

            customer.update()
            flash(
                f'PRTG details updated for customer {edit_form.customer_username.data}.')
            return redirect(url_for('get_customers_prtg'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Could not update prtg details for {edit_form.customer_username.data}. Try again.')
            return redirect(url_for('update_customer_prtg', customer_code=edit_form.customer_code.data))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/customerprtg.html', form=edit_form, is_edit=True, current_user=current_user)


@app.route('/customers-prtg/<customer_code>/delete', methods=['GET', 'DELETE'])
@login_required
@ip_only
def delete_customer_prtg(customer_code):
    customer = CustomerPRTG.query.filter_by(
        customer_code=customer_code).one_or_none()

    try:
        customer.delete()
        flash(f'Deleted prtg details for customer {customer.customer_username}.')
    except:
        db.session.rollback()
        print(sys.exc_info())
        flash(
            'Could not delete prtg details for customer {customer.customer_username}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_customers_prtg'))


# --------------------------------------------- LINK ACTIVATION TRACKERS ------------------------------------------->
@app.route('/link-activation-trackers')
@login_required
@ip_only
def get_link_activation_trackers():

    return render_template('pages/ip/linkactivationtrackers.html', current_user=current_user)


@app.route('/link-activation-trackers/data')
@login_required
def get_link_activation_trackers_data():
    query = LinkActivationTracker.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            LinkActivationTracker.customer_code.ilike(f'%{search}%'),
            LinkActivationTracker.customer_code.contains(search),
            LinkActivationTracker.customer_name.ilike(f'%{search}%'),
            LinkActivationTracker.customer_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [customer.to_dict() for customer in query],
        'total': total,
    }

    return response


@app.route('/link-activation-trackers/verify', methods=['GET', 'POST'])
@login_required
@ip_only
def verify_code_for_lat():
    customer_code = request.form.get('customer_code')

    if Customer.query.filter_by(customer_code=customer_code).one_or_none():
        return redirect(url_for('add_link_activation_tracker', customers_code=customer_code))
    else:
        flash('Please enter a valid customer code')


@app.route('/link-activation-trackers/<customers_code>', methods=['GET', 'POST'])
@login_required
@ip_only
def add_link_activation_tracker(customers_code):
    customer = Customer.query(Customer.customer_name, Customer.customer_code).filter_by(
        customer_code=customers_code).one_or_none()

    form = LinkActivationTrackerForm(
        customer_name=customer[0],
        customer_code=customer[1],
    )
    
    form.customer_basestation_id.choices = [(basestation.basestation_id, basestation.basestation_id) for basestation in Basestation.query.order_by('server_name')]

    if form.validate_on_submit():
        if LinkActivationTracker.query.filter_by(customer_code=form.customer_code.data):
            flash(
                f'There is an existing entry for customer {form.customer_code.data}.')
        else:
            try:
                lat = LinkActivationTracker(
                    customer_name=form.customer_name.data,
                    customer_code=form.customer_code.data,
                    customer_basestation_id=form.customer_basestation_id.data,
                    customer_service_desc=form.customer_service_desc,
                    customer_request_date=form.customer_request_date.data,
                    customer_link_completion_date=form.customer_link_completion_date.data,
                    customer_implemented_by=form.customer_implemented_by.data
                )
                lat.insert()
                flash(
                    f'Link activation tracker saved for customer {form.customer_code.data}.')
                return redirect(url_for('get_link_activation_trackers'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Could not save link activation tracker for {form.customer_code.data}. Try again.')
                return redirect(url_for('add_link_activation_tracker', customers_code=form.customer_code.data))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/linkactivationtracker.html.html', form=form, current_user=current_user)


@app.route('/link-activation-trackers/upload', methods=['POST', 'GET'])
@login_required
@admin_only
def upload_link_activation_trackers_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = [
            'customer_name', 
            'customer_code', 
            'customer_basestation_id', 
            'customer_service_desc', 
            'customer_request_date', 
            'customer_link_completion_date', 
            'customer_implemented_by'
        ]
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                lat = LinkActivationTracker(
                    customer_name=row['customer_name'],
                    customer_code=row['customer_code'],
                    customer_basestation_id=row['customer_basestation_id'],
                    customer_service_desc=row['customer_service_desc'],
                    customer_request_date=row['customer_request_date'],
                    customer_link_completion_date=row['customer_link_completion_date'],
                    customer_implemented_by=row['customer_implemented_by']
                )
                lat.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload link activation trackers.')
        else:
            flash('Uploaded link activation trackers successfully.')

        return redirect(url_for('get_link_activation_trackers'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/linkactivationtracker.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/link-activation-trackers/<customer_code>/edit', methods=['POST', 'PATCH', 'GET'])
@login_required
@ip_only
def update_link_activation_tracker(customer_code):
    customer = LinkActivationTracker.query.filter_by(
        customer_code=customer_code).one_or_none()

    edit_form = LinkActivationTrackerForm(
        customer_name=customer.customer_name,
        customer_code=customer.customer_code,
        customer_basestation_id=customer.customer_basestation_id,        
        customer_service_desc=customer.customer_service_desc,
        customer_request_date=customer.customer_request_date,
        customer_link_completion_date=customer.customer_link_completion_date,
        customer_implemented_by=customer.customer_implemented_by   
    )

    edit_form.customer_basestation_id.choices = [(basestation.basestation_id, basestation.basestation_id) for basestation in Basestation.query.order_by('server_name')]


    if edit_form.validate_on_submit():
        try:
            customer.customer_name = edit_form.customer_name.data
            customer.customer_code = edit_form.customer_code.data
            customer.customer_basestation_id = edit_form.customer_basestation_id.data
            customer.customer_service_desc = edit_form.customer_service_desc.data
            customer.customer_request_date = edit_form.customer_request_date.data
            customer.customer_link_completion_date = edit_form.customer_link_completion_date.data
            customer.customer_implemented_by = edit_form.customer_implemented_by.data

            customer.update()
            flash(
                f'Link activation tracker updated for customer {edit_form.customer_code.data}.')
            return redirect(url_for('get_link_activation_trackers'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Could not update link activation tracker for {edit_form.customer_code.data}. Try again.')
            return redirect(url_for('update_link_activation_tracker', customer_code=edit_form.customer_code.data))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/linkactivationtracker.html', form=edit_form, is_edit=True, current_user=current_user)


@app.route('/link-activation-trackers/<customer_code>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_link_activation_tracker(customer_code):
    customer = LinkActivationTracker.query.filter_by(
        customer_code=customer_code).one_or_none()

    try:
        customer.delete()
        flash(
            f'Deleted link activation tracker for customer {customer.customer_code}.')
    except:
        db.session.rollback()
        print(sys.exc_info())
        flash(
            f'Could not delete link activation tracker for customer {customer.customer_code}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_link_activation_trackers'))


# --------------------------------------------- CHANGE IMPLEMENTATION TRACKERS ------------------------------------------->
@app.route('/change-implementation-trackers')
@login_required
@ip_only
def get_change_implementation_trackers():

    return render_template('pages/ip/changeimplementationtrackers.html', current_user=current_user)


@app.route('/change-implementation-trackers/data')
@login_required
def get_change_implementation_trackers_data():
    query = ChangeImplementationTracker.query

    # search filter
    search = request.args.get('search')
    if search:
        query = query.filter(db.or_(
            ChangeImplementationTracker.customer_code.ilike(f'%{search}%'),
            ChangeImplementationTracker.customer_code.contains(search),
            ChangeImplementationTracker.customer_name.ilike(f'%{search}%'),
            ChangeImplementationTracker.customer_name.contains(search)
        ))

    total = query.count()

    # pagination
    start = request.args.get('start', type=int, default=-1)
    length = request.args.get('length', type=int, default=-1)
    if start != -1 and length != -1:
        query = query.offset(start).limit(length)

    # response
    response = {
        'data': [customer.to_dict() for customer in query],
        'total': total,
    }

    return response


@app.route('/change-implementation-trackers/verify', methods=['GET', 'POST'])
@login_required
@ip_only
def verify_code_for_cit():
    customer_code = request.form.get('customer_code')

    if Customer.query.filter_by(customer_code=customer_code).one_or_none():
        return redirect(url_for('add_change_implementation_tracker', customers_code=customer_code))
    else:
        flash('Please enter a valid customer code')


@app.route('/change-implementation-trackers/<customers_code>', methods=['GET', 'POST'])
@login_required
@ip_only
def add_change_implementation_tracker(customers_code):
    customer = Customer.query(Customer.customer_name, Customer.customer_code).filter_by(
        customer_code=customers_code).one_or_none()

    form = ChangeImplementationTrackerForm(
        customer_name=customer[0],
        customer_code=customer[1],
    )

    if form.validate_on_submit():
        if ChangeImplementationTracker.query.filter_by(customer_code=form.customer_code.data):
            flash(
                f'There is an existing entry for customer {form.customer_code.data}.')
        else:
            try:
                cit = ChangeImplementationTracker(
                    customer_name=form.customer_name.data,
                    customer_code=form.customer_code.data,
                    customer_change_id=form.customer_change_id.data,
                    customer_change_desc=form.customer_change_desc,
                    customer_change_type=form.customer_change_type.data,
                    customer_instructed_by=form.customer_instructed_by.data,
                    customer_approved_by=form.customer_approved_by.data,
                    customer_request_date=form.customer_request_date,
                    customer_implementation_date_and_time=form.customer_implementation_date_and_time.data,
                    customer_implemented_by=form.customer_implemented_by.data,
                    customer_status=form.customer_status.data
                )
                cit.insert()
                flash(
                    f'Change implementation tracker saved for customer {form.customer_code.data}.')
                return redirect(url_for('get_change_implementation_trackers'))
            except:
                db.session.rollback()
                print(sys.exc_info())
                flash(
                    f'Could not save change implementation tracker for {form.customer_code.data}. Try again.')
                return redirect(url_for('add_change_implementation_tracker', customers_code=form.customer_code.data))
            finally:
                db.session.close()
    else:
        for field, message in form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/changeimplementationtracker.html.html', form=form, current_user=current_user)


@app.route('/change-implementation-trackers/upload', methods=['POST', 'GET'])
@login_required
@admin_only
def upload_change_implementation_trackers_csv():
    upload_form = CSVUploadForm()

    if upload_form.validate_on_submit():
        # get the uploaded file
        uploaded_file = upload_form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = [
            'customer_name',
            'customer_code',
            'customer_change_id',
            'customer_change_desc',
            'customer_change_type',
            'customer_instructed_by',
            'customer_approved_by'
            'customer_request_date',
            'customer_implementation_date_and_time',
            'customer_implemented_by',
            'customer_status'
        ]
        csvData = pd.read_csv(file_path, names=col_names, header=None)

        error = False
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                cit = ChangeImplementationTracker(
                    customer_name=row['customer_name'],
                    customer_code=row['customer_code'],
                    customer_change_id=row['customer_change_id'],
                    customer_change_desc=row['customer_change_desc'],
                    customer_change_type=row['customer_change_type'],
                    customer_instructed_by=row['customer_instructed_by'],
                    customer_approved_by=row['customer_approved_by'],
                    customer_request_date=row['customer_request_date'],
                    customer_implementation_date_and_time=row['customer_implementation_date_and_time'],
                    customer_implemented_by=row['customer_implemented_by'],
                    customer_status=row['customer_status']
                )
                cit.insert()
            except:
                db.session.rollback()
                error = True
                print(sys.exc_info())

        db.session.close()
        if error:
            flash('Could not upload change implementation trackers.')
        else:
            flash('Uploaded change implementation trackers successfully.')

        return redirect(url_for('get_change_implementation_trackers'))
    else:
        for field, message in upload_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/changeimplementationtracker.html', form=upload_form, is_upload=True, current_user=current_user)


@app.route('/change-implementation-trackers/<change_id>/edit', methods=['POST', 'PATCH', 'GET'])
@login_required
@ip_only
def update_change_implementation_tracker(change_id):
    customer = ChangeImplementationTracker.query.filter_by(customer_change_id=change_id).one_or_none()

    edit_form = ChangeImplementationTrackerForm(
        customer_name=customer.customer_name,
        customer_code=customer.customer_code,
        customer_change_id=customer.customer_change_id,
        customer_change_desc=customer.customer_change_desc,
        customer_change_type=customer.customer_change_type,
        customer_instructed_by=customer.customer_instructed_by,
        customer_approved_by=customer.customer_approved_by,
        customer_request_date=customer.customer_request_date,
        customer_implementation_date_and_time=customer.customer_implementation_date_and_time,
        customer_implemented_by=customer.customer_implemented_by,
        customer_status=customer.customer_status
    )

    if edit_form.validate_on_submit():
        try:
            customer.customer_name = edit_form.customer_name.data
            customer.customer_code = edit_form.customer_code.data
            customer.customer_change_id = edit_form.customer_change_id.data
            customer.customer_change_desc = edit_form.customer_change_desc.data
            customer.customer_change_type = edit_form.customer_change_type.data
            customer.customer_instructed_by = edit_form.customer_instructed_by.data
            customer.customer_approved_by = edit_form.customer_approved_by.data
            customer.customer_request_date = edit_form.customer_request_date.data
            customer.customer_implementation_date_and_time = edit_form.customer_implementation_date_and_time.data
            customer.customer_implemented_by = edit_form.customer_implemented_by.data
            customer.customer_status = edit_form.customer_status.data

            customer.update()
            flash(
                f'Change implementation tracker updated for customer {edit_form.customer_change_id.data}.')
            return redirect(url_for('get_change_implementation_trackers'))
        except:
            db.session.rollback()
            print(sys.exc_info())
            flash(
                f'Could not update change implementation tracker for {edit_form.customer_change_id.data}. Try again.')
            return redirect(url_for('update_change_implementation_tracker', change_id=edit_form.customer_change_id.data))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/ip/changeimplementation.html', form=edit_form, is_edit=True, current_user=current_user)


@app.route('/change-implementation-trackers/<change_id>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_change_implementation_tracker(change_id):
    customer = ChangeImplementationTracker.query.filter_by(customer_change_id=change_id).one_or_none()

    try:
        customer.delete()
        flash(
            f'Deleted change implementation tracker for customer {customer.customer_code}.')
    except:
        db.session.rollback()
        print(sys.exc_info())
        flash(
            f'Could not delete change implementation tracker for customer {customer.customer_code}. Try again.')
    finally:
        db.session.close()
        return redirect(url_for('get_change_implementation_trackers'))


'''
Error Handlers
'''

@app.errorhandler(400)
def bad_request(error):
    error = {
        "success": False,
        "error": 400,
        "message": "It seems you have made a bad request."
    }

    return render_template('pages/error.html', response=error, current_user=current_user)


@app.errorhandler(401)
def lacks_valid_authentication(error):
    return redirect(url_for('login'))


@app.errorhandler(403)
def unauthorized(error):
    error = {
        "success": False,
        "error": 403,
        "message": "You are not authorized to access this url."
    }

    return render_template('pages/error.html', response=error, current_user=current_user)


@app.errorhandler(404)
def not_found(error):
    error = {
        "success": False,
        "error": 404,
        "message": "The resource you have requested cannot be found."
    }

    return render_template('pages/error.html', response=error, current_user=current_user)


@app.errorhandler(405)
def method_not_allowed(error):
    error = {
        "success": False,
        "error": 405,
        "message": "This method is not allowed for the requested url."
    }
    return render_template('pages/error.html', response=error, current_user=current_user)


@app.errorhandler(422)
def unprocessable(error):
    error = {
        "success": False,
        "error": 422,
        "message": "Your request could not be processed. Try again."
    }

    return render_template('pages/error.html', response=error, current_user=current_user)


@app.errorhandler(500)
def server_error(error):
    error = {
        "success": False,
        "error": 500,
        "message": "We're sorry, something went wrong on our end. Please try again."
    }

    return render_template('pages/error.html', response=error, current_user=current_user)


if __name__ == '__main__':
    app.run(debug=True)

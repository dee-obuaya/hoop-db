import os
import sys
import pandas as pd
from cryptography.fernet import Fernet
from flask import Flask, jsonify, render_template, redirect, url_for, flash, abort, request
from flask_bootstrap import Bootstrap
from flask_cors import CORS
from flask_login import login_user, LoginManager, login_required, current_user, logout_user
from flask_migrate import Migrate
from functools import wraps
from werkzeug.utils import secure_filename
from models import CPE, BandwidthPlan, Basestation, Connection, Partner, Radio, Server, ServicePlan, ServiceType, User, Vlan, db
from forms import CSVUploadForm, PartnerForm, UserForm

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


def create_key():
    """
    Generates a key and save it into a file
    """
    key = Fernet.generate_key()

    with open('fernet.key', 'wb') as key_file:
        key_file.write(key)

    print('Key created')


def call_key():
    '''
    Loads the key from the file where it is stored.
    '''
    return open('fernet.key', 'r').read()


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
        # If users privileges is not Admin then return abort with 403 error
        if (current_user.privileges != 'Admin') or (current_user.department != 'IP'):
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


def admin_noc_ip(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # If users privileges is not Admin then return abort with 403 error
        if (current_user.privileges != 'Admin') or (current_user.department != 'IP') or (current_user.department != 'NOC'):
            return abort(403)
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
        # If users department is not IP then return abort with 403 error
        if (current_user.department != 'IP') or (current_user.department != 'Technical Support') or (current_user.department != 'Service Management'):
            return abort(403)
        # Otherwise continue with the route function
        return f(*args, **kwargs)

    return decorated_function


@app.route('/', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        key = call_key()
        fernet = Fernet(key)

        user = User.query.filter_by(username=username).one_or_none()

        if not user:
            flash(f'Username {username} does not exist.')
            return redirect(url_for('login'))
        elif fernet.decrypt(user.password).decode() != password:
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
    selection = User.query.order_by(User.username)
    formatted_selection = [user.format() for user in selection.all()]

    key = call_key()
    print(key)
    fernet = Fernet(key)

    return render_template('pages/admin/users.html', response=formatted_selection, fernet=fernet, current_user=current_user)


@app.route('/users/search', methods=['GET', 'POST'])
@login_required
@admin_only
def search_users():
    search_query = request.form.get('search_term', '')
    search_response = User.query.filter(
        User.username.ilike(f'%{search_query}%') | User.username.contains(search_query) |
        User.department.ilike(f'%{search_query}%') | User.department.contains(
            search_query.title())
    )
    response = {
        "count": search_response.count(),
        "data": [user.format() for user in search_response.all()]
    }

    key = call_key()
    fernet = Fernet(key)
    return render_template('pages/admin/users.html', response=response, search_term=search_query, fernet=fernet, is_search=True, current_user=current_user)


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
            key = call_key()
            fernet = Fernet(key)
            try:
                user = User(
                    username=form.username.data,
                    password=fernet.encrypt(form.password.data.encode()),
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
        key = call_key()
        fernet = Fernet(key)
        error = False
        for i, row in csvData.iterrows():
            try:
                user = User(
                    username=row['username'],
                    password=fernet.encrypt(row['password'].encode()),
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


@app.route('/users/<int:user_id>', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_only
def update_user(user_id):
    user = User.query.get(user_id)
    key = call_key()
    fernet = Fernet(key)

    edit_form = UserForm(
        username=user.username,
        password=fernet.decrypt(user.password).decode(),
        department=user.department,
        privileges=user.privileges
    )

    if edit_form.validate_on_submit():
        try:
            user.username = edit_form.username.data
            user.password = fernet.encrypt(
                edit_form.password.data.encode())
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
            return redirect(url_for('update_user', user_id=user.id))
        finally:
            db.session.close()
    else:
        for field, message in edit_form.errors.items():
            flash(field + ' - ' + str(message), 'danger')

    return render_template('forms/admin/user.html', is_edit=True, form=edit_form, current_user=current_user)


@app.route('/users/<int:user_id>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_only
def delete_user(user_id):
    user = User.query.get(user_id)

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
    selection = Partner.query.order_by(Partner.partner_id)
    formatted_selection = [user.format() for user in selection.all()]

    return render_template('pages/admin/partners.html', response=formatted_selection, current_user=current_user)


@app.route('/partners/search', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def search_partners():
    search_query = request.form.get('search_term', '')
    search_response = Partner.query.filter(
        Partner.partner_id.ilike(f'%{search_query}%') | Partner.partner_id.contains(search_query) |
        Partner.partner_name.ilike(f'%{search_query}%') | Partner.partner_name.contains(search_query)
    )
    response = {
        "count": search_response.count(),
        "data": [partner.format() for partner in search_response.all()]
    }
    print(response)
    return render_template('pages/admin/partners.html', response=response, is_search=True, search_term=search_query, current_user=current_user)


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


@app.route('/partners/<partner_id>', methods=['GET', 'POST', 'PATCH'])
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
            partner.partner_id = edit_form.partner_id.data
            partner.partner_name = edit_form.partner_name
            partner.partner_contact = edit_form.partner_contact
            partner.partner_address = edit_form.partner_address

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
    pass


@app.route('/basestations/search', methods=['GET', 'POST'])
@login_required
def search_basestations():
    search_query = request.form.get('search_term', '')
    search_response = Basestation.query.filter(
        Basestation.basestation_id.ilike(f'%{search_query}%') | Basestation.basestation_id.contains(search_query) |
        Basestation.basestation_name.ilike(f'%{search_query}%') | Basestation.basestation_name.contains(
            search_query.title())
    )
    response = {
        "count": search_response.count(),
        "data": [bsestation.format() for bsestation in search_response.all()]
    }
    print(response)
    return render_template('pages/admin/bsestations.html', response=response, search_term=search_query, current_user=current_user)


@app.route('/basestations/new', methods=['GET', 'POST'])
@login_required
@admin_noc_ip
def add_basestation():
    pass


@app.route('/basestations/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_basestations_csv():
    form = CSVUploadForm()

    if form.validate_on_submit():
        # get the uploaded file
        uploaded_file = form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = []
        csvData = pd.read_csv(file_path, names=col_names, header=None)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                pass
            except:
                pass


@app.route('/basestations/<basestation_id>', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_noc_ip
def update_basestation(basestation_id):
    pass


@app.route('/basestations/<basestation_id>/delete', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_basestation(basestation_id):
    pass


# --------------------------------------------- BASESTATIONS ------------------------------------------->
@app.route('/servers')
@login_required
@admin_and_ip
def get_servers():
    pass


@app.route('/servers/search', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def search_servers():
    search_query = request.form.get('search_term', '')
    search_response = Server.query.filter(
        Server.server_name.ilike(f'%{search_query}%') | Server.server_name.contains(search_query) |
        Server.server_ip.ilike(
            f'%{search_query}%') | Server.server_ip.contains(search_query)
    )
    response = {
        "count": search_response.count(),
        "data": [server.format() for server in search_response.all()]
    }
    print(response)
    return render_template('pages/admin/servers.html', response=response, search_term=search_query, current_user=current_user)


@app.route('/servers/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_server():
    pass


@app.route('/servers/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_servers_csv():
    form = CSVUploadForm()

    if form.validate_on_submit():
        # get the uploaded file
        uploaded_file = form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = []
        csvData = pd.read_csv(file_path, names=col_names, header=None)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                pass
            except:
                pass


@app.route('/servers/<int:server_id>', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_server(server_id):
    pass


@app.route('/servers/<int:server_id>', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_server(server_id):
    pass


# --------------------------------------------- VLANS ------------------------------------------->
@app.route('/vlans')
@login_required
@admin_and_ip
def get_vlans():
    pass


@app.route('/vlans/search', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def search_vlans():
    search_query = request.form.get('search_term', '')
    search_response = Vlan.query.filter(
        Vlan.vlan_id.ilike(f'%{search_query}%') | Vlan.vlan_id.contains(search_query) |
        Vlan.customer_assigned.ilike(
            f'%{search_query}%') | Vlan.customer_assigned.contains(search_query)
    )
    response = {
        "count": search_response.count(),
        "data": [vlan.format() for vlan in search_response.all()]
    }
    print(response)
    return render_template('pages/admin/vlans.html', response=response, search_term=search_query, current_user=current_user)


@app.route('/vlans/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_vlan():
    pass


@app.route('/vlans/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_vlans_csv():
    form = CSVUploadForm()

    if form.validate_on_submit():
        # get the uploaded file
        uploaded_file = form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = []
        csvData = pd.read_csv(file_path, names=col_names, header=None)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                pass
            except:
                pass


@app.route('/vlans/<vlan_id>', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_vlan(vlan_id):
    pass


@app.route('/vlans/<vlan_id>', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_vlan(vlan_id):
    pass


# --------------------------------------------- CONNECTIONS ------------------------------------------->
@app.route('/connections')
@login_required
@admin_and_ip
def get_connections():
    pass


@app.route('/connections/search', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def search_connections():
    search_query = request.form.get('search_term', '')
    search_response = Connection.query.filter(
        Connection.conn_name.ilike(
            f'%{search_query}%') | Connection.conn_name.contains(search_query)
    )
    response = {
        "count": search_response.count(),
        "data": [conn.format() for conn in search_response.all()]
    }
    print(response)
    return render_template('pages/admin/connectiontypes.html', response=response, search_term=search_query, current_user=current_user)


@app.route('/connections/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_connection():
    pass


@app.route('/connections/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_connections_csv():
    form = CSVUploadForm()

    if form.validate_on_submit():
        # get the uploaded file
        uploaded_file = form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = []
        csvData = pd.read_csv(file_path, names=col_names, header=None)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                pass
            except:
                pass


@app.route('/connections/<int:conn_id>', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_connection(conn_id):
    pass


@app.route('/connections/<int:conn_id>', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_connection(conn_id):
    pass


# --------------------------------------------- RADIOS ------------------------------------------->
@app.route('/radios')
@login_required
@admin_and_ip
def get_radios():
    pass


@app.route('/radios/search', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def search_radios():
    search_query = request.form.get('search_term', '')
    search_response = Radio.query.filter(
        Radio.radio_name.ilike(
            f'%{search_query}%') | Radio.radio_name.contains(search_query)
    )
    response = {
        "count": search_response.count(),
        "data": [radio.format() for radio in search_response.all()]
    }
    print(response)
    return render_template('pages/admin/radiotypes.html', response=response, search_term=search_query, current_user=current_user)


@app.route('/radios/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_radio():
    pass


@app.route('/radios/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_radios_csv():
    form = CSVUploadForm()

    if form.validate_on_submit():
        # get the uploaded file
        uploaded_file = form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = []
        csvData = pd.read_csv(file_path, names=col_names, header=None)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                pass
            except:
                pass


@app.route('/radios/<int:radio_id>', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_radio(radio_id):
    pass


@app.route('/radios/<int:radio_id>', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_radio(radio_id):
    pass


# --------------------------------------------- SERVICE TYPES ------------------------------------------->
@app.route('/service-types')
@login_required
@admin_and_ip
def get_sevice_types():
    pass


@app.route('/service-types/search', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def search_sevice_types():
    search_query = request.form.get('search_term', '')
    search_response = ServiceType.query.filter(
        ServiceType.service_name.ilike(
            f'%{search_query}%') | ServiceType.service_name.contains(search_query)
    )
    response = {
        "count": search_response.count(),
        "data": [service.format() for service in search_response.all()]
    }
    print(response)
    return render_template('pages/admin/servicetypes.html', response=response, search_term=search_query, current_user=current_user)


@app.route('/service-types/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_service_type():
    pass


@app.route('/service-types/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_sevice_types_csv():
    form = CSVUploadForm()

    if form.validate_on_submit():
        # get the uploaded file
        uploaded_file = form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = []
        csvData = pd.read_csv(file_path, names=col_names, header=None)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                pass
            except:
                pass


@app.route('/service-types/<int:service_type_id>', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_service_type(service_type_id):
    pass


@app.route('/service-types/<int:service_type_id>', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_service_type(service_type_id):
    pass


# --------------------------------------------- SERVICE PLANS ------------------------------------------->
@app.route('/service-plans')
@login_required
@admin_and_ip
def get_sevice_plans():
    pass


@app.route('/service-plans/search', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def search_sevice_plans():
    search_query = request.form.get('search_term', '')
    search_response = ServicePlan.query.filter(
        ServicePlan.service_plan.ilike(
            f'%{search_query}%') | ServicePlan.service_plan.contains(search_query)
    )
    response = {
        "count": search_response.count(),
        "data": [plan.format() for plan in search_response.all()]
    }
    print(response)
    return render_template('pages/admin/serviceplans.html', response=response, search_term=search_query, current_user=current_user)


@app.route('/service-plans/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_service_plan():
    pass


@app.route('/service-plans/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_sevice_plans_csv():
    form = CSVUploadForm()

    if form.validate_on_submit():
        # get the uploaded file
        uploaded_file = form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = []
        csvData = pd.read_csv(file_path, names=col_names, header=None)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                pass
            except:
                pass


@app.route('/service-plans/<int:service_plan_id>', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_service_plan(service_plan_id):
    pass


@app.route('/service-plans/<int:service_plan_id>', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_service_plan(service_plan_id):
    pass


# --------------------------------------------- SERVICE TYPES ------------------------------------------->


@app.route('/bandwidth-plans')
@login_required
@admin_and_ip
def get_bandwidth_plans():
    pass


@app.route('/bandwidth-plans/search', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def search_bandwidth_plans():
    search_query = request.form.get('search_term', '')
    search_response = BandwidthPlan.query.filter(
        BandwidthPlan.bandwidth_name.ilike(
            f'%{search_query}%') | BandwidthPlan.bandwidth_name.contains(search_query)
    )
    response = {
        "count": search_response.count(),
        "data": [bandwidth.format() for bandwidth in search_response.all()]
    }
    print(response)
    return render_template('pages/admin/bandwidths.html', response=response, search_term=search_query, current_user=current_user)


@app.route('/bandwidth-plans/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_bandwidth_plan():
    pass


@app.route('/bandwidth-plans/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_bandwidth_plans_csv():
    form = CSVUploadForm()

    if form.validate_on_submit():
        # get the uploaded file
        uploaded_file = form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = []
        csvData = pd.read_csv(file_path, names=col_names, header=None)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                pass
            except:
                pass


@app.route('/bandwidth-plans/<int:bandwidth_plan_id>', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_bandwidth_plan(bandwidth_plan_id):
    pass


@app.route('/bandwidth-plans/<int:bandwidth_plan_id>', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_bandwidth_plan(bandwidth_plan_id):
    pass


# --------------------------------------------- RADIOS ------------------------------------------->
@app.route('/cpes')
@login_required
@admin_and_ip
def get_cpes():
    pass


@app.route('/cpes/search', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def search_cpes():
    search_query = request.form.get('search_term', '')
    search_response = CPE.query.filter(
        CPE.cpe_name.ilike(
            f'%{search_query}%') | CPE.cpe_name.contains(search_query)
    )
    response = {
        "count": search_response.count(),
        "data": [cpe.format() for cpe in search_response.all()]
    }
    print(response)
    return render_template('pages/admin/cpetypes.html', response=response, search_term=search_query, is_search=True, current_user=current_user)


@app.route('/cpes/new', methods=['GET', 'POST'])
@login_required
@admin_and_ip
def add_cpe():
    pass


@app.route('/cpes/upload', methods=['GET', 'POST'])
@login_required
@admin_only
def upload_cpes_csv():
    form = CSVUploadForm()

    if form.validate_on_submit():
        # get the uploaded file
        uploaded_file = form.file.data

        filename = secure_filename(uploaded_file.filename)

        # set the file path
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        # save the file
        uploaded_file.save(file_path)

        # Use Pandas to parse the CSV file
        col_names = []
        csvData = pd.read_csv(file_path, names=col_names, header=None)
        # Loop through the Rows
        for i, row in csvData.iterrows():
            try:
                pass
            except:
                pass


@app.route('/cpes/<int:cpe_id>', methods=['GET', 'POST', 'PATCH'])
@login_required
@admin_and_ip
def update_cpe(cpe_id):
    pass


@app.route('/cpes/<int:cpe_id>', methods=['GET', 'DELETE'])
@login_required
@admin_and_ip
def delete_cpe(cpe_id):
    pass


'''
Error Handlers
'''


@app.errorhandler(400)
def bad_request(error):
    error = jsonify({
        "success": False,
        "error": 400,
        "message": "It seems you have made a bad request."
    })

    return render_template('pages/error.html', response=error, current_user=current_user)


@app.errorhandler(401)
def lacks_valid_authentication(error):
    return redirect(url_for('login'))


@app.errorhandler(403)
def unauthorized(error):
    error = jsonify({
        "success": False,
        "error": 403,
        "message": "You are not authorized to access this url."
    })

    return render_template('pages/error.html', response=error, current_user=current_user)


@app.errorhandler(404)
def not_found(error):
    error = jsonify({
        "success": False,
        "error": 404,
        "message": "The resource you have requested cannot be found."
    })

    return render_template('pages/error.html', response=error, current_user=current_user)


@app.errorhandler(405)
def method_not_allowed(error):
    error = jsonify({
        "success": False,
        "error": 405,
        "message": "This method is not allowed for the requested url."
    })

    return render_template('pages/error.html', response=error, current_user=current_user)


@app.errorhandler(422)
def unprocessable(error):
    error = jsonify({
        "success": False,
        "error": 422,
        "message": "Your request could not be processed. Try again."
    })

    return render_template('pages/error.html', response=error, current_user=current_user)


@app.errorhandler(500)
def server_error(error):
    error = jsonify({
        "success": False,
        "error": 500,
        "message": "We're sorry, something went wrong on our end. Please try again."
    })

    return render_template('pages/error.html', response=error, current_user=current_user)


if __name__ == '__main__':
    app.run(debug=True)

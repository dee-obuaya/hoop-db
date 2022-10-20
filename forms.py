import json
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileAllowed, FileRequired
from wtforms import DateField, DateTimeField, StringField, SelectField
from wtforms.validators import DataRequired, Email, InputRequired


class JSONField(StringField):
    def _value(self):
        return json.dumps(self.data) if self.data else ''

    def process_formdata(self, valuelist):
        if valuelist:
            try:
                self.data = json.loads(valuelist[0])
            except ValueError:
                raise ValueError('This field contains incorrect JSON')
        else:
            self.data = None

    def pre_validate(self, form):
        super().pre_validate(form)
        if self.data:
            try:
                json.dumps(self.data)
            except TypeError:
                raise ValueError('This field contains invalid JSON')


class CSVUploadForm(FlaskForm):
    file = FileField('file', validators=[
                     FileRequired(), FileAllowed(['csv'], 'CSV files only!')])


class UserForm(FlaskForm):
    username = StringField('username', validators=[
                           DataRequired(), InputRequired()])
    password = StringField('password', validators=[
                           DataRequired(), InputRequired()])
    department = SelectField('department', choices=[('IP', 'IP'), ('NOC', 'NOC'), (
        'Technical Support', 'Technical Support'), ('Service Management', 'Seervice Management')], validators=[DataRequired()])
    privileges = SelectField('privileges', choices=[(
        'Admin', 'Admin'), ('Default', 'Default')], validators=[DataRequired()])


class PartnerForm(FlaskForm):
    partner_id = StringField('partner_id', validators=[DataRequired()])
    partner_name = StringField('partner_name', validators=[DataRequired()])
    partner_contact = StringField(
        'partner_contact', validators=[DataRequired()])
    partner_address = StringField(
        'partner_address', validators=[DataRequired()])


class BasestationForm(FlaskForm):
    basestation_id = StringField('basestation_id', validators=[DataRequired()])
    basestation_name = StringField(
        'basestation_name', validators=[DataRequired()])
    basestation_location = StringField(
        'basestation_location', validators=[DataRequired()])
    basestation_contact = StringField(
        'basestation_contact', validators=[DataRequired()])


class ServerForm(FlaskForm):
    server_name = StringField('server_name', validators=[
                              DataRequired(), InputRequired()])
    server_ip = StringField('server_ip', validators=[
                            DataRequired(), InputRequired()])
    server_location = StringField('server_location', validators=[
                                  DataRequired(), InputRequired()])


class VlanForm(FlaskForm):
    vlan_id = StringField('vlan_id', validators=[DataRequired()])
    customer_assigned = StringField(
        'customer_assigned', validators=[DataRequired()])


class ConnectionForm(FlaskForm):
    conn_name = StringField('conn_name', validators=[
                            DataRequired(), InputRequired()])
    conn_desc = StringField('conn_desc')


class RadioForm(FlaskForm):
    radio_name = StringField('radio_name', validators=[
                             DataRequired(), InputRequired()])


class ServiceTypeForm(FlaskForm):
    service_name = StringField('service_name', validators=[
                               DataRequired(), InputRequired()])
    service_desc = StringField('service_desc')


class ServicePlanForm(FlaskForm):
    service_plan = StringField('service_plan', validators=[
                               DataRequired(), InputRequired()])
    service_desc = StringField('service_desc')


class BandwidthPlanForm(FlaskForm):
    bandwidth_name = StringField('bandwidth_name', validators=[
                                 DataRequired(), InputRequired()])


class CPEForm(FlaskForm):
    cpe_name = StringField('cpe_name', validators=[
                           DataRequired(), InputRequired()])


class CustomerForm(FlaskForm):
    customer_name = StringField('customer_name', validators=[
                                DataRequired()])
    customer_code = StringField('customer_code', validators=[
                                DataRequired()])
    customer_status = SelectField('customer_status',
                                  choices=[('New Provision', 'New Provision'),
                                           ('Active Enabled', 'Active Enabled'),
                                           ('Active Suspended',
                                            'Active Suspended'),
                                           ('Active Disconnected',
                                            'Active Disconnected'),
                                           ('Churned', 'Churned'),
                                           ('Closed', 'Closed')]
                                  )
    customer_server = SelectField('customer_server')
    customer_conn_type = SelectField('customer_conn_type')
    customer_location = SelectField(
        'customer_location',
        choices=[
            ('Abia', 'Abia'),
            ('Abuja', 'Abuja'),
            ('Adamawa', 'Adamawa'),
            ('Akwa Ibom', 'Akwa Ibom'),
            ('Anambra', 'Anambra'),
            ('Bauchi', 'Bauchi'),
            ('Bayelsa', 'Bayelsa'),
            ('Benue', 'Benue'),
            ('Borno', 'Borno'),
            ('Cross River', 'Cross River'),
            ('Delta', 'Delta'),
            ('Ebonyi', 'Ebonyi'),
            ('Edo', 'Edo'),
            ('Ekiti', 'Ekiti'),
            ('Enugu', 'Enugu'),
            ('Gombe', 'Gombe'),
            ('Imo', 'Imo'),
            ('Jigawa', 'Jigawa'),
            ('Kaduna', 'Kaduna'),
            ('Kano', 'Kano'),
            ('Katsina', 'Katsina'),
            ('Kebbi', 'Kebbi'),
            ('Kogi', 'Kogi'),
            ('Kwara', 'Kwara'),
            ('Lagos', 'Lagos'),
            ('Nasarawa', 'Nasawara'),
            ('Niger', 'Niger'),
            ('Ogun', 'Ogun'),
            ('Ondo', 'Ondo'),
            ('Osun', 'Osun'),
            ('Plateau', 'Plateau'),
            ('Rivers', 'Rivers'),
            ('Sokoto', 'Sokoto'),
            ('Taraba', 'Taraba'),
            ('Yobe', 'Yobe'),
            ('Zamfara', 'Zamfara')
        ]
    )
    customer_partner = SelectField('customer_partner')
    customer_basestation_location = StringField(
        'customer_basestation_location')
    customer_basestation_id = SelectField('customer_basestation_id')
    customer_sector = StringField('customer_sector')
    customer_switch = StringField('customer_switch')
    customer_management_vlan = StringField('customer_management_vlan')
    customer_traffic_vlan = StringField('customer_traffic_vlan')
    customer_subnet = SelectField(
        'customer_subnet',
        choices=[('255.255.255.0/24', '255.255.255.0/24'),
                 ('255.255.255.128/25', '255.255.255.128/25'),
                 ('255.255.255.192/26', '255.255.255.192/26'),
                 ('255.255.255.224/27', '255.255.255.224/27'),
                 ('255.255.255.240/28', '255.255.255.240/28'),
                 ('255.255.255.248/29', '255.255.255.248/29'),
                 ('255.255.255.252/30', '255.255.255.252/30'),
                 ('255.255.255.252/32', '255.255.255.252/32'), ]
    )
    customer_mu_ip = StringField('customer_mu_ip')
    customer_su_ip = StringField('customer_su_ip')
    customer_ssid = StringField('customer_ssid')
    customer_channel_width = StringField('customer_channel_width')
    customer_frequency = StringField('customer_frequency')
    customer_mu_mac_id = StringField('customer_mu_mac_id')
    customer_su_mac_id = StringField('customer_su_mac_id')
    customer_rssi_ccq_airmax = StringField('customer_rssi_ccq_airmax')
    customer_radio_type = SelectField('customer_radio_type')
    customer_cpe = SelectField('customer_cpe')
    customer_provider_edge_router = StringField(
        'customer_provider_edge_router')
    customer_wan_ip = StringField('customer_wan_ip')
    customer_wan_subnet = StringField('customer_wan_subnet')
    customer_wan_gateway = StringField('customer_wan_gateway')
    customer_wan_routing_protocol = StringField(
        'customer_wan_routing_protocol')
    customer_ip = StringField('customer_ip')
    customer_subnet_mask = SelectField(
        'customer_subnet_mask',
        choices=[('255.255.255.0/24', '255.255.255.0/24'),
                 ('255.255.255.128/25', '255.255.255.128/25'),
                 ('255.255.255.192/26', '255.255.255.192/26'),
                 ('255.255.255.224/27', '255.255.255.224/27'),
                 ('255.255.255.240/28', '255.255.255.240/28'),
                 ('255.255.255.248/29', '255.255.255.248/29'),
                 ('255.255.255.252/30', '255.255.255.252/30'),
                 ('255.255.255.252/32', '255.255.255.252/32'), ]
    )
    customer_gateway = StringField('customer_gateway')
    customer_service_type = SelectField('customer_service_type')
    customer_service_plan = SelectField('customer_service_plan')
    customer_bandwidth_plan = SelectField('customer_bandwidth_plan')
    customer_wifi_ssid = StringField('customer_wifi_ssid')
    customer_wifi_password = StringField('customer_wifi_password')
    customer_installation_date = DateField('customer_installation_date')
    customer_activation_date = DateField('customer_activation_date')
    customer_installation_engineer = StringField(
        'customer_installation_engineer')
    customer_contact_person = StringField('customer_contact_person')
    customer_phone_number = StringField('customer_phone_number')
    customer_email = StringField('customer_email', validators=[Email()])
    customer_physical_address = StringField('customer_physical_address')


class CustomerPasswordForm(FlaskForm):
    customer_name = StringField('customer_name', validators=[DataRequired()])
    customer_code = StringField('customer_code', validators=[DataRequired()])
    customer_device_type = StringField('customer_device_type')
    customer_device_ip = StringField('customer_device_ip')
    customer_username = StringField(
        'customer_username', validators=[DataRequired()])
    customer_password = StringField(
        'customer_password', validators=[DataRequired()])


class CustomerPRTGForm(FlaskForm):
    customer_name = StringField('customer_name', validators=[DataRequired()])
    customer_code = StringField('customer_code', validators=[DataRequired()])
    customer_username = StringField(
        'customer_username', validators=[DataRequired()])
    customer_password = StringField(
        'customer_password', validators=[DataRequired()])


class LinkActivationTrackerForm(FlaskForm):
    customer_name = StringField('customer_name', validators=[DataRequired()])
    customer_code = StringField('customer_code', validators=[DataRequired()])
    customer_basestation_id = SelectField(
        'customer_basestation_id', validators=[DataRequired()])
    customer_service_desc = StringField(
        'customer_service_desc', validators=[DataRequired()])
    customer_request_date = DateField(
        'customer_request_date', validators=[DataRequired()])
    customer_link_completion_date = DateField(
        'customer_link_completion_date', validators=[DataRequired()])
    customer_implemented_by = StringField(
        'customer_implemented_by', validators=[DataRequired()])


class ChangeImplementationTrackerForm(FlaskForm):
    customer_name = StringField('customer_name', validators=[DataRequired()])
    customer_code = StringField('customer_code', validators=[DataRequired()])
    customer_change_id = StringField(
        'customer_change_id', validators=[DataRequired()])
    customer_change_desc = StringField(
        'customer_change_desc', validators=[DataRequired()])
    customer_change_type = SelectField(
        'customer_change_type', choices=[(
            'Temporary', 'Temporary'), ('Permanent', 'Permanent')], validators=[DataRequired()])
    customer_instructed_by = StringField(
        'customer_instructed_by', validators=[DataRequired()])
    customer_approved_by = StringField(
        'customer_approved_by', validators=[DataRequired()])
    customer_request_date = DateField(
        'customer_request_date', validators=[DataRequired()])
    customer_implementation_date_and_time = DateTimeField(
        'customer_implementation_date_and_time', validators=[DataRequired()])
    customer_implemented_by = StringField(
        'customer_implemented_by', validators=[DataRequired()])
    customer_status = SelectField('customer_status', choices=[(
        'Ongoing', 'Ongoing'), ('Pending', 'Pending'), ('Done', 'Done')], validators=[DataRequired()])

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import date, datetime

db = SQLAlchemy()


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(), unique=True)
    password = db.Column(db.LargeBinary(), nullable=False)
    department = db.Column(db.String(), nullable=False)
    privileges = db.Column(db.String(), nullable=False)

    def __init__(self, username, password, department, privileges):
        self.username = username
        self.password = password
        self.department = department
        self.privileges = privileges

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'username': self.username,
            'password': self.password,
            'department': self.department,
            'privileges': self.privileges
        }

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'password': self.password,
            'department': self.department,
            'privileges': self.privileges
        }


class Partner(db.Model):
    __tablename__ = 'partners'
    id = db.Column(db.Integer, primary_key=True)
    partner_id = db.Column(db.String(), unique=True)
    partner_name = db.Column(db.String(), nullable=False)
    partner_contact = db.Column(db.String())
    partner_address = db.Column(db.String())

    def __init__(self, partner_id, partner_name, partner_contact, partner_address):
        self.partner_id = partner_id
        self.partner_name = partner_name
        self.partner_contact = partner_contact
        self.partner_address = partner_address

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'partner_id': self.partner_id,
            'partner_name': self.partner_name,
            'partner_contact': self.partner_contact,
            'partner_address': self.partner_address
        }

    def to_dict(self):
        return {
            'id': self.id,
            'partner_id': self.partner_id,
            'partner_name': self.partner_name,
            'partner_contact': self.partner_contact,
            'partner_address': self.partner_address
        }


class Basestation(db.Model):
    __tablename__ = 'basestations'
    id = db.Column(db.Integer, primary_key=True)
    basestation_id = db.Column(db.String(), unique=True)
    basestation_name = db.Column(db.String(), nullable=False)
    basestation_location = db.Column(db.String())
    basestation_contact = db.Column(db.String())

    def __init__(self, basestation_id, basestation_name, basestation_location, basestation_contact):
        self.basestation_id = basestation_id
        self.basestation_name = basestation_name
        self.basestation_location = basestation_location
        self.basestation_contact = basestation_contact

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'basestation_id': self.basestation_id,
            'basestation_name': self.basestation_name,
            'basestation_location': self.basestation_location,
            'basestation_contact': self.basestation_contact
        }

    def to_dict(self):
        return {
            'id': self.id,
            'basestation_id': self.basestation_id,
            'basestation_name': self.basestation_name,
            'basestation_location': self.basestation_location,
            'basestation_contact': self.basestation_contact
        }


class Server(db.Model):
    __tablename__ = 'servers'
    id = db.Column(db.Integer, primary_key=True)
    server_name = db.Column(db.String(), unique=True, nullable=False)
    server_ip = db.Column(db.String(), unique=True, nullable=False)
    server_location = db.Column(db.String())

    def __init__(self, server_name, server_ip, server_location):
        self.server_name = server_name
        self.server_ip = server_ip
        self.server_location = server_location

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'server_name': self.server_name,
            'server_ip': self.server_ip,
            'server_location': self.server_location
        }

    def to_dict(self):
        return {
            'id': self.id,
            'server_name': self.server_name,
            'server_ip': self.server_ip,
            'server_location': self.server_location
        }


class Vlan(db.Model):
    __tablename__ = 'vlans'
    id = db.Column(db.Integer, primary_key=True)
    vlan_id = db.Column(db.String(), nullable=False)
    customer_assigned = db.Column(db.String())

    def __init__(self, vlan_id, customer_assigned):
        self.vlan_id = vlan_id
        self.customer_assigned = customer_assigned

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'vlan_id': self.vlan_id,
            'customer_assigned': self.customer_assigned
        }

    def to_dict(self):
        return {
            'id': self.id,
            'vlan_id': self.vlan_id,
            'customer_assigned': self.customer_assigned
        }


class Connection(db.Model):
    __tablename__ = 'connections'
    id = db.Column(db.Integer, primary_key=True)
    conn_name = db.Column(db.String(), unique=True, nullable=False)
    conn_desc = db.Column(db.String())

    def __init__(self, conn_name, conn_desc):
        self.conn_name = conn_name
        self.conn_desc = conn_desc

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'conn_name': self.conn_name,
            'conn_desc': self.conn_desc
        }

    def to_dict(self):
        return {
            'id': self.id,
            'conn_name': self.conn_name,
            'conn_desc': self.conn_desc
        }


class Radio(db.Model):
    __tablename__ = 'radios'
    id = db.Column(db.Integer, primary_key=True)
    radio_name = db.Column(db.String(), unique=True, nullable=False)

    def __init__(self, radio_name):
        self.radio_name = radio_name

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'radio_name': self.radio_name
        }

    def to_dict(self):
        return {
            'id': self.id,
            'radio_name': self.radio_name
        }


class ServiceType(db.Model):
    __tablename__ = 'servicetypes'
    id = db.Column(db.Integer, primary_key=True)
    service_name = db.Column(db.String(), unique=True, nullable=False)
    service_desc = db.Column(db.String())

    def __init__(self, service_name, service_desc):
        self.service_name = service_name
        self.service_desc = service_desc

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'service_name': self.service_name,
            'service_desc': self.service_desc
        }

    def to_dict(self):
        return {
            'id': self.id,
            'service_name': self.service_name,
            'service_desc': self.service_desc
        }


class ServicePlan(db.Model):
    __tablename__ = 'serviceplans'
    id = db.Column(db.Integer, primary_key=True)
    service_plan = db.Column(db.String(), unique=True, nullable=False)
    service_desc = db.Column(db.String())

    def __init__(self, service_plan, service_desc):
        self.service_plan = service_plan
        self.service_desc = service_desc

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'service_plan': self.service_plan,
            'service_desc': self.service_desc
        }

    def to_dict(self):
        return {
            'id': self.id,
            'service_plan': self.service_plan,
            'service_desc': self.service_desc
        }


class BandwidthPlan(db.Model):
    __tablename__ = 'bandwidths'
    id = db.Column(db.Integer, primary_key=True)
    bandwidth_name = db.Column(db.String(), unique=True, nullable=False)

    def __init__(self, bandwidth_name):
        self.bandwidth_name = bandwidth_name

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'bandwidth_name': self.bandwidth_name,
        }

    def to_dict(self):
        return {
            'id': self.id,
            'bandwidth_name': self.bandwidth_name,
        }


class CPE(db.Model):
    __tablename__ = 'cpes'
    id = db.Column(db.Integer, primary_key=True)
    cpe_name = db.Column(db.String(), unique=True, nullable=False)

    def __init__(self, cpe_name):
        self.cpe_name = cpe_name

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'cpe_name': self.cpe_name,
        }

    def to_dict(self):
        return {
            'id': self.id,
            'cpe_name': self.cpe_name,
        }


class Customer(db.Model):
    __tablename__ = 'customers'
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(), unique=True, nullable=False)
    customer_code = db.Column(db.String(), unique=True, nullable=False)
    customer_status = db.Column(db.String())
    customer_server = db.Column(db.String())
    customer_conn_type = db.Column(db.String())
    customer_location = db.Column(db.String())
    customer_partner = db.Column(db.String())
    customer_basestation_location = db.Column(db.String())
    customer_basestation_id = db.Column(db.String())
    customer_sector = db.Column(db.String())
    customer_switch = db.Column(db.String())
    customer_management_vlan = db.Column(db.String())
    customer_traffic_vlan = db.Column(db.String())
    customer_subnet = db.Column(db.String())
    customer_mu_ip = db.Column(db.String())
    customer_su_ip = db.Column(db.String())
    customer_ssid = db.Column(db.String())
    customer_channel_width = db.Column(db.String())
    customer_frequency = db.Column(db.String())
    customer_mu_mac_id = db.Column(db.String())
    customer_su_mac_id = db.Column(db.String())
    customer_rssi_ccq_airmax = db.Column(db.String())
    customer_radio_type = db.Column(db.String())
    customer_cpe = db.Column(db.String())
    customer_provider_edge_router = db.Column(db.String())
    customer_wan_ip = db.Column(db.String())
    customer_wan_subnet = db.Column(db.String())
    customer_wan_gateway = db.Column(db.String())
    customer_wan_routing_protocol = db.Column(db.String())
    customer_ip = db.Column(db.String())
    customer_subnet_mask = db.Column(db.String())
    customer_gateway = db.Column(db.String())
    customer_service_type = db.Column(db.String())
    customer_service_plan = db.Column(db.String())
    customer_bandwidth_plan = db.Column(db.String())
    customer_wifi_ssid = db.Column(db.String())
    customer_wifi_password = db.Column(db.LargeBinary())
    customer_installation_date = db.Column(db.Date, nullable=False, default=date.today())
    customer_activation_date = db.Column(db.Date, nullable=False, default=date.today())
    customer_installation_engineer = db.Column(db.String())
    customer_contact_person = db.Column(db.String())
    customer_phone_number = db.Column(db.String())
    customer_email = db.Column(db.String())
    customer_physical_address = db.Column(db.String())

    customerpassword = db.relationship(
        'CustomerPassword', backref=db.backref('customerspassword', uselist=False))
    customerprtg = db.relationship(
        'CustomerPRTG', backref=db.backref('customersprtg', uselist=False))
    linkactivationtracker = db.relationship(
        'LinkActivationTracker', backref='linkactivationtrackers')
    changeimplementationtracker = db.relationship(
        'ChangeImplementationTracker', backref='changeimplementationtrackers')

    def __init__(self, customer_name, customer_code, customer_status, customer_server, customer_conn_type, customer_location, customer_partner, customer_basestation_location, customer_basestation_id, customer_sector, customer_switch, customer_management_vlan, customer_traffic_vlan, customer_subnet, customer_mu_ip, customer_su_ip, customer_ssid, customer_channel_width, customer_frequency, customer_mu_mac_id, customer_su_mac_id, customer_rssi_ccq_airmax, customer_radio_type, customer_cpe, customer_provider_edge_router, customer_wan_ip, customer_wan_subnet, customer_wan_gateway, customer_wan_routing_protocol, customer_ip, customer_subnet_mask, customer_gateway, customer_service_type, customer_service_plan, customer_bandwidth_plan, customer_wifi_ssid, customer_wifi_password, customer_installation_date, customer_activation_date, customer_installation_engineer, customer_contact_person, customer_phone_number, customer_email, customer_physical_address):
        self.customer_name = customer_name
        self.customer_code = customer_code
        self.customer_status = customer_status
        self.customer_server = customer_server
        self.customer_conn_type = customer_conn_type
        self.customer_location = customer_location
        self.customer_partner = customer_partner
        self.customer_basestation_location = customer_basestation_location
        self.customer_basestation_id = customer_basestation_id
        self.customer_sector = customer_sector
        self.customer_switch = customer_switch
        self.customer_management_vlan = customer_management_vlan
        self.customer_traffic_vlan = customer_traffic_vlan
        self.customer_subnet = customer_subnet
        self.customer_mu_ip = customer_mu_ip
        self.customer_su_ip = customer_su_ip
        self.customer_ssid = customer_ssid
        self.customer_channel_width = customer_channel_width
        self.customer_frequency = customer_frequency
        self.customer_mu_mac_id = customer_mu_mac_id
        self.customer_su_mac_id = customer_su_mac_id
        self.customer_rssi_ccq_airmax = customer_rssi_ccq_airmax
        self.customer_radio_type = customer_radio_type
        self.customer_cpe = customer_cpe
        self.customer_provider_edge_router = customer_provider_edge_router
        self.customer_wan_ip = customer_wan_ip
        self.customer_wan_subnet = customer_wan_subnet
        self.customer_wan_gateway = customer_wan_gateway
        self.customer_wan_routing_protocol = customer_wan_routing_protocol
        self.customer_ip = customer_ip
        self.customer_subnet_mask = customer_subnet_mask
        self.customer_gateway = customer_gateway
        self.customer_service_type = customer_service_type
        self.customer_service_plan = customer_service_plan
        self.customer_bandwidth_plan = customer_bandwidth_plan
        self.customer_wifi_ssid = customer_wifi_ssid
        self.customer_wifi_password = customer_wifi_password
        self.customer_installation_date = customer_installation_date
        self.customer_activation_date = customer_activation_date
        self.customer_installation_engineer = customer_installation_engineer
        self.customer_contact_person = customer_contact_person
        self.customer_phone_number = customer_phone_number
        self.customer_email = customer_email
        self.customer_physical_address = customer_physical_address

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_code': self.customer_code,
            'customer_status': self.customer_status,
            'customer_server': self.customer_server,
            'customer_conn_type': self.customer_conn_type,
            'customer_location': self.customer_location,
            'customer_partner': self.customer_partner,
            'customer_basestation_location': self.customer_basestation_location,
            'customer_basestation_id': self.customer_basestation_id,
            'customer_sector': self.customer_sector,
            'customer_switch': self.customer_switch,
            'customer_management_vlan': self.customer_management_vlan,
            'customer_traffic_vlan': self.customer_traffic_vlan,
            'customer_subnet': self.customer_subnet,
            'customer_mu_ip': self.customer_mu_ip,
            'customer_su_ip': self.customer_su_ip,
            'customer_ssid': self.customer_ssid,
            'customer_channel_width': self.customer_channel_width,
            'customer_frequency': self.customer_frequency,
            'customer_mu_mac_id': self.customer_mu_mac_id,
            'customer_su_mac_id': self.customer_su_mac_id,
            'customer_rssi_ccq_airmax': self.customer_rssi_ccq_airmax,
            'customer_radio_type': self.customer_radio_type,
            'customer_cpe': self.customer_cpe,
            'customer_provider_edge_router': self.customer_provider_edge_router,
            'customer_wan_ip': self.customer_wan_ip,
            'customer_wan_subnet': self.customer_wan_subnet,
            'customer_wan_gateway': self.customer_wan_gateway,
            'customer_wan_routing_protocol': self.customer_wan_routing_protocol,
            'customer_ip': self.customer_ip,
            'customer_subnet_mask': self.customer_subnet_mask,
            'customer_gateway': self.customer_gateway,
            'customer_service_type': self.customer_service_type,
            'customer_service_plan': self.customer_service_plan,
            'customer_bandwidth_plan': self.customer_bandwidth_plan,
            'customer_wifi_ssid': self.customer_wifi_ssid,
            'customer_wifi_password': self.customer_wifi_password,
            'customer_installation_date': self.customer_installation_date,
            'customer_activation_date': self.customer_activation_date,
            'customer_installation_enginner': self.customer_installation_engineer,
            'customer_contact_person': self.customer_contact_person,
            'customer_phone_number': self.customer_phone_number,
            'customer_email': self.customer_email,
            'customer_physical_address': self.customer_physical_address
        }

    def to_dict(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_code': self.customer_code,
            'customer_status': self.customer_status,
            'customer_server': self.customer_server,
            'customer_conn_type': self.customer_conn_type,
            'customer_location': self.customer_location,
            'customer_partner': self.customer_partner,
            'customer_basestation_location': self.customer_basestation_location,
            'customer_basestation_id': self.customer_basestation_id,
            'customer_sector': self.customer_sector,
            'customer_switch': self.customer_switch,
            'customer_management_vlan': self.customer_management_vlan,
            'customer_traffic_vlan': self.customer_traffic_vlan,
            'customer_subnet': self.customer_subnet,
            'customer_mu_ip': self.customer_mu_ip,
            'customer_su_ip': self.customer_su_ip,
            'customer_ssid': self.customer_ssid,
            'customer_channel_width': self.customer_channel_width,
            'customer_frequency': self.customer_frequency,
            'customer_mu_mac_id': self.customer_mu_mac_id,
            'customer_su_mac_id': self.customer_su_mac_id,
            'customer_rssi_ccq_airmax': self.customer_rssi_ccq_airmax,
            'customer_radio_type': self.customer_radio_type,
            'customer_cpe': self.customer_cpe,
            'customer_provider_edge_router': self.customer_provider_edge_router,
            'customer_wan_ip': self.customer_wan_ip,
            'customer_wan_subnet': self.customer_wan_subnet,
            'customer_wan_gateway': self.customer_wan_gateway,
            'customer_wan_routing_protocol': self.customer_wan_routing_protocol,
            'customer_ip': self.customer_ip,
            'customer_subnet_mask': self.customer_subnet_mask,
            'customer_gateway': self.customer_gateway,
            'customer_service_type': self.customer_service_type,
            'customer_service_plan': self.customer_service_plan,
            'customer_bandwidth_plan': self.customer_bandwidth_plan,
            'customer_wifi_ssid': self.customer_wifi_ssid,
            'customer_wifi_password': self.customer_wifi_password,
            'customer_installation_date': self.customer_installation_date,
            'customer_activation_date': self.customer_activation_date,
            'customer_installation_enginner': self.customer_installation_engineer,
            'customer_contact_person': self.customer_contact_person,
            'customer_phone_number': self.customer_phone_number,
            'customer_email': self.customer_email,
            'customer_physical_address': self.customer_physical_address
        }


class CustomerPassword(db.Model):
    __tablename__ = 'customerspassword'
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(), nullable=False)
    customer_code = db.Column(
        db.String(), db.ForeignKey('customers.customer_code'))
    customer_device_type = db.Column(db.String())
    customer_device_ip = db.Column(db.String())
    customer_username = db.Column(db.String(), unique=True)
    customer_password = db.Column(db.LargeBinary())

    def __init__(self, customer_name, customer_code, customer_device_type, customer_device_ip, customer_username, customer_password):
        self.customer_name = customer_name
        self.customer_code = customer_code
        self.customer_device_type = customer_device_type
        self.customer_device_ip = customer_device_ip
        self.customer_username = customer_username
        self.customer_password = customer_password

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_code': self.customer_code,
            'customer_device_type': self.customer_device_type,
            'customer_device_ip': self.customer_device_ip,
            'customer_username': self.customer_username,
            'customer_password': self.customer_password
        }

    def to_dict(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_code': self.customer_code,
            'customer_device_type': self.customer_device_type,
            'customer_device_ip': self.customer_device_ip,
            'customer_username': self.customer_username,
            'customer_password': self.customer_password
        }


class CustomerPRTG(db.Model):
    __tablename__ = 'customersprtg'
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String(), nullable=False)
    customer_code = db.Column(
        db.String(), db.ForeignKey('customers.customer_code'))
    customer_username = db.Column(db.String(), unique=True)
    customer_password = db.Column(db.LargeBinary())

    def __init__(self, customer_name, customer_code, customer_username, customer_password):
        self.customer_name = customer_name
        self.customer_code = customer_code
        self.customer_username = customer_username
        self.customer_password = customer_password

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_code': self.customer_code,
            'customer_username': self.customer_username,
            'customer_password': self.customer_password
        }

    def to_dict(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_code': self.customer_code,
            'customer_username': self.customer_username,
            'customer_password': self.customer_password
        }


class LinkActivationTracker(db.Model):
    __tablename__ = 'linkactivationtrackers'
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String())
    customer_code = db.Column(
        db.String(), db.ForeignKey('customers.customer_code'))
    customer_basestation_id = db.Column(db.String())
    customer_service_desc = db.Column(db.String())
    customer_request_date = db.Column(db.Date, default=date.today())
    customer_link_completion_date = db.Column(
        db.Date, default=date.today())
    customer_implemented_by = db.Column(db.String())

    def __init__(self, customer_name, customer_code, customer_basestation_id, customer_service_desc, customer_request_date, customer_link_completion_date, customer_implemented_by):
        self.customer_name = customer_name
        self.customer_code = customer_code
        self.customer_basestation_id = customer_basestation_id
        self.customer_service_desc = customer_service_desc
        self.customer_request_date = customer_request_date
        self.customer_link_completion_date = customer_link_completion_date
        self.customer_implemented_by = customer_implemented_by

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_code': self.customer_code,
            'customer_basestation_id': self.customer_basestation_id,
            'customer_service_desc': self.customer_service_desc,
            'customer_request_date': self.customer_request_date,
            'customer_link_completion_date': self.customer_link_completion_date,
            'customer_implemented_by': self.customer_implemented_by
        }

    def to_dict(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_code': self.customer_code,
            'customer_basestation_id': self.customer_basestation_id,
            'customer_service_desc': self.customer_service_desc,
            'customer_request_date': self.customer_request_date,
            'customer_link_completion_date': self.customer_link_completion_date,
            'customer_implemented_by': self.customer_implemented_by
        }


class ChangeImplementationTracker(db.Model):
    __tablename__ = 'changeimplementationtrackers'
    id = db.Column(db.Integer, primary_key=True)
    customer_name = db.Column(db.String())
    customer_code = db.Column(
        db.String(), db.ForeignKey('customers.customer_code'))
    customer_change_id = db.Column(db.String(), unique=True)
    customer_change_desc = db.Column(db.String())
    customer_change_type = db.Column(db.String())
    customer_instructed_by = db.Column(db.String())
    customer_approved_by = db.Column(db.String())
    customer_request_date = db.Column(db.Date, default=date.today())
    customer_implementation_date_and_time = db.Column(db.DateTime, default=datetime.today())
    customer_implemented_by = db.Column(db.String())
    customer_status = db.Column(db.String())

    def __init__(self, customer_name, customer_code, customer_change_id, customer_change_desc, customer_change_type, customer_instructed_by, customer_approved_by, customer_request_date, customer_implementation_date_and_time, customer_implemented_by, customer_status):
        self.customer_name = customer_name
        self.customer_code = customer_code
        self.customer_change_id = customer_change_id
        self.customer_change_desc = customer_change_desc
        self.customer_change_type = customer_change_type
        self.customer_instructed_by = customer_instructed_by
        self.customer_approved_by = customer_approved_by
        self.customer_request_date = customer_request_date
        self.customer_implementation_date_and_time = customer_implementation_date_and_time
        self.customer_implemented_by = customer_implemented_by
        self.customer_status = customer_status

    def insert(self):
        db.session.add(self)
        db.session.commit()

    def update(self):
        db.session.commit()

    def delete(self):
        db.session.delete(self)
        db.session.commit()

    def format(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_code': self.customer_code,
            'customer_change_id': self.customer_change_id,
            'customer_change_desc': self.customer_change_desc,
            'customer_change_type': self.customer_change_type,
            'customer_instructed_by': self.customer_instructed_by,
            'customer_approved_by': self.customer_approved_by,
            'customer_request_date': self.customer_request_date,
            'customer_implementation_date_and_time': self.customer_implementation_date_and_time,
            'customer_implemented_by': self.customer_implemented_by,
            'customer_status': self.customer_status
        }

    def to_dict(self):
        return {
            'id': self.id,
            'customer_name': self.customer_name,
            'customer_code': self.customer_code,
            'customer_change_id': self.customer_change_id,
            'customer_change_desc': self.customer_change_desc,
            'customer_change_type': self.customer_change_type,
            'customer_instructed_by': self.customer_instructed_by,
            'customer_approved_by': self.customer_approved_by,
            'customer_request_date': self.customer_request_date,
            'customer_implementation_date_and_time': self.customer_implementation_date_and_time,
            'customer_implemented_by': self.customer_implemented_by,
            'customer_status': self.customer_status
        }

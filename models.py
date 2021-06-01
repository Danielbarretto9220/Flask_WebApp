from __init__ import db
from datetime import datetime

class RECEPTION(db.Model):
    e_id = db.Column(db.String(50), primary_key=True)
    name = db.Column(db.String(50))
    email = db.Column(db.String(50), unique=True)
    password = db.Column(db.String(200))
    register_date = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self):
        return "<User(e_id='%s', name='%s', email='%s', password='%s', register_date='%s')>" % (
            self.e_id, self.name, self.email, self.password, self.register_date)

class DONOR(db.Model):
    d_id = db.Column(db.Integer, primary_key=True)
    dname = db.Column(db.String(50), nullable=False)
    sex = db.Column(db.String(10), nullable=True)
    age = db.Column(db.Integer, primary_key=False)
    weight = db.Column(db.Integer, primary_key=False)
    address = db.Column(db.String(150), nullable=False)
    disease = db.Column(db.String(50), nullable=False)
    demail = db.Column(db.String(50), nullable=False)
    donor_date = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def __repr__(self):
        return f"DONOR('{self.d_id}', '{self.dname}')"

class BLOODBANK(db.Model):
    b_group = db.Column(db.String(50), primary_key=True, nullable=False)
    total_packets = db.Column(db.Integer, primary_key=False)

    def __repr__(self):
        return f"BLOODBANK('{self.b_group}', '{self.total_packets}')"

class BLOOD(db.Model):
    b_code = db.Column(db.Integer, primary_key=True)
    d_id = db.Column(db.Integer, db.ForeignKey('DONOR.d_id'), nullable=False)
    b_group = db.Column(db.String(50), db.ForeignKey('BLOODBANK.b_group'), nullable=False)
    packets = db.Column(db.Integer)

    def __repr__(self):
        return f"BLOOD('{self.b_code}', '{self.d_id}', '{self.b_group}')"

class CONTACT(db.Model):
    contact_id = db.Column(db.Integer, primary_key=True)
    b_group = db.Column(db.String(50), db.ForeignKey('BLOODBANK.b_group'))
    c_packets = db.Column(db.Integer)
    f_name = db.Column(db.String(50))
    address = db.Column(db.String(250))

    def __repr__(self):
        return f"CONTACT('{self.contact_id}', '{self.b_group}', '{self.f_name}')"


class NOTIFICATIONS(db.Model):
    n_id = db.Column(db.Integer, primary_key=True)
    nb_group = db.Column(db.String(5))
    n_packets = db.Column(db.Integer)
    nf_name = db.Column(db.String(50))
    naddress = db.Column(db.String(250))

    def __repr__(self):
        return f"NOTIFICATIONS('{self.n_id}', '{self.nb_group}', '{self.nf_name}', '{self.naddress}')"

from flask import render_template, flash, redirect, request, url_for, session, logging
from wtforms import Form, StringField, TextAreaField, PasswordField, validators, SelectField
from passlib.hash import sha256_crypt
import random
from functools import wraps
from models import RECEPTION, DONOR, BLOOD, BLOODBANK,CONTACT,NOTIFICATIONS
from __init__ import app, db


@app.route('/')
def index():
    return render_template('home.html')

@app.route('/contact', methods=['GET','POST'])
def contact():
    if request.method == 'POST':
        bgroup = request.form["bgroup"]
        bpackets = request.form["bpackets"]
        fname = request.form["fname"]
        adress = request.form["adress"]


        # Create db instance
        contact = CONTACT(b_group=bgroup, c_packets=bpackets, f_name=fname, address=adress)
        notifications = NOTIFICATIONS(nb_group=bgroup, n_packets=bpackets, nf_name=fname, naddress=adress)

        #Commit to DB
        db.session.add(contact)
        db.session.add(notifications)
        db.session.commit()

        flash('Your request is successfully sent to the Blood Bank','success')
        return redirect(url_for('index'))

    return render_template('contact.html')


class RegisterForm(Form):
    name = StringField('Name', [validators.DataRequired(),validators.Length(min=1,max=25)])
    email = StringField('Email',[validators.DataRequired(),validators.Length(min=10,max=50)])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm',message='Password do not match')
    ])
    confirm = PasswordField('Confirm Password')

@app.route('/register', methods=['GET','POST'])
def register():
    form = RegisterForm(request.form)
    if request.method == 'POST' and form.validate():
        password = sha256_crypt.encrypt(str(form.password.data))
        e_id = form.name.data+str(random.randint(1111,9999))

        reception = RECEPTION(e_id=e_id, name=form.name.data, email=form.email.data, password=password)
        db.session.add(reception)
        db.session.commit()

        flashing_message = "Success! You can log in with Employee ID " + str(e_id)
        flash( flashing_message,"success")

        return redirect(url_for('login'))

    return render_template('register.html',form = form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':

        e_id = request.form["e_id"]
        password_candidate = request.form["password"]

        result = RECEPTION.query.filter_by(e_id=e_id).first()

        if result:
            data = RECEPTION.query.filter_by(e_id=e_id).first()
            password = data.password

            # Compare Passwords
            if sha256_crypt.verify(password_candidate, password):
                # Passed
                session['logged_in'] = True
                session['e_id'] = e_id

                flash('You are now logged in', 'success')
                return redirect(url_for('dashboard'))
            else:
                error = 'Invalid login'
                return render_template('login.html', error=error)

        else:
            error = 'Employee ID not found'
            return render_template('login.html', error=error)

    return render_template('login.html')

# Check if user logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            flash('Unauthorized, Please login!', 'danger')
            return redirect(url_for('login'))
    return wrap


@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    flash('You are now logged out', 'success')
    return redirect(url_for('index'))

@app.route('/dashboard')
@is_logged_in
def dashboard():

    result = BLOODBANK.query.first()
    details = BLOODBANK.query.all()

    if result:
        return render_template('dashboard.html',details=details)
    else:
        msg = ' Blood Bank is Empty '
        return render_template('dashboard.html',msg=msg)

@app.route('/donate', methods=['GET', 'POST'])
@is_logged_in
def donate():
    if request.method  == 'POST':
        # Get Form Fields
        dname = request.form["dname"]
        sex = request.form["sex"]
        age = request.form["age"]
        weight = request.form["weight"]
        address = request.form["address"]
        disease =  request.form["disease"]
        demail = request.form["demail"]

        donor = DONOR(dname=dname , sex=sex, age=age, weight=weight, address=address, disease=disease, demail=demail)

        db.session.add(donor)
        db.session.commit()

        flash('Success! Donor details Added.','success')
        return redirect(url_for('donorlogs'))

    return render_template('donate.html')

@app.route('/donorlogs')
@is_logged_in
def donorlogs():

    result = DONOR.query.first()
    logs = DONOR.query.all()

    if result:
        return render_template('donorlogs.html',logs=logs)
    else:
        msg = ' No logs found '
        return render_template('donorlogs.html',msg=msg)

@app.route('/bloodform',methods=['GET','POST'])
@is_logged_in
def bloodform():
    if request.method  == 'POST':
        # Get Form Fields
        d_id = request.form["d_id"]
        blood_group = request.form["blood_group"]
        packets = request.form["packets"]

        blood = BLOOD(d_id=d_id, b_group=blood_group, packets=packets)
        db.session.add(blood)
        db.session.commit()

        records = BLOODBANK.query.all()
        tmp=0
        for r in records:
            if r.b_group == blood_group:
                r.total_packets = r.total_packets + int(packets)
                db.session.add(r)
                db.session.commit()
                tmp=1



        if tmp==0:
            new_record = BLOODBANK(b_group=blood_group, total_packets=int(packets))
            db.session.add(new_record)
            db.session.commit()
            tmp=0

        flash('Success! Donor Blood details Added.','success')
        return redirect(url_for('dashboard'))

    return render_template('bloodform.html')


@app.route('/notifications')
@is_logged_in
def notifications():

    result = CONTACT.query.first()
    requests = CONTACT.query.all()

    if result:
        return render_template('notification.html',requests=requests)
    else:
        msg = ' No requests found '
        return render_template('notification.html',msg=msg)

@app.route('/notifications/accept/<string:id>')
@is_logged_in
def accept(id):
    c_id = int(id)
    c = CONTACT.query.filter_by(contact_id=c_id).first()
    ra = BLOODBANK.query.all()
    temp = 0
    for r in ra:
        if r.b_group == c.b_group:
            temp=1
            rec = r




    if temp == 1:
        rec.total_packets = rec.total_packets - c.c_packets
        db.session.add(rec)
        db.session.commit()
        flash('Request Accepted', 'success')
        db.session.delete(c)
        db.session.commit()

    else:
        flash('Blood Type Not Available', 'warning')



    return redirect(url_for('notifications'))

@app.route('/notifications/decline/<string:id>')
@is_logged_in
def decline(id):
    c_id = int(id)
    cd = CONTACT.query.filter_by(contact_id=c_id).first()
    msg = 'Request Declined'
    flash(msg,'danger')
    db.session.delete(cd)
    db.session.commit()
    return redirect(url_for('notifications'))

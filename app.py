from flask import Flask, render_template, redirect, request, session, url_for, flash
from flask_bcrypt import Bcrypt
from pymongo import MongoClient
import os
from werkzeug.utils import secure_filename
import re

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'doc', 'docx'}

app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "Mohamed@124"

url = "mongodb://localhost:27017"
client = MongoClient(url)
db = client.APP_LOGIN
signup_coll = db.LOGIN
register_coll = db.REGISTER
contact_coll = db.Contact
uplodad_coll = db.uploded
profile_coll = db.profile

UPLOAD_FOLDER = os.path.join('static', 'uploads')
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

def is_logged_in():
    return 'Name' in session

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def strong_password(password):
    if len(password) < 8:
        return False
    if not re.search(r"[a-z]", password) or not re.search(r"[A-Z]", password):
        return False
    if not re.search(r"[!@#$%^&*()_+{}|:\"<>?]", password) or not re.search(r"\d", password):
        return False
    return True

@app.route("/", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        Name = request.form["Name"]
        Password = request.form["Password"]
        user = signup_coll.find_one({"Name": Name})
        if user:
            flash("Name already exists", "danger")
        elif not strong_password(Password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters', "danger")
        else:
            hash_password = bcrypt.generate_password_hash(Password).decode("utf-8")
            signup_data = {
                "Name": Name,
                "Password": hash_password
            }
            signup_coll.insert_one(signup_data)
            flash("Signup successful! Please login.", "success")
            return redirect(url_for("register"))
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form["Name"]
        address = request.form["Address"]
        email = request.form["Email"]
        location = request.form["Location"]

        if 'resume' not in request.files or 'image' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)

        resume = request.files['resume']
        image = request.files['image']

        if resume.filename == '' or image.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)

        if resume and allowed_file(resume.filename) and image and allowed_file(image.filename):
            resume_filename = secure_filename(resume.filename)
            resume_path = os.path.join(app.config['UPLOAD_FOLDER'], resume_filename)
            resume.save(resume_path)

            image_filename = secure_filename(image.filename)
            image_path = os.path.join(app.config['UPLOAD_FOLDER'], image_filename)
            image.save(image_path)

            registration_data = {
                "Name": name,
                "Address": address,
                "Email": email,
                "Location": location,
                "Resume": resume_path,
                "Image": image_path
            }
            register_coll.insert_one(registration_data)

            session['Name'] = name

            flash("Registration successful!", "success")
            return redirect(url_for("profile"))
        else:
            flash('Allowed file types are png, jpg, jpeg, pdf, doc, docx', 'danger')
    return render_template("register.html")

@app.route("/profile", methods=["GET", "POST"])
def profile():
    if not is_logged_in():
        flash("Please login to access your profile", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        profile_pic = request.files.get('profile_pic')
        profile_banner = request.files.get('profile_banner')
        merchant_name = request.form.get('merchant_name')
        merchant_description = request.form.get('merchant_description')

        profile_data = {}

        if profile_pic and allowed_file(profile_pic.filename):
            profile_pic_filename = secure_filename(profile_pic.filename)
            profile_pic_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_pic_filename)
            profile_pic.save(profile_pic_path)
            profile_data['profile_pic'] = profile_pic_path

        if profile_banner and allowed_file(profile_banner.filename):
            profile_banner_filename = secure_filename(profile_banner.filename)
            profile_banner_path = os.path.join(app.config['UPLOAD_FOLDER'], profile_banner_filename)
            profile_banner.save(profile_banner_path)        
            profile_data['profile_banner'] = profile_banner_path

        if merchant_name:
            profile_data['merchant_name'] = merchant_name
        if merchant_description:
            profile_data['merchant_description'] = merchant_description

        if profile_data:
            user_name = session['Name']
            profile_data['Name'] = user_name  
            profile_coll.insert_one(profile_data)  
            flash("Profile updated successfully!", "success")
            return redirect(url_for("contact"))
        else:
            flash("No updates made to the profile.", "info")

    return render_template("profile.html")

@app.route("/contact", methods=["GET", "POST"])
def contact():
    if request.method == "POST":
        country = request.form["country"]
        state = request.form["state"]
        city = request.form["city"]
        street_name = request.form["street_name"]
        contact_number = request.form["contact_number"]

        contact_data = {
            "Country": country,
            "State": state,
            "City": city,
            "Street Name": street_name,
            "Contact Number": contact_number
        }
        contact_coll.insert_one(contact_data)

        flash("Contact information submitted successfully!", "success")
        return redirect(url_for("upload_documents"))
    return render_template("contact.html")

@app.route("/upload_documents", methods=["GET", "POST"])
def upload_documents():
    if not is_logged_in():
        flash("Please login to upload your documents", "danger")
        return redirect(url_for("login"))

    if request.method == "POST":
        user_name = session.get('Name')

        personal_id_proof = request.files.get('personal_id_proof')
        company_proof = request.files.get('company_proof')
        company_product_license = request.files.get('company_product_license')

        if user_name:
            user_data = {"Name": user_name}

            if personal_id_proof and allowed_file(personal_id_proof.filename):
                personal_id_proof_filename = secure_filename(personal_id_proof.filename)
                personal_id_proof_path = os.path.join(app.config['UPLOAD_FOLDER'], personal_id_proof_filename)
                personal_id_proof.save(personal_id_proof_path)
                user_data["Personal ID Proof"] = personal_id_proof_path

            if company_proof and allowed_file(company_proof.filename):
                company_proof_filename = secure_filename(company_proof.filename)
                company_proof_path = os.path.join(app.config['UPLOAD_FOLDER'], company_proof_filename)
                company_proof.save(company_proof_path)
                user_data["Company Proof/License"] = company_proof_path

            if company_product_license and allowed_file(company_product_license.filename):
                company_product_license_filename = secure_filename(company_product_license.filename)
                company_product_license_path = os.path.join(app.config['UPLOAD_FOLDER'], company_product_license_filename)
                company_product_license.save(company_product_license_path)
                user_data["Company Product/Service License"] = company_product_license_path

            if user_data:
                uplodad_coll.insert_one(user_data)
                flash("Documents uploaded successfully!", "success")
            else:
                flash("No valid documents uploaded!", "warning")

            return redirect(url_for("dashboard"))
    return render_template("upload_documents.html")

@app.route("/dashboard")
def dashboard():
    if not is_logged_in():
        flash("Please login to view your dashboard", "danger")
        return redirect(url_for("login"))

    user_name = session['Name']
    
    signup_data = signup_coll.find_one({"Name": user_name})
    register_data = register_coll.find_one({"Name": user_name})
    profile_data = profile_coll.find_one({"Name": user_name})
    contact_data = contact_coll.find_one({"Name": user_name})
    upload_data = uplodad_coll.find_one({"Name": user_name})

    return render_template("dashboard.html", 
                           signup_data=signup_data, 
                           register_data=register_data, 
                           profile_data=profile_data, 
                           contact_data=contact_data, 
                           upload_data=upload_data)

@app.route("/logout")
def logout():
    session.pop("Name", None)
    flash("Logged out successfully.", "success")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)

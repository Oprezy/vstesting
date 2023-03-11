from flask import Flask, render_template, request, url_for, redirect, flash, send_from_directory, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user

app = Flask(__name__)
login_manager = LoginManager()
login_manager.init_app(app)

app.config['UPLOAD_FOLDER'] = '/static/files'
app.config['SECRET_KEY'] = 'any-secret-key-you-choose'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

##CREATE TABLE IN DB
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    name = db.Column(db.String(1000))

    def logged_in():
        return current_user.is_authenticated
#Line below only required once, when creating DB. 

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    logged_in = session.get('logged_in', False)
    return render_template("index.html")

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == "POST":
        user_name = request.form['name']
        user_email = request.form['email']
        user_pass = request.form['password']
        
        user = User.query.filter_by(email=user_email).first()
        if user:
            flash("You have registered with this email. you should login instead.")
            return redirect(url_for('login'))
        else:
            hashed_password = generate_password_hash(user_pass, "pbkdf2:sha256", 8)
            new_user = User(name=user_name, email=user_email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('secrets'))
    return render_template("register.html")



@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == "POST":
        u_email = request.form['email']
        u_password = request.form['password']

        user = User.query.filter_by(email=u_email).first()
        if user:
            if check_password_hash(user.password, u_password):
                login_user(user)
                # session['logged_in'] = True
                
                return redirect(url_for('secrets'))
            else:
                flash("Password Error.. is wrong")
        else:
            flash("Email error.. does not exist")
            error = "Invalid emails"
            return render_template('login.html', error=error)
        return render_template("login.html")
        
    return render_template("login.html")


@app.route('/secrets')
@login_required
def secrets():
    logged_in = session.get('logged_in', False)
    return render_template("secrets.html")


@app.route('/logout')
@login_required
def logout():
    # session['logged_in'] = False
    logout_user()
    return redirect(url_for('home'))

@app.route('/download')
def download():
    return send_from_directory('static', filename="files/cheat_sheet.pdf")

@app.route('/check')
def check():
    # user_del = User.query.filter_by(id=7).first()
    # db.session.delete(user_del)
    # db.session.commit()
    users = User.query.all()
    for user in users:
        print(user.id, user.name, user.email, user.password)
    return "a"

if __name__ == "__main__":
    app.run(debug=True)
    db.create_all()
    







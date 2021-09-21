from flask import Flask, request, session, render_template, flash,redirect, url_for
from flask_mysqldb import MySQL
from werkzeug.security import generate_password_hash, check_password_hash
import re

app = Flask(__name__)


app.secret_key="your secret key"

#MySQL connection with Flask

app.config['MYSQL_HOST'] = "localhost"
app.config['MYSQL_USER'] = "root"
app.config['MYSQL_PASSWORD'] = ""
app.config['MYSQL_DB'] = "your database"
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)



#home route
@app.route("/")
def home():
    return render_template('index.html')


#SignUP route

@app.route("/SignUp",methods=["GET","POST"])
def Signup():
    if request.method=="POST":
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']
        
        #converting the password into the hashed password for security purpose
        hash_password = generate_password_hash(password)

        cur = mysql.connection.cursor()

        cur.execute("SELECT * from user where email=%s",[email])
        record = cur.fetchall()
        if len(record)>0:                                    #check user already exist or not
            flash("user already exist")   
        elif not name or not password or not email:          #all field must not be not null
            flash('Please fill out the all form fields')    
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):     #validating email address
            flash('Invalid email address')    
        else:    
            #creating account in user table
            cur.execute("INSERT INTO user (name,email,password) VALUES(%s,%s,%s)",(name,email,hash_password))
            mysql.connection.commit()
            cur.close()
            flash("SignUp successful now please login")
            return render_template("login.html")
    return render_template('signup.html')

@app.route("/login",methods=["GET","POST"])
def login():
    #check if user already loggedin, then redirect to home page
    if 'loggedin' in session:
        return redirect(url_for("home"))   

    if request.method=="POST":
        email = request.form['email']
        passwrd = request.form['password']

        cur=mysql.connection.cursor()
        cur.execute("SELECT name,email,password FROM user WHERE email=%s",[email])
        record=cur.fetchone()

        #if record exist then match the password with record password else return Incorrect Credentials
        if record:
            session.pop('email',None)
            if check_password_hash(record['password'],passwrd):
                
                #if password matched then create a session or saved the user in session
                session['loggedin']=True
                session['email']=record['email']
                session['name']=record['name']
                #print(session)
                flash("login successful")
                return redirect(url_for('home'))
            else:
                flash("Incorrect password")    
        else:
            flash("Incorrect credentials")    

    return render_template('login.html')

#logout route 
@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    app.run(debug=True)



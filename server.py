from flask import Flask, render_template, redirect, request, session, flash
from datetime import datetime
from flask_bcrypt import Bcrypt
import re
from mysqlconnection import MySQLConnector
EMAIL_REGEX =re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
    # REGEX -is defined as a regular expression.
number_check = recompile(r"^[a-zA-Z]+$")
    # NAME_REGEX = re.compile
app = Flask(__name__)
    # Keyword for the module.

mysql = MySQLConnector(app,"wall")
    # The mysql connection is coming from the "mydb" connect in the MySQL database. And the server.py file is connecting to the mydb database.

bcrypt = Bcrypt(qpp)
app.secret_key = "Secret"

@app.route('/')
def index():
    return render_template('index.html')
        # I believe this is saying render_template is taking the information from the render tempalte information.
        # This is for registration
@app.route('/register', methods =['POST'])
def register():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    password = request.form['password']
    confirmation_password = request.form['confirmation_password']
    passflag = True
    if request.form["password"] != request.form["confirm"]:
        flash("Passwords do not match!")
    # else:
        # query = "INSERT INTO users(first_name, last_name, username, password, created_at, updated_at) VALUES ('{}', '{}', '{}', '{}', NOW(), NOW())".format(request.form["first_name"], request.form["last_name"], request.form["username"], str(bcrypt.generate_password_hash(request.form["password"]))
        # print(query)
        # mysql.run_mysql_query(query)

        # query = "SELECT id FROM users WHERE username='{}'".format(request.form["username"])
        # new_user = mysql.fetch(query)[0]
        # session["user_id"] = new_user["id"]
        # print(session["user_id"])
    return redirect("/")

    if not EMAIL_REGEX.match(request.form['email']):
        flash('Not a valid email', 'error')
        passflag = False
    if len(request.form['fName'])< 1:
        flash('Cannot be blank', 'error')
    if len(request.form['lName'])<1:
        flash('Cannot be blank', 'error')
    if len(request.form['password'])<1:
        flash('cannot be less than 8 characters', 'error')
        error = False
    if (request.form['confirm_password']) != request.form['password']:
        flash('password does not match', 'error')
        error = False
        # How does elif not impact the rest of this information.
    if len(errors) == 0:
        flash('Thanks for registering')
        password = request.form['password']
        pw_hash = bcrypt.generate_password_hash(password)
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW())"

        data = {
        'email': request.form['email'],
        'first_name': request.form['fName'],
        'last_name': request.form['lName'],
        'password': pw_hash
        }
        return redirect('/')


@app.route("/login", methods =['POST'])
def login():
    email = request.form['email']
    password = request.form['password']
    print request.form['email']
    # New information; The below replaced the older data to make sure the user_query worked while reducing errors.
    user_query = "SELECT * FROM users WHERE email = :email"
    query_data = {'email': email }
    user = mysql.query_db(user_query, query_data)
    print user
    if not user:
        flash('please enter email', 'error')
        return redirect('/')
    if bcrypt.check_password_hash(user[0]['pw_hash'], password):
        session['user_id'] = user[0]['id']
        return redirect('/wall')
    else:
        flash('Your login information did not match', 'error')
        return redirect('/')
    return redirect('/success')

@app.route("/success")
def success():
    render_template("/wall.html")

@app.route('/wall')
def wall():
    # new information
    user = mysql.fetch("SELECT * FROM users WHERE id={}".format(session["user_id"]))[0]

    query = "SELECT messages.message, messages.created_at, messages.id, messages.user_id, users.first_name FROM messages LEFT JOIN users ON users.id=messages.user_id ORDER BY messages.updated_at DESC"

    messages = mysql.fetch(query)

    comment_dict = {}

    for comment in comments:
        if int(comment.user_id) == int(session["user_id"]) and datetime.datetime.now() - comment.created_at <= datetime.timedelta(minutes=30):
                comment["can_delete"] = True
        else:
                comment["can_delete"] = False

                if comment ["message_id"] in comment_dict:
                    comment_dict[comment["message_id"]].append(comment)
                else:
                    comment_dict[comment["message_id"]] = [comment]
    for message in messages:
        if message ["id"] in comment_dict:
                    message["comments"] = comment_dict [message["id"]]
        else:
                    message["comments"] = []
    return render_template("wall.html", user=user, messages=messages)

@app.route('/message', methods=['POST'])
def message():
    message = request.form["message"].replace("'", "''")

    query = "INSERT INTO messages (message, user_id, created_at, updated_at) VALUES('{}', '{}'.format(message, session["user_id"])

    mysql.run_mysql_query
@app.route('/comment', methods=['POST'])
def comment():
    # New information
    query = "INSERT INTO comments (comment, user_id, message_id, created_at, updated_at) VALUES ('{}', '{}', '{}', NOW(), NOW())".format(request.form["comment"].replace("'", "''"), session["user_id"], request.form["message_id"])
    mysql.run_mysql_query(query)
    return redirect("/wall")
    }

@app.route("/delete_comment", methods=["POST"])
def delete_comment():
    comment = mysql.fetch("SELECT comments.user_id, comments.created_at FROM comments WHERE comments.id={}.format(request.form["comment_id"]))[0]

    if comment["user_id"] == session["user_id"] and datetime.datetime.now() - comment["created_at"] <= datetime.timedelta(minutes=30):
            query = "DELETE FROM comments WHERE comments.id={}".format(request.form["comment_id"])
            mysql.run_mysql_query(query)
    else:
            flash("Nice try, guy")
    return redirect("/wall")

@app.route("delete_message", methods=["POST"])
def delete_message():
    query = "DELETE FROM comments WHERE comments.message_id={}".format(request.form["message_id"])

    mysql.run_mysql_query(query)
    query = "DELETE FROM messages WHERE messages.id={}".format(request.form["message_id"])
    mysql.run_mysql_query(query)
    return redirect("/wall")

app.run(debug=True)

import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for
)
from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db

# define blueprint for '/auth' endpoint
bp = Blueprint('auth', __name__, url_prefix='/auth')

# ################## REGISTER FUNCTIONS #################### #


# adds '/register' to '/auth' endpoint.  results in '/auth/register'
@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        # pulls username and password from the request form
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None

        # validates that username exists
        if not username:
            error = 'Username is required.'
            # validates that password exits
        elif not password:
            error = 'Password is required.'
            # db.execute uses as many '?' as necessary for palceholders. Second
            # argument of db.execute fills in values for '?' in first argument.
            #
            # Validates to make sure username is not already present in the
            # database and throws creates an error if user already exists
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)

        # if there is no error, create the new user with 'username' and hashed
        # 'password'
        if error is None:
            db.execute(
                'INSERT INTO user (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            # db.commit needs to be called in order to save changes (according
            # to the tutorial)
            db.commit()
            # redirect after successful registration to instantly login user
            return redirect(url_for('auth.login'))

        # flash() is a special function used to store error messages that are
        # retrieved when rendering the template. If error != None, the error
        # will display to the user
        flash(error)

    # render_template() calls a specific html template to be rendered
    return render_template('auth/register.html')

# ################### LOGIN FUNCTION ####################### #


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        # pulls username and password from the request form and access the
        # database
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        # looks in the database for a username with the sent of username
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        # validation check to make sure the user exists in the databse
        if user is None:
            error = 'Incorrect username.'
            # validation check to see if the hashed password from the form
            # matches the db's password
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        # if no error exists, clear the current session data and assign it
        # to the new user's ID, then redirect to the 'index' page
        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        # show the user any errors, if they exists
        flash(error)

    return render_template('auth/login.html')

# ################## ADDS USER INFO TO SESSION ############## #


# bp.before_app_request() registers a function that runs before the view
# function no matter what URL is requested.  This allows us to load the
# current users data.
@bp.before_app_first_request
def load_logged_in_user():
    # checks to see if a user is logged in.  Pull the user_id from the
    # session object otherwise user is None
    user_id = session.get('user_id')

    if user_id is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE id = ?', (user_id,)
        ).fetchone()

# ################# LOG OUT FUNCTION ######################## #


@bp.route('/logout')
def logout():
    # clears the user info from session
    session.clear()
    # redirects to the index page
    return redirect(url_for('index'))

# ################# FUNCTION FOR REQUIRING LOG IN ############ #


# Wraps the original view in a new function that checks to see if a user
# is logged in. If no user is logged, then redirect to the login page.
def login_required(view):
    @functools.wraps(view)
    def wrapped_view(**kwargs):
        if g.user is None:
            return redirect(url_for('auth.login'))

        return view(**kwargs)

    return wrapped_view

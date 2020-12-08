import functools

from flask import (
    Blueprint, flash, g, redirect, render_template, request, session, url_for, make_response, jsonify
)

import json

from werkzeug.security import check_password_hash, generate_password_hash

from flaskr.db import get_db



bp = Blueprint('auth', __name__, url_prefix='/auth')


@bp.route('/register', methods=('GET', 'POST'))
def register():
    if request.method == 'POST':
        #print("hello")#而axios则是一个PayLoad
        data = request.get_json(silent=True)
        username = data['username']
        password = data['password']

        print(username)
        print(password)
        db = get_db()
        error = None

        if not username:
            error = 'Username is required.'
        elif not password:
            error = 'Password is required.'
        elif db.execute(
            'SELECT id FROM user WHERE username = ?', (username,)
        ).fetchone() is not None:
            error = 'User {} is already registered.'.format(username)
            print("hello3")
            resp = make_response("q")
            resp.status = "200 OK"
            resp.headers["data"] = "0"
            print(resp)
            return resp
            #resp_data = {"data":"已被注册，请检查", "registersucceedurl":"http://127.0.0.1:5000/auth/loginasd"}
            #return jsonify(resp_data)

        if error is None:
            db.execute(
                'INSERT INTO user (username, password) VALUES (?, ?)',
                (username, generate_password_hash(password))
            )
            db.commit()
            #return redirect(url_for('auth.login'))
            print("hello2")

            return {"data":0, "registersucceedurl":"http://127.0.0.1:5000/auth/login"}

        flash(error)

    return render_template('auth/register.html')
    #return


@bp.route('/login', methods=('GET', 'POST'))
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        db = get_db()
        error = None
        user = db.execute(
            'SELECT * FROM user WHERE username = ?', (username,)
        ).fetchone()

        if user is None:
            error = 'Incorrect username.'
        elif not check_password_hash(user['password'], password):
            error = 'Incorrect password.'

        if error is None:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))

        flash(error)

    return render_template('auth/login.html')
from flask import Flask, render_template, request, redirect, url_for, flash, \
    jsonify, make_response, send_from_directory, session as login_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CategoryItem
from werkzeug.utils import secure_filename
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import os
import random
import urllib
import string
import httplib2
import json
import requests
import pprint

UPLOAD_FOLDER = '/vagrant/catalog/uploads'
ALLOWED_EXTENSIONS = set(['jpg', 'jpe', 'jpeg', 'png', 'gif', 'svg', 'bmp'])

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024

# APPLICATION_NAME = "Restaurant Menu Application"

engine = create_engine('sqlite:///categoryitem.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

def randomToken():
    return ''.join(random.choice(string.ascii_uppercase + string.digits) \
        for x in xrange(32))

def allowedFile(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def preventOverwrite(filename):
    i = 1
    f = filename.rsplit('.', 1)
    while os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
        filename = "%s_%d.%s" % (f[0], i, f[1])
        i += 1
    return filename

def googleConnect(token):
    CLIENT_ID = json.loads(
        open('./client_secrets/google.json', 'r').read())['web']['client_id']

    try:
        # Upgrade the authorization token into a credentials object
        oauth_flow = flow_from_clientsecrets('./client_secrets/google.json', \
            scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(token)
    except FlowExchangeError:
        return {"response": 'Failed to upgrade the authorization code.', \
            "status": 401}

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    print result

    if result.get('error') is not None:
        return {"response": result.get('error'), "status": 500}

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        return {"response": "Token's user ID doesn't match given user ID.", \
            "status": 500}

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        return {"response": "Token's client ID does not match app's.", \
            "status": 401}

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['user_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    login_session['account'] = "Google"

    return {"response": "Login Successful.", "status": 200}

def googleDisconnect():
    if login_session['access_token'] is None:
        return {"response": "Current user not connected", "status": 401}
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']

    h = httplib2.Http()
    resp, content = h.request(url, 'GET')

    if resp['status'] != '200':
        return {"response": "Failed to revoke token for given user.", \
            "status": 400}

    return {"response": "Successfully disconnected.", "status": 200}


def facebookConnect(token):
    h = httplib2.Http()
    app_id = json.loads(open('client_secrets/facebook.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('client_secrets/facebook.json', 'r').read())['web']['app_secret']

    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (app_id, app_secret, token)

    resp, content = h.request(url, 'GET')

    if("error" in content):
        return {"response": json.loads(content)['error']['message'], \
            "status": 401}

    access_token = json.loads(content)['access_token']
    login_session['account'] = access_token

    # Use token to get user info from API
    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % access_token

    resp, content = h.request(url, 'GET')

    if("error" in content):
        return {"response": json.loads(content)['error']['message'], \
            "status": 401}

    data = json.loads(content)

    login_session['account'] = "Facebook"
    login_session['user_id'] = data["id"]
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % access_token

    h = httplib2.Http()
    resp, content = h.request(url, 'GET')

    if("error" in content):
        return {"response": json.loads(content)['error']['message'], "status": 401}

    data = json.loads(content)
    login_session['picture'] = data["data"]["url"]

    return {"response": "Login Successful.", "status": 200}


def facebookDisconnect():
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        login_session['user_id'], login_session['access_token'])
    h = httplib2.Http()
    resp, content = h.request(url, 'DELETE')[1]

    if resp['status'] != '200':
        return {"response": "Failed to revoke token for given user.", \
            "status": 400}

    return {"response": "Successfully disconnected.", "status": 200}


def githubConnect(token):
    h = httplib2.Http()
    client_id = json.loads(open('client_secrets/github.json', 'r') \
        .read())['client_id']
    client_secret = json.loads(open('client_secrets/github.json', 'r').read())['client_secret']

    url = 'https://github.com/login/oauth/access_token'
    headers = {'Accept': 'application/json'}
    body = urllib.urlencode( \
        {'client_id': client_id, 'client_secret': client_secret,
        'code': token, 'state': login_session['state']})

    resp, content = h.request(url, 'POST', body=body, headers=headers)

    if("error" in content):
        return {"response": "Incorrect web token.", "status": 401}

    login_session['access_token'] = json.loads(content)['access_token']
    url = ('https://api.github.com/user?access_token=%s' % login_session['access_token'])
    resp, content = h.request(url, 'GET')

    if(resp['status'] == 401):
        return {"response": "Bad credentials.", "status": 401}

    user_data = json.loads(content)
    login_session['account'] = 'Github'
    login_session['user_id'] = user_data['id']
    login_session['username'] = user_data['login']
    login_session['picture'] = user_data['avatar_url']
    login_session['email'] = user_data['email']

    return {"response": "Login Successful.", "status": 200}


def serializeItem(item):
    ret = item.serialize
    ret['image'] = url_for('uploaded_file', filename=ret['image'], \
        _external=True)
    return ret


@app.route('/images/<filename>')
def uploaded_file(filename):
    if filename:
        filename = 'placeholder.jpg'

    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)


@app.route('/login')
def showLogin():
    if 'username' in login_session:
        return redirect(url_for('displayItems'))

    login_session['state'] = randomToken()
    return render_template('login.html.j2', STATE=login_session['state'], login_session=login_session)


@app.route('/acctconnect', methods=['POST'])
def acctConnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    data = json.loads(request.data)
    # resp = make_response(json.dumps('Invalid login info.'), 401)

    if(data['account'] == "Google"):
        ret = googleConnect(data['token'])

    if(data['account'] == "Facebook"):
        ret = facebookConnect(data['token'])

    if(data['account'] == "Github"):
        ret = githubConnect(data['token'])

    print data['account']

    response = make_response(json.dumps(ret['response']), ret['status'])
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/acctdisconnect')
def acctDisconnect():

    if(login_session['account'] == "Google"):
        ret = googleDisconnect()

    if(login_session['account'] == "Facebook"):
        ret = googleDisconnect()

    if(login_session['account'] == "Github"):
        # Cannot revoke Github access token.
        ret = {"response": "Successfully disconnected.", "status": 200}

    print ret
    del login_session['account']
    del login_session['access_token']
    del login_session['user_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']

    return redirect(url_for('displayItems'))


@app.route('/ghcallback')
def ghCallback():
    ret = '<script>'\
        'var code = window.location.toString().replace(/.+code=/, \'\');' \
        'window.opener.githubCallback(code);' \
        'window.close();' \
        '</script>'

    return ret


@app.route('/')
@app.route('/<endpoint>')
def displayItems(endpoint=None):
    cats = session.query(Category).all()
    items = session.query(CategoryItem).order_by(CategoryItem.id).all()
    title_text = "Latest Items"

    if(endpoint == 'json'):
        categories = {i.id: i.serialize for i in cats}
        for val in items:
            if 'items' in categories[val.category_id]:
                categories[val.category_id]['items'].append(serializeItem(val))
            else:
                categories[val.category_id]['items'] = [serializeItem(val)]

        return jsonify(categories=categories)

    return render_template(
        'display_items.html.j2', cats=cats, items=items,
        title_text=title_text, cat_name="", login_session=login_session)


@app.route('/catalog/<int:cat_id>/')
@app.route('/catalog/<int:cat_id>/<endpoint>')
def displaySingleCatItems(cat_id, endpoint=None):
    cats = session.query(Category).all()
    curr_cat = session.query(Category).filter(Category.id == cat_id).one()
    items = session.query(CategoryItem) \
        .filter(CategoryItem.category_id == cat_id).all()

    if endpoint == 'json':
        # map(externalLink, items)
        curr_cat = curr_cat.serialize
        curr_cat['items'] = [serializeItem(i) for i in items]
        return jsonify(category=curr_cat)

    title_text = "%s Items (%i items)" % (curr_cat.name, len(items))

    return render_template(
        'display_items.html.j2', cats=cats, items=items,
        title_text=title_text, cat_name=curr_cat.name, login_session=login_session)


@app.route('/item/<int:item_id>/')
@app.route('/item/<int:item_id>/<endpoint>')
def displayItemDetails(item_id, endpoint=None):
    item = session.query(CategoryItem).join(CategoryItem.category) \
        .filter(CategoryItem.id == item_id).one()

    if endpoint == 'json':
        return jsonify(item=serializeItem(item))

    login_session['_csrf_token'] = randomToken()
    return render_template('item_details.html.j2', item=item, login_session=login_session)


@app.route('/item/<int:item_id>/edit',
           methods=['GET', 'POST'])
def editItem(item_id):
    if 'username' not in login_session:
        return redirect(url_for('displayItemDetails', item_id=item_id))

    cats = session.query(Category).all()
    item = session.query(CategoryItem).join(CategoryItem.category) \
        .filter(CategoryItem.id == item_id).one()

    if request.method == 'POST':
        if request.form['_csrf_token'] != "login_session['_csrf_token']":
            response = make_response(json.dumps("Invalid web token."), 400)
            response.headers['Content-Type'] = 'application/json'
            return response

        item.name = request.form['name']
        item.description = request.form['description']
        item.category_id = request.form['category']

        imagefile = None

        if 'image' in request.files:
            file = request.files['image']

            if file and (file.filename != '') and allowedFile(file.filename):
                # delete exsisting file
                if item.image is not None:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'], item.image))

                imagefile = secure_filename(file.filename)
                imagefile = preventOverwrite(imagefile)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], imagefile))

        if imagefile is not None:
            item.image = imagefile

        session.add(item)
        session.commit()

        return redirect(url_for('displayItemDetails', item_id=item.id))
    else:
        login_session['_csrf_token'] = randomToken()

        return render_template('item_edit.html.j2', cats=cats, item=item, login_session=login_session)


@app.route('/item/add', methods=['GET', 'POST'])
def addItem():
    if 'username' not in login_session:
        return redirect(url_for('displayItems'))

    cats = session.query(Category).all()
    new_item = CategoryItem(name="", description="", category_id=-1)

    if request.method == 'POST':
        print request.form['_csrf_token']
        print
        if request.form['_csrf_token'] != login_session['_csrf_token']:
            response = make_response(json.dumps("Invalid web token."), 400)
            response.headers['Content-Type'] = 'application/json'
            return response

        new_item.name = request.form['name']
        new_item.description = request.form['description']
        new_item.category_id = request.form['category']

        session.add(new_item)
        session.commit()

        return redirect(url_for('displayItemDetails', item_id=new_item.id))
    else:
        login_session['_csrf_token'] = randomToken()
        return render_template('item_edit.html.j2', cats=cats, item=None, login_session=login_session)


@app.route('/item/<int:item_id>/delete',
           methods=['POST'])
def deleteItem(item_id):
    if 'username' not in login_session:
        response = make_response(json.dumps("Not Logged In."), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    if request.form['_csrf_token'] != login_session['_csrf_token']:
        response = make_response(json.dumps("Invalid web token."), 400)
        response.headers['Content-Type'] = 'application/json'
        return response

    item = session.query(CategoryItem).join(CategoryItem.category) \
        .filter(CategoryItem.id == item_id).one()

    session.delete(item)
    session.commit()

    return redirect(url_for('displayItems'))


if __name__ == '__main__':
    app.secret_key = '1GrSamWXZ8ikGhg43UIUbw5X'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

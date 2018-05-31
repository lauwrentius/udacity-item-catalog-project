from flask import (Flask,
                   render_template,
                   request,
                   redirect,
                   url_for,
                   flash,
                   jsonify,
                   make_response,
                   send_from_directory,
                   send_file,
                   session as login_session)

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from db_setup import Base, Category, CategoryItem, User
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
import boto3

ALLOWED_EXTENSIONS = {'jpg', 'jpe', 'jpeg', 'png', 'gif', 'svg', 'bmp'}

def loadClientSecret(account):
    """
    Loads Json File of client's Secret
    returns json: app client secret for authentication
    """
    file = (app.root_path + '/client_secrets/%s.json' % account)
    return json.loads(open(file, 'r').read())

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = app.root_path + '/uploads'
app.config['MAX_CONTENT_LENGTH'] = 5 * 1024 * 1024
app.config['AWS_BUCKET'] = 'elasticbeanstalk-us-west-2-369336360970'
app.config['AWS_PATH'] = 'item-catalog-uploads/'
app.config['AWS_HOST'] = 'https://s3-us-west-2.amazonaws.com/elasticbeanstalk-us-west-2-369336360970/item-catalog-uploads/'

engine = create_engine('mysql+pymysql://' +
    loadClientSecret('dbase')['user'] + ':' +
    loadClientSecret('dbase')['pass'] + '@' +
    loadClientSecret('dbase')['host'] + '/' +
    loadClientSecret('dbase')['dbase'])

Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()

s3 = boto3.resource('s3')

def randomToken():
    """
    Generates Random token for authentication
    returns string: randomized string of characters
    """
    return ''.join(random.choice(string.ascii_uppercase + string.digits)
                   for x in range(32))


def registerUser():
    user = session.query(User) \
        .filter(User.email == login_session['email'])

    if user.count() == 0:
        newUser = User(
            email=login_session['email'],
            username=login_session['username'])
        session.add(newUser)
        session.commit()
        login_session['registered_user'] = newUser.id
    else:
        login_session['registered_user'] = user[0].id


def allowedFile(filename):
    """
    Helper function to check if a file extensions is alowed/not
    returns boolean
    """
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def preventOverwrite(filename):
    """
    Helper function prevent files being overwitten.
    Adds '_i' to the end of the filename if file exsists on the folder.
    returns string: new filename
    """
    i = 1
    f = filename.rsplit('.', 1)
    while os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
        filename = "%s_%d.%s" % (f[0], i, f[1])
        i += 1
    return filename


def googleConnect(token):
    """
    Connect to Google account using a token and
    retreives user's basic information (usrname, email, and photo)
    params: token(string):  authentication token received from the client
    returns dict: response-The response message, status-Http status result
    """
    CLIENT_ID = json.loads(
        open(app.root_path + '/client_secrets/google.json', 'r').read())['web']['client_id']

    try:
        # Upgrade the authorization token into a credentials object
        oauth_flow = flow_from_clientsecrets(app.root_path + '/client_secrets/google.json',
                                             scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(token)
    except FlowExchangeError:
        return {"response": 'Failed to upgrade the authorization code.',
                "status": 401}

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        return {"response": result.get('error'), "status": 500}

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        return {"response": "Token's user ID doesn't match given user ID.",
                "status": 500}

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        return {"response": "Token's client ID does not match app's.",
                "status": 401}

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = answer.json()

    if data['name'] == '':
        data['name'] = data['email']

    login_session.update({
        'account': 'Google',
        'user_id': gplus_id,
        'username': data['name'],
        'email': data['email'],
        'picture': data['picture'],
        'access_token': credentials.access_token})

    registerUser()
    return {"response": "Login Successful.", "status": 200}


def googleDisconnect():
    """
    Disconnect from Google account
    return dict: {response, status}
    """
    if login_session['access_token'] is None:
        return {"response": "Current user not connected", "status": 401}
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']

    h = httplib2.Http()
    resp, content = h.request(url, 'GET')

    if resp['status'] != '200':
        return {"response": "Failed to revoke token for given user.",
                "status": 400}

    return {"response": "Successfully disconnected.", "status": 200}


def facebookConnect(token):
    """
    Function to connect to Facebook account using a token and
    retreives user's basic information (usrname, email, and photo)
    params: token(string):  authentication token received from the client
    returns dict: response-The response message, status-Http status result
    """
    h = httplib2.Http()
    app_id = json.loads(open(app.root_path + '/client_secrets/facebook.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open(app.root_path + '/client_secrets/facebook.json', 'r').read())['web']['app_secret']

    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, token)

    resp, content = h.request(url, 'GET')

    if("error" in content):
        return {"response": json.loads(content)['error']['message'],
                "status": 401}

    access_token = json.loads(content)['access_token']

    # Use token to get user info from API
    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % access_token

    resp, content = h.request(url, 'GET')

    if("error" in content):
        return {"response": json.loads(content)['error']['message'],
                "status": 401}

    data = json.loads(content)

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % access_token
    h = httplib2.Http()
    resp, content = h.request(url, 'GET')

    if("error" in content):
        return {"response": json.loads(content)['error']['message'], "status": 401}
    picture_data = json.loads(content)

    login_session.update({
        'account': "Facebook",
        'user_id': data["id"],
        'username': data["name"],
        'email': data["email"],
        'picture': picture_data["data"]["url"],
        'access_token': access_token})

    registerUser()
    return {"response": "Login Successful.", "status": 200}


def facebookDisconnect():
    """
    Disconnect from Facebook account
    return dict: {response, status}
    """
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (
        login_session['user_id'], login_session['access_token'])
    h = httplib2.Http()
    resp, content = h.request(url, 'DELETE')[1]

    if resp['status'] != '200':
        return {"response": "Failed to revoke token for given user.",
                "status": 400}

    return {"response": "Successfully disconnected.", "status": 200}


def githubConnect(token):
    """
    Connect to GitHub account using a token and
    retreives user's basic information (usrname, email, and photo)
    params: token(string):  authentication token received from the client
    returns dict: response-The response message, status-Http status result
    """
    h = httplib2.Http()
    client_id = json.loads(open(app.root_path + '/client_secrets/github.json', 'r')
                           .read())['client_id']
    client_secret = json.loads(
        open(app.root_path + '/client_secrets/github.json', 'r').read())['client_secret']

    url = 'https://github.com/login/oauth/access_token'
    headers = {'Accept': 'application/json'}
    body = urllib.urlencode(
        {'client_id': client_id, 'client_secret': client_secret,
         'code': token, 'state': login_session['state']})

    resp, content = h.request(url, 'POST', body=body, headers=headers)

    if("error" in content):
        return {"response": "Incorrect web token.", "status": 401}
    access_token = json.loads(content)['access_token']

    url = ('https://api.github.com/user?access_token=%s' % access_token)
    resp, content = h.request(url, 'GET')

    if(resp['status'] == 401):
        return {"response": "Bad credentials.", "status": 401}

    user_data = json.loads(content)
    login_session.update({
        'account': 'Github',
        'username': user_data['login'],
        'user_id': user_data['id'],
        'email': user_data['email'],
        'picture': user_data['avatar_url'],
        'access_token': access_token})

    registerUser()
    return {"response": "Login Successful.", "status": 200}


def serializeItem(item):
    """
    Serialize Item object and add change the image url
    to serve for client's endpoint
    params: item(object): Item Object
    returns dict: serialized item
    """
    ret = item.serialize
    ret['image'] = url_for('uploaded_file', filename=ret['image'],
                           _external=True)
    return ret

def getURLImage(filename):
    return app.config['AWS_HOST'] + filename

@app.route('/images/<filename>')
def uploaded_file(filename):
    """
    Serves the image from the upload folder
    params: filename(string): Filename
    returns string: path to the image
    """
    if filename == 'None':
        filename = 'placeholder.jpg'

    # generate_img(path)
    # fullpath = 'https://s3-us-west-2.amazonaws.com/elasticbeanstalk-us-west-2-369336360970/item-catalog-uploads/'+filename
    # resp = flask.make_response(open(fullpath).read())
    # resp.content_type = "image/jpeg"
    # print('sad')
    # send_file(fullpath)
    # return s3.meta.client.download_file(
    #     app.config['AWS_BUCKET'],
    #     filename,
    #     os.path.join(app.config['AWS_PATH'], filename))

    # return resp
    return send_from_directory(app.config['UPLOAD_FOLDER'],
        filename)


@app.route('/login')
def showLogin():
    """
    Displays the login Page for sign-in
    """

    if 'username' in login_session:
        return redirect(url_for('displayItems'))

    login_session['state'] = randomToken()
    client_id = {
        'google': loadClientSecret('google')['web']['client_id'],
        'facebook': loadClientSecret('facebook')['web']['app_id'],
        'github': loadClientSecret('github')['client_id']}

    return render_template('login.html.j2', login_session=login_session,
                           client_id=client_id)


@app.route('/acctconnect', methods=['POST'])
def acctConnect():
    """
    Ajax call by the user to exchange token with the user info.
    """
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    data = json.loads(request.data)

    if(data['account'] == "Google"):
        ret = googleConnect(data['token'])

    if(data['account'] == "Facebook"):
        ret = facebookConnect(data['token'])

    if(data['account'] == "Github"):
        ret = githubConnect(data['token'])

    response = make_response(json.dumps(ret['response']), ret['status'])
    response.headers['Content-Type'] = 'application/json'
    return response


@app.route('/acctdisconnect')
def acctDisconnect():
    """
    Disconnects user and deletes the info from the session.
    """
    if(login_session['account'] == "Google"):
        ret = googleDisconnect()

    if(login_session['account'] == "Facebook"):
        ret = googleDisconnect()

    if(login_session['account'] == "Github"):
        # Cannot revoke Github access token.
        ret = {"response": "Successfully disconnected.", "status": 200}

    # print ret
    del login_session['account']
    del login_session['access_token']
    del login_session['user_id']
    del login_session['username']
    del login_session['email']
    del login_session['picture']

    return redirect(url_for('displayItems'))


@app.route('/ghcallback')
def ghCallback():
    """
    Callback window for Github account
    """
    ret = '<script>'\
        'var code = window.location.toString().replace(/.+code=/, \'\');' \
        'window.opener.githubCallback(code);' \
        'window.close();' \
        '</script>'

    return ret


@app.route('/')
@app.route('/<endpoint>')
def displayItems(endpoint=None):
    """
    Displays all items from all categories.
    It also provides a JSON endpoint option.
    """
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
        getURLImage=getURLImage,
        title_text=title_text, cat_name="", login_session=login_session)


@app.route('/catalog/<int:cat_id>/')
@app.route('/catalog/<int:cat_id>/<endpoint>')
def displaySingleCatItems(cat_id, endpoint=None):
    """
    Displays all items from specific category.
    It also provides a JSON endpoint option.
    """
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
    """
    Displays single item detail.
    It also provides a JSON endpoint option.
    """
    item = session.query(CategoryItem) \
        .filter(CategoryItem.id == item_id).one()

    print(item.user.serialize)

    if endpoint == 'json':
        return jsonify(item=serializeItem(item))

    login_session['_csrf_token'] = randomToken()
    return render_template('item_details.html.j2', item=item, login_session=login_session)


@app.route('/item/edit/<int:item_id>/',
           methods=['GET', 'POST'])
def editItem(item_id):
    """
    Page for editing item
    """
    if 'username' not in login_session:
        return redirect(url_for('displayItemDetails', item_id=item_id))

    cats = session.query(Category).all()
    item = session.query(CategoryItem).join(CategoryItem.category) \
        .filter(CategoryItem.id == item_id).one()

    if login_session['registered_user'] != item.user_id:
        return redirect(url_for('displayItemDetails', item_id=item_id))

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
                    os.remove(os.path.join(
                        app.config['UPLOAD_FOLDER'], item.image))

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

        return render_template('item_edit.html.j2', cats=cats, item=item,
                               login_session=login_session)


@app.route('/item/add', methods=['GET', 'POST'])
def addItem():
    """
    Page to add an item
    """
    if 'username' not in login_session:
        return redirect(url_for('displayItems'))

    cats = session.query(Category).all()

    if request.method == 'POST':

        imagefile = None
        if 'image' in request.files:
            file = request.files['image']

            if file and (file.filename != '') and allowedFile(file.filename):
                imagefile = secure_filename(file.filename)
                imagefile = preventOverwrite(imagefile)
                # file.save(os.path.join(app.config['UPLOAD_FOLDER'], imagefile))
                # print(os.path.join(app.config['AWS_PATH'], imagefile))
                s3.meta.client.upload_fileobj(file, app.config['AWS_BUCKET'],os.path.join(app.config['AWS_PATH'], imagefile))
                # s3.meta.client.upload_file(
                #     imagefile,
                #     app.config['AWS_BUCKET'],imagefile)
                #print(type(file.read()))

                # s3.meta.client.upload_file(os.path.join(app.config['AWS_PATH'], imagefile), app.config['AWS_BUCKET'],imagefile)

        if request.form['_csrf_token'] != login_session['_csrf_token']:
            response = make_response(json.dumps("Invalid web token."), 400)
            response.headers['Content-Type'] = 'application/json'
            return response
        new_item = CategoryItem(
            name=request.form['name'],
            description=request.form['description'],
            category_id=request.form['category'],
            image=imagefile,
            user_id=login_session['registered_user'])

        session.add(new_item)
        session.commit()

        return redirect(url_for('displayItemDetails', item_id=new_item.id))
    else:
        login_session['_csrf_token'] = randomToken()
        return render_template('item_edit.html.j2', cats=cats, item=None,
                               login_session=login_session)


@app.route('/item/delete/<int:item_id>/',
           methods=['POST'])
def deleteItem(item_id):
    """
    Deletes an item
    """
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

    # print 'asdasdasd'
    # print item
    if login_session['registered_user'] != item.user_id:
        response = make_response(json.dumps("Unauthorized to delete."), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    session.delete(item)
    session.commit()

    return redirect(url_for('displayItems'))

@app.context_processor
def addAWSHost():
    return dict(aws_host=app.config['AWS_HOST'])


if __name__ == '__main__':
    app.secret_key = '1GrSamWXZ8ikGhg43UIUbw5X'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, make_response, send_from_directory, session as login_session
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, Category, CategoryItem
from werkzeug.utils import secure_filename
from oauth2client.client import flow_from_clientsecrets, FlowExchangeError
import os, random , urllib, string, httplib2, json, requests, pprint

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

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def prevent_overwrite(filename):
    i = 1
    f = filename.rsplit('.', 1)

    while os.path.isfile(os.path.join(app.config['UPLOAD_FOLDER'], filename)):
        filename = "%s_%d.%s" % (f[0], i, f[1])
        i += 1

    return filename

@app.route('/images/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'],
                               filename)


# ADD JSON API ENDPOINT HERE

@app.route('/login')
def showLogin():
    login_session['state'] = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    return render_template('login.html.j2', STATE=login_session['state'], login_session=login_session)

@app.route('/acctConnect', methods=['POST'])
def acctConnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # print request.data
    data = json.loads(request.data)
    print data['account']

    return "true"

@app.route('/ghcallback')
def ghCallback():
    ret = '<script>'\
        'var code = window.location.toString().replace(/.+code=/, \'\');' \
        'window.opener.githubCallback(code);' \
        'window.close();' \
        '</script>'

    return ret

@app.route('/ghconnect', methods=['POST'])
def ghconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    h = httplib2.Http()
    client_id = json.loads(open('client_secrets/github.json', 'r').read())['client_id']
    client_secret = json.loads(open('client_secrets/github.json', 'r').read())['client_secret']

    #  url = ('https://github.com/login/oauth/access_token?client_id=e6789cd05a49a53a00b6&client_secret=3d9f803979f5964e840d9c6cc6015b9f07eb4b8c&code=%s&state=%s'%(request.data, login_session['state']))
    url = 'https://github.com/login/oauth/access_token'
    headers = {'Accept':'application/json'}
    body = urllib.urlencode({ 'client_id': client_id, 'client_secret': client_secret, 'code': request.data, 'state':login_session['state']})


    resp, content = h.request(url, 'POST', body=body, headers=headers)

    #check for error??
    #200{"error":"bad_verification_code","error_description":"The code passed is incorrect or expired.","error_uri":"https://developer.github.com/v3/oauth/#bad-verification-code"}

    login_session['access_token'] = json.loads(content)['access_token']

    url = ('https://api.github.com/user?access_token=%s' % login_session['access_token'])

    #check for error??
    #401{"message":"Bad credentials","documentation_url":"https://developer.github.com/v3"}

    resp, content = h.request(url, 'GET')
    user_data = json.loads(content)

    login_session['username'] = user_data['login']
    login_session['picture'] = user_data['avatar_url']
    login_session['email'] = user_data['email']

    return "Login Successful"

@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data
    print "access token received %s " % access_token


    app_id = json.loads(open('client_secrets/facebook.json', 'r').read())[
        'web']['app_id']
    app_secret = json.loads(
        open('client_secrets/facebook.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]


    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.8/me"
    '''
        Due to the formatting for the result from the server token exchange we have to
        split the token first on commas and select the first index which gives us the key : value
        for the server access token then we split it on colons to pull out the actual token value
        and replace the remaining quotes with nothing so that it can be used directly in the graph
        api calls
    '''
    token = result.split(',')[0].split(':')[1].replace('"', '')

    url = 'https://graph.facebook.com/v2.8/me?access_token=%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    # login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    # login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    login_session['access_token'] = token

    # Get user picture
    url = 'https://graph.facebook.com/v2.8/me/picture?access_token=%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    # user_id = getUserID(login_session['email'])
    # if not user_id:
    #     user_id = createUser(login_session)

    # output = ''
    # output += '<h1>Welcome, '
    # output += login_session['username']
    #
    # output += '!</h1>'
    # output += '<img src="'
    # output += login_session['picture']
    # output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    #
    # flash("Now logged in as %s" % login_session['username'])
    return "Login Successful"

@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id,access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"

@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Obtain authorization code

    CLIENT_ID = json.loads(
        open('./client_secrets/google.json', 'r').read())['web']['client_id']

    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('./client_secrets/google.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # output = ''
    # output += '<h1>Welcome, '
    # output += login_session['username']
    # output += '!</h1>'
    # output += '<img src="'
    # output += login_session['picture']
    # output += ' " style = "width: 300px; height: 300px;border-radius: 150px;-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    # flash("you are now logged in as %s" % login_session['username'])
    # print "done!"
    return "Login Successfull"

@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        print 'Access Token is None'
        response = make_response(json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    print 'In gdisconnect access token is %s', access_token
    print 'User name is: '
    print login_session['username']
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % login_session['access_token']
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print 'result is '
    print result
    if result['status'] == '200':
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'

@app.route('/')
def displayItems():
    cats = session.query(Category).all()
    items = session.query(CategoryItem).order_by(CategoryItem.id).all()
    title_text = "Latest Items"

    return render_template(
        'display_items.html.j2', cats=cats, items=items,
        title_text=title_text, cat_name = "", login_session=login_session)

@app.route('/catalog/<int:cat_id>/')
def displaySingleCatItems(cat_id):
    cats = session.query(Category).all()
    curr_cat = session.query(Category).filter(Category.id==cat_id).one()
    items = session.query(CategoryItem) \
        .filter(CategoryItem.category_id==cat_id).all()

    title_text = "%s Items (%i items)" % (curr_cat.name, len(items))

    return render_template(
        'display_items.html.j2', cats=cats, items=items,
        title_text=title_text, cat_name = curr_cat.name, login_session=login_session)

@app.route('/item/<int:item_id>')
def displayItemDetails(item_id):
    item = session.query(CategoryItem).join(CategoryItem.category) \
        .filter(CategoryItem.id==item_id).one()
    return render_template('item_details.html.j2', item=item, login_session=login_session)

@app.route('/item/<int:item_id>/edit', \
    methods=['GET', 'POST'])
def editItem(item_id):
    cats = session.query(Category).all()
    item = session.query(CategoryItem).join(CategoryItem.category) \
        .filter(CategoryItem.id==item_id).one()

    if request.method == 'POST':
        item.name = request.form['name']
        item.description = request.form['description']
        item.category_id = request.form['category']

        imagefile = None

        if 'image' in request.files:
            file = request.files['image']

            if file and (file.filename != '') and allowed_file(file.filename):
                # delete exsisting file
                if item.image is not None:
                    os.remove(os.path.join(app.config['UPLOAD_FOLDER'],item.image))

                imagefile = secure_filename(file.filename)
                imagefile = prevent_overwrite(imagefile)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'],imagefile))

        item.image = imagefile

        session.add(item)
        session.commit()

        return redirect(url_for('displayItemDetails', item_id= item.id))
    else:
        return render_template('item_edit.html.j2', cats=cats, item=item, login_session=login_session)

@app.route('/item/add', methods=['GET', 'POST'])
def addItem():
    cats = session.query(Category).all()
    new_item = CategoryItem(name="", description="", category_id=-1)

    if request.method == 'POST':
        new_item.name = request.form['name']
        new_item.description = request.form['description']
        new_item.category_id = request.form['category']

        session.add(new_item)
        session.commit()

        return redirect(url_for('displayItemDetails', item_id= new_item.id))
    else:
        return render_template('item_edit.html.j2', cats=cats, item=None)

@app.route('/item/<int:item_id>/delete', \
    methods=['POST'])
def deleteItem(item_id):
    item = session.query(CategoryItem).join(CategoryItem.category) \
        .filter(CategoryItem.id==item_id).one()

    session.delete(item)
    session.commit()

    return redirect(url_for('displayItems'))

if __name__ == '__main__':
    app.secret_key = '1GrSamWXZ8ikGhg43UIUbw5X'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)

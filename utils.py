def loadClientSecret(account):
    """
    Loads Json File of client's Secret
    returns json: app client secret for authentication
    """
    file = (app.root_path + '/client_secrets/%s.json' % account)
    return json.loads(open(file, 'r').read())

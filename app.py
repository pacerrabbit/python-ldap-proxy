# Standard libs
import os

# Third party libs
from flask import Flask
from flask import abort
from flask import jsonify
from flask import request
import ldap

# Constants
LDAP_SERVER_URL = os.environ['LDAP_SERVER_URL']
AUTH_TOKEN = os.environ['AUTH_TOKEN']

# Initialize Flask app
app = Flask(__name__)

@app.route('/auth', methods=['POST'])
def auth():
    # Only allow requests with a valid auth token
    auth_token = request.headers.get('Auth-Token')
    if auth_token != AUTH_TOKEN:
        abort(403)

    user = request.form['user']
    password = request.form['password']
    get_user_info = request.form.get('get_user_info')

    # Connect to LDAP server
    client = ldap.initialize(LDAP_SERVER_URL)

    response_data = {}

    try:
        # Do a synchronous bind to verify the username/password combination
        client.simple_bind_s(user, password)

        # If successful, set the response status to success
        response_data['status'] = 'success'

        # Conditionally retrieve name and email
        if get_user_info:
            base_dn = request.form['base_dn']
            search_filter = request.form['search_filter']

            results = client.search_s(base_dn, ldap.SCOPE_SUBTREE, search_filter)

            try:
                name = results[0][1]['displayName'][0]
            except:
                name = ''

            try:
                email = results[0][1]['mail'][0]
            except:
                email = ''

            response_data['name'] = name
            response_data['email'] = email
    except ldap.LDAPError:
        # If the authentication fails, set an error status
        response_data['status'] = 'error'
    finally:
        # Close the connection to the LDAP server
        client.unbind()

    return jsonify(response_data)


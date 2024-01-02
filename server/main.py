from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from flask import Flask, request, jsonify
import uuid  # For generating session tokens
import json  # For parsing JSON
from base64 import b64encode, b64decode  # For encoding/decoding base64
import os
import atexit

app = Flask(__name__)

# Dummy storage for users and sessions
users = {}
sessions = {}

metadata_file = '.metadata.json'
data_folder = 'data'

"""
folder metadata:
{
    # Key
    'seed_k': '',
    'encrypted_key': '',

    # Name
    'seed_n': '',
    'encrypted_name': '',

    # Link
    'linked_to': ''
}
"""

"""
file metadata:
{
    # Key
    'seed_k': '',
    'encrypted_key': '',

    # Name
    'seed_n': '',
    'encrypted_name': '',

    # Data
    'seed_d': '',
}
"""

def folder_from_path(path, username):
    # Create server path
    server_path = f'{data_folder}/{username}/{path}'

    # Check if the path exists
    if not os.path.exists(server_path):
        return None
    
    # Get metadata from folder
    with open(f'{server_path}{metadata_file}', 'r') as f:
        metadata = json.load(f)
        return metadata

def create_root_folder(username, seed, encrypted_key):
    print(f'{data_folder}/{username}')

    # Check if the user already has a root folder
    if os.path.exists(f'{data_folder}/{username}'):
        return None

    # Create a root folder
    os.makedirs(f'{data_folder}/{username}')

    # Create json metadata file
    with open(f'{data_folder}/{username}/{metadata_file}', 'w') as f:
        json.dump({
            'seed_k': seed,
            'encrypted_key': encrypted_key,
            'linked_to': ''
        }, f)

def create_folder(username, name, parent, seed, encrypted_key):
    # Create a folder
    os.makedirs(f'{data_folder}/{username}/{parent}{name}')

    # Create json metadata file
    with open(f'{data_folder}/{username}/{parent}{name}/{metadata_file}', 'w') as f:
        json.dump({
            'seed': seed,
            'encrypted_key': encrypted_key,
            'linked_to': ''
        }, f)

def is_authenticated(session_token):
    return session_token in sessions

@app.route('/api', methods=['POST'])
def api():
    data = request.json
    session_token = data.get('session_token', None)
    request_type = data['request'].lower()

    # Get request data (if any)
    request_data = data.get('data', {})

    print(f'Received request: {request_type}')

    # print(users)
    # print(sessions)

    match request_type:
        case 'register_user':
            # Check if username already exists
            if request_data['username'] in users:
                # We can't register two users with the same username
                return jsonify({'error': 'Username already exists'}), 400
            else:
                # Add the user to the list of users
                users[request_data['username']] = {
                    'p_hash': request_data['p_hash'],
                    'p_salt': request_data['p_salt'],
                    'b64_pk': request_data['b64_pk'],
                    'e_b64_sk': request_data['e_b64_sk']
                }

                # Create a session token
                session_token = str(uuid.uuid4())
                sessions[session_token] = {
                    'username': request_data['username']
                }
                
                # Return the session token
                return jsonify({'session_token': session_token})
            
        case 'get_user_password_salt':
            # Check if username exists
            if request_data['username'] not in users:
                return jsonify({'error': 'User does not exist'}), 400
            else:
                # Return the user's salt
                return jsonify({'p_salt': users[request_data['username']]['p_salt']})
            
        case 'prepare_login':
            # Get username from request data
            username = request_data['username']

            # Get hashed password from request data
            p_hash = request_data['p_hash']

            # Verify that the user exists
            if username not in users:
                return jsonify({'error': 'User does not exist'}), 400
            
            # Verify that the password is correct
            if users[username]['p_hash'] != p_hash:
                return jsonify({'error': 'Invalid password'}), 400
            
            # Return the user's encrypted secret key
            return jsonify({'e_b64_sk': users[username]['e_b64_sk']})

        case 'login':
            # Generate random value as a challenge
            challenge = str(uuid.uuid4())

            # Generate session token
            session_token = str(uuid.uuid4())
            sessions[session_token] = {
                'username': request_data['username'],
                'challenge': challenge
            }

            # return the session token and challenge
            return jsonify({'session_token': session_token, 'challenge': challenge})

        case 'verify_login':
            # Verify that the session token is valid
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get the challenge from the session
            challenge = sessions[session_token]['challenge']
            username = sessions[session_token]['username']

            # Create a signing key from the user's public key
            pk = b64decode(users[username]['b64_pk'])
            verify_key = VerifyKey(pk)

            # Decode the signature
            signature = b64decode(request_data['signature'])
            challenge = challenge.encode('utf-8')

            # Verify the signature
            try:
                verify_key.verify(challenge, signature)
            except BadSignatureError:
                return jsonify({'error': 'Invalid signature'}), 400

            # Destroy the session
            sessions.pop(session_token)

            # Generate a new session token
            session_token = str(uuid.uuid4())
            sessions[session_token] = {
                'username': username
            }

            # return the session token
            return jsonify({'session_token': session_token})
        
        case 'create_root_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Check if the user already has a root folder
            if os.path.exists(f'{data_folder}/{sessions[session_token]["username"]}'):
                return jsonify({'message': 'Root folder already exists'})

            # Add the root folder to the list of folders
            create_root_folder(
                sessions[session_token]['username'],
                request_data['b64_seed_k'],
                request_data['e_b64_key']
            )
            
            return jsonify({'message': 'Root folder created successfully'})

        case 'logout':
            if is_authenticated(session_token):
                sessions.pop(session_token)
                return jsonify({'message': 'Logged out successfully'})
            else:
                return jsonify({'error': 'Invalid session token'}), 401

        case 'get_users':
            return jsonify({'users': list(users.keys())})

        case 'get_user_public_key':
            if request_data['username'] not in users:
                return jsonify({'error': 'User does not exist'}), 400

            return jsonify({'b64_pk': users[request_data['username']]['b64_pk']})

        case 'change_password':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get data
            username = sessions[session_token]['username']
            p_hash = request_data['p_hash']
            p_salt = request_data['p_salt']
            e_b64_sk = request_data['e_b64_sk']

            # Verify that the user exists
            if username not in users:
                return jsonify({'error': 'User does not exist'}), 400
            
            # Store the new password
            users[username]['p_hash'] = p_hash
            users[username]['p_salt'] = p_salt
            users[username]['e_b64_sk'] = e_b64_sk
            
            return jsonify({'message': 'Password changed successfully'})

        case 'create_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            pass

        case 'create_file':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
                
            # Add logic to create a file
            pass

        case 'get_file':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Add logic to get a file's content
            pass

        case 'get_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']

            # Create server path
            server_path = f'{data_folder}/{username}/{path}'

            # Check if the path exists
            if not os.path.exists(server_path):
                return jsonify({'error': 'Folder does not exist'}), 400
            
            # Get metadata from folder
            with open(f'{server_path}{metadata_file}', 'r') as f:
                metadata = json.load(f)

            toReturn = {
                'seed': metadata['seed'],
                'encrypted_key': metadata['encrypted_key'],
                'files': [],
                'folders': []
            }

            # Get files and folders
            for file in os.listdir(server_path):
                if file != metadata_file:
                    if os.path.isfile(f'{server_path}/{file}'):
                        # Get file metadata's file
                        with open(f'{server_path}/{file}{metadata_file}', 'r') as f:
                            toReturn['files'].append(json.load(f))
                    else:
                        # Get folder metadata
                        toReturn['folders'].append(file)

            return jsonify(toReturn)

        case 'update_file':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Add logic to update a file
            pass

        case 'update_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Add logic to update a folder
            pass

        case 'share_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Add logic to share a folder
            pass

        case 'share_file':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Add logic to share a file
            pass

        case 'revoke_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Add logic to revoke access to a folder
            pass

        case 'revoke_file':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Add logic to revoke access to a file
            pass

        case _:
            return jsonify({'error': 'Invalid request type'}), 400

    return jsonify({'message': 'Request processed'})

def at_exit():
    print('Saving users to file ...')
    # Save users to file
    with open(f'{data_folder}/users.json', 'w') as f:
        json.dump(users, f)

if __name__ == '__main__':
    # Create data folder if it doesn't exist
    if not os.path.exists(data_folder):
        os.makedirs(data_folder)
    else:
        # Check if users.json exists
        if os.path.exists(f'{data_folder}/users.json'):
            # Load users from file
            with open(f'{data_folder}/users.json', 'r') as f:
                users = json.load(f)

    # Register at_exit function
    atexit.register(at_exit)

    # https://blog.miguelgrinberg.com/post/running-your-flask-application-over-https
    app.run(debug=True, port=4242)

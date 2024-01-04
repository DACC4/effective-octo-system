from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from flask import Flask, request, jsonify
import uuid  # For generating session tokens
import json  # For parsing JSON
from base64 import b64encode, b64decode  # For encoding/decoding base64
import os # For creating folders and files
import atexit # For saving users to file
import shutil # For deleting folders

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
    'b64_seed_k': '',
    'e_b64_key': {
        'user1': '',
        'user2': '',
    }

    # Name
    'b64_seed_n': '',
    'e_b64_name': '',
}
"""

"""
file metadata:
{
    # Key
    'b64_seed_k': '',
    'e_b64_key': {
        'user1': '',
        'user2': '',
    }

    # Name
    'b64_seed_n': '',
    'e_b64_name': '',

    # Data
    'b64_seed_d': '',
}
"""

def sanitize_path(path):
    # Remove leading and trailing slash
    if len(path) != 0 and path[0] == '/':
        path = path[1:]
    if len(path) != 0 and path[-1] == '/':
        path = path[:-1]

    return path

def folder_from_path(path, username):
    # Create server path
    server_path = f'{data_folder}/{path}'

    # Check if the path exists
    if not os.path.exists(server_path):
        return None
    
    # Get metadata from folder
    with open(f'{server_path}/{metadata_file}', 'r') as f:
        metadata = json.load(f)

        # Check if the user has access to the folder
        if username not in metadata['e_b64_key']:
            return None
        
        # Return the folder metadata
        return metadata

def file_from_path(path, username):
    # Create server path
    server_path = f'{data_folder}/{path}'

    # Check if the path exists
    if not os.path.exists(server_path):
        return None
    
    # Get metadata from file
    with open(f'{server_path}{metadata_file}', 'r') as f:
        metadata = json.load(f)

        # Check if the user has access to the file
        if username not in metadata['e_b64_key']:
            return None

        return metadata
    
def get_file_content(path):
    # Create server path
    server_path = f'{data_folder}/{path}'

    # Check if the path exists
    if not os.path.exists(server_path):
        return None
    
    # Get metadata from file
    with open(f'{server_path}', 'r') as f:
        return f.read()
    
def create_file(name, parent, seed_k, encrypted_key, seed_n, encrypted_name, seed_d, encrypted_data):
    file_path = f'{data_folder}/{parent}/{name}'

    # Create a file
    with open(file_path, 'w') as f:
        f.write(encrypted_data)
    
    # Create json metadata file
    with open(f'{file_path}{metadata_file}', 'w') as f:
        json.dump({
            'b64_seed_k': seed_k,
            'e_b64_key': encrypted_key,

            'b64_seed_n': seed_n,
            'e_b64_name': encrypted_name,

            'b64_seed_d': seed_d,
        }, f)

def create_root_folder(username, seed, encrypted_key):
    # Check if the user already has a root folder
    if os.path.exists(f'{data_folder}/{username}'):
        return None

    # Create a root folder
    os.makedirs(f'{data_folder}/{username}')

    # Create json metadata file
    with open(f'{data_folder}/{username}/{metadata_file}', 'w') as f:
        json.dump({
            'b64_seed_k': seed,
            'e_b64_key': encrypted_key,

            'b64_seed_n': "",
            'e_b64_name': "",
        }, f)

def create_folder(name, parent, seed_k, encrypted_key, seed_n, encrypted_name):
    folder_path = f'{data_folder}/{parent}/{name}'

    # Create a folder
    os.makedirs(folder_path, exist_ok=True)

    # Create json metadata file
    with open(f'{folder_path}/{metadata_file}', 'w') as f:
        json.dump({
            'b64_seed_k': seed_k,
            'e_b64_key': encrypted_key,

            'b64_seed_n': seed_n,
            'e_b64_name': encrypted_name,
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
    print(f'Request data: {request_data}')

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

        case 'logout':
            if is_authenticated(session_token):
                sessions.pop(session_token)
                return jsonify({'message': 'Logged out successfully'})
            else:
                return jsonify({'error': 'Invalid session token'}), 401

        case 'get_users':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401

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
            
            # Get request data
            username = sessions[session_token]['username']
            name = request_data['e_b64_name']
            parent = request_data['parent']
            seed_k = request_data['b64_seed_k']
            encrypted_key = request_data['e_b64_key']
            seed_n = request_data['b64_seed_n']
            encrypted_name = request_data['e_b64_name']

            if '/' in name:
                name = name.replace('/', '&')

            folder_path = f'{data_folder}/{parent}/{name}'

            # Check if the parent folder exists
            if parent != '':
                if not os.path.exists(f'{data_folder}/{parent}'):
                    return jsonify({'error': 'Parent folder does not exist'}), 400
                
            # Check if the folder already exists
            if os.path.exists(f'{folder_path}'):
                return jsonify({'error': 'Folder already exists'}), 400
            
            # Add the folder to the list of folders
            create_folder(
                name,
                parent,
                seed_k,
                encrypted_key,
                seed_n,
                encrypted_name
            )

            return jsonify({'message': 'Folder created successfully'})

        case 'create_file':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
                
            # Get request data
            username = sessions[session_token]['username']
            name = request_data['e_b64_name']
            parent = request_data['parent']
            seed_k = request_data['b64_seed_k']
            encrypted_key = request_data['e_b64_key']
            seed_n = request_data['b64_seed_n']
            encrypted_name = request_data['e_b64_name']
            seed_d = request_data['b64_seed_d']
            encrypted_data = request_data['e_b64_data']

            if '/' in name:
                name = name.replace('/', '&')

            file_path = f'{data_folder}/{parent}/{name}'
            parent_path = f'{data_folder}/{parent}'

            # Check if the parent folder exists
            if parent != '':
                if not os.path.exists(f'{parent_path}'):
                    return jsonify({'error': 'Parent folder does not exist'}), 400
                
            # Check if the file already exists
            if os.path.exists(f'{file_path}'):
                return jsonify({'error': 'File already exists'}), 400
            
            # Create the file
            create_file(
                name,
                parent,
                seed_k,
                encrypted_key,
                seed_n,
                encrypted_name,
                seed_d,
                encrypted_data
            )

            return jsonify({'message': 'File created successfully'})

        case 'get_file':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']

            # Remove leading and trailing slash
            path = sanitize_path(path)

            # Get file metadata
            metadata = file_from_path(path, username)

            # Check if the file exists
            if metadata is None:
                return jsonify({'error': 'File does not exist'}), 400
            
            # Return the file metadata
            return jsonify(metadata)

        case 'get_file_data':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']

            # Remove leading and trailing slash
            path = sanitize_path(path)

            # Get file metadata
            metadata = file_from_path(path, username)

            # Check if the file exists
            if metadata is None:
                return jsonify({'error': 'File does not exist'}), 400
            
            # Get file content
            content = get_file_content(path)

            # Return the file  content
            return jsonify({
                'e_b64_data': content
            })

        case 'get_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']

            # Remove leading and trailing slash
            path = sanitize_path(path)

            # Get folder metadata
            metadata = folder_from_path(path, username)

            # Check if the folder exists
            if metadata is None:
                return jsonify({'error': 'Folder does not exist'}), 400
            
            # Return the folder metadata
            return jsonify(metadata)

        case 'list_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']

            # Remove leading and trailing slash
            path = sanitize_path(path)

            folder_path = f'{data_folder}/{path}'

            # Get folder metadata
            metadata = folder_from_path(path, username)

            # Check if the folder exists
            if metadata is None:
                return jsonify({'error': 'Folder does not exist'}), 400
            
            # Get files and folders in the folder
            files = {}
            folders = {}

            for f in os.listdir(f'{folder_path}'):
                if f == metadata_file or f.endswith(metadata_file):
                    continue

                sub_path = f'{path}/{f}'

                if os.path.isfile(f'{folder_path}/{f}'):
                    files[sub_path] = file_from_path(sub_path, username)
                else:
                    folders[sub_path] = folder_from_path(sub_path, username)

            # Add files and folders to the metadata
            metadata['files'] = files
            metadata['folders'] = folders
            
            # Return the folder metadata
            return jsonify(metadata)

        case 'rename_file':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']
            e_b64_name = request_data['e_b64_name']
            b64_seed_n = request_data['b64_seed_n']

            # Remove leading and trailing slash
            path = sanitize_path(path)

            # Get file metadata
            metadata = file_from_path(path, username)

            # Check if the file exists
            if metadata is None:
                return jsonify({'error': 'File does not exist'}), 400
            
            # Edit the file metadata
            metadata['e_b64_name'] = e_b64_name
            metadata['b64_seed_n'] = b64_seed_n

            # New path is old path without the last part and the new name (replace '/' with '&')
            new_name = e_b64_name.replace('/', '&')
            new_path = '/'.join(path.split('/')[:-1]) + '/' + new_name

            # Rename the file
            os.rename(f'{data_folder}/{path}', f'{data_folder}/{new_path}')

            # Remove the old metadata file
            os.remove(f'{data_folder}/{path}{metadata_file}')

            # Save the new file metadata
            with open(f'{data_folder}/{new_path}{metadata_file}', 'w') as f:
                json.dump(metadata, f)

            return jsonify({'message': 'File renamed successfully'})

        case 'rename_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']
            e_b64_name = request_data['e_b64_name']
            b64_seed_n = request_data['b64_seed_n']

            # Remove leading and trailing slash
            path = sanitize_path(path)

            # Get folder metadata
            metadata = folder_from_path(path, username)

            # Check if the folder exists
            if metadata is None:
                return jsonify({'error': 'Folder does not exist'}), 400
            
            # Edit the folder metadata
            metadata['e_b64_name'] = e_b64_name
            metadata['b64_seed_n'] = b64_seed_n

            # New path is old path without the last part and the new name (replace '/' with '&')
            new_name = e_b64_name.replace('/', '&')
            new_path = ''.join(path.split('/')[:-1]) + '/' + new_name

            # Rename the folder
            os.rename(f'{data_folder}/{path}', f'{data_folder}/{new_path}')

            # Save the folder metadata
            with open(f'{data_folder}/{new_path}/{metadata_file}', 'w') as f:
                json.dump(metadata, f)

            return jsonify({'message': 'Folder renamed successfully'})

        case 'delete_file':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']

            # Remove leading and trailing slash
            path = sanitize_path(path)

            # Get file metadata
            metadata = file_from_path(path, username)

            # Check if the file exists
            if metadata is None:
                return jsonify({'error': 'File does not exist'}), 400
            
            # Delete the file
            os.remove(f'{data_folder}/{path}')
            
            # Delete the file metadata
            os.remove(f'{data_folder}/{path}{metadata_file}')

            return jsonify({'message': 'File deleted successfully'})

        case 'delete_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']

            # Remove leading and trailing slash
            path = sanitize_path(path)

            # Get folder metadata
            metadata = folder_from_path(path, username)

            # Check if the folder exists
            if metadata is None:
                return jsonify({'error': 'Folder does not exist'}), 400
            
            # Delete the folder (and its contents)
            shutil.rmtree(f'{data_folder}/{path}')

            return jsonify({'message': 'Folder deleted successfully'})

        case 'share_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']
            user = request_data['username']
            e_b64_key = request_data['e_b64_key']

            # Remove leading and trailing slash
            path = sanitize_path(path)

            # Get folder metadata
            metadata = folder_from_path(path, username)

            # Check if the folder exists
            if metadata is None:
                return jsonify({'error': 'Folder does not exist'}), 400
            
            # Check if the user exists
            if user not in users:
                return jsonify({'error': 'User does not exist'}), 400
            
            # Check if the user already has access to the folder
            if user in metadata['e_b64_key']:
                return jsonify({'error': 'User already has direct access to the folder'}), 400
            
            # Add the user to the list of users with access to the folder
            metadata['e_b64_key'][user] = e_b64_key

            # Save the folder metadata
            with open(f'{data_folder}/{path}/{metadata_file}', 'w') as f:
                json.dump(metadata, f)

            return jsonify({'message': 'Folder shared successfully'})

        case 'share_file':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Get request data
            username = sessions[session_token]['username']
            path = request_data['path']
            user = request_data['username']
            e_b64_key = request_data['e_b64_key']

            # Remove leading and trailing slash
            path = sanitize_path(path)

            # Get file metadata
            metadata = file_from_path(path, username)

            # Check if the file exists
            if metadata is None:
                return jsonify({'error': 'File does not exist'}), 400
            
            # Check if the user exists
            if user not in users:
                return jsonify({'error': 'User does not exist'}), 400
            
            # Check if the user already has access to the file
            if user in metadata['e_b64_key']:
                return jsonify({'error': 'User already has direct access to the file'}), 400
            
            # Add the user to the list of users with access to the file
            metadata['e_b64_key'][user] = e_b64_key

            # Save the file metadata
            with open(f'{data_folder}/{path}/{metadata_file}', 'w') as f:
                json.dump(metadata, f)

            return jsonify({'message': 'File shared successfully'})

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
    app.run(debug=False, port=4242)

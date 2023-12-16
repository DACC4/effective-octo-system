from nacl.signing import VerifyKey
from nacl.exceptions import BadSignatureError
from flask import Flask, request, jsonify
import uuid  # For generating session tokens
import json  # For parsing JSON
from base64 import b64encode, b64decode  # For encoding/decoding base64

app = Flask(__name__)

# Dummy storage for users and sessions
users = {}
sessions = {}

def is_authenticated(session_token):
    return session_token in sessions

@app.route('/api', methods=['POST'])
def api():
    data = request.json
    session_token = data.get('session_token', None)
    request_type = data['request'].lower()
    request_data = json.loads(data['data'])

    print(f'Received request: {request_type}')

    print(users)
    print(sessions)

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
                    'b64_pk': request_data['b64_pk'],
                    'e_b64_sk': request_data['e_b64_sk']
                }
                return jsonify({'message': 'Registered successfully'})
            
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

            # Create a signing key from the user's public key
            pk = b64decode(users[sessions[session_token]['username']]['b64_pk'])
            verify_key = VerifyKey(pk)

            # Decode the signature
            signature = b64decode(request_data['signature'])
            challenge = challenge.encode('utf-8')

            # Verify the signature
            try:
                signed_challenge = verify_key.verify(challenge, signature)
            except BadSignatureError:
                return jsonify({'error': 'Invalid signature'}), 400

            # Destroy the session
            sessions.pop(session_token)

            # Generate a new session token
            session_token = str(uuid.uuid4())
            sessions[session_token] = {
                'username': request_data['username']
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
            return jsonify({'users': list(users.keys())})

        case 'get_user_public_key':
            if request_data['username'] not in users:
                return jsonify({'error': 'User does not exist'}), 400

            return jsonify({'b64_pk': users[request_data['username']]['b64_pk']})

        case 'change_password':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            if request_data['username'] not in users:
                return jsonify({'error': 'User does not exist'}), 400
            
            users[request_data['username']]['e_b64_sk'] = request_data['e_b64_sk']
            return jsonify({'message': 'Password changed successfully'})

        case 'create_folder':
            if not is_authenticated(session_token):
                return jsonify({'error': 'Invalid session token'}), 401
            
            # Add logic to create a folder
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
            
            # Add logic to get a folder's content
            pass

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

if __name__ == '__main__':
    app.run(debug=True, port=4242)

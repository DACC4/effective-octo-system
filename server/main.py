from nacl.signing import SigningKey
from flask import Flask, request, jsonify
import uuid  # For generating session tokens
import json  # For parsing JSON

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

    match request_type:
        case 'register_user':
            # Check if username already exists
            if request_data['username'] in users:
                # We can't register two users with the same username
                return jsonify({'error': 'Username already exists'}), 400
            else:
                # Add the user to the list of users
                users[request_data['username']] = {
                    'b64_pk': request_data['b64_pk'],
                    'e_b64_sk': request_data['e_b64_sk']
                }
                return jsonify({'message': 'Registered successfully'})
            
        case 'prepare_login':
            # Add logic to prepare login
            pass

        case 'login':
            # Add logic for login
            # Generate session token as an example
            session_token = str(uuid.uuid4())
            sessions[session_token] = request_data['username']
            return jsonify({'session_token': session_token})

        case 'verify_login':
            # Add logic to verify login
            pass

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

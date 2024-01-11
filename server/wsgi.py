from main import app

if __name__ == "__main__":
    # Check if data directory exists
    import os
    if not os.path.exists('data'):
        os.makedirs('data')

    app.run(host='0.0.0.0', debug=False, port=4242)
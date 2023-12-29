# Store current directory
current_dir=$(pwd)

# ---------------------------
# ---------------------------

path="server"
executable="main.py"

# Go to the server directory
cd $path

# Start the server in the background with all outputs erased and store the PID
python3 $executable > /dev/null 2>&1 &
pid=$!
sleep 1

# Go back to the current directory
cd $current_dir

# ---------------------------
# ---------------------------

path="code/cmake-build-debug"
executable="eos"

# Go to the build directory
cd $path

# ---------------------------
echo "Configuring"
./$executable config localhost 4242

echo "Registering user"
./$executable register username password

echo "Logging in"
./$executable login username password

# ---------------------------

# Go back to the current directory
cd $current_dir

# Kill the server
kill $pid
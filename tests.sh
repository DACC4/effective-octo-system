# Store current directory
current_dir=$(pwd)

# ---------------------------
# ---------------------------

path="server"
executable="main.py"

# Go to the server directory
cd $path

# Delete data folder if it exists
if [ -d "data" ]; then
    rm -rf data
fi

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

file_content="Hello World!"

# Go to the build directory
cd $path

# ---------------------------
echo "\nConfiguring"
./$executable config localhost 4242

echo "\nRegistering user"
./$executable register username password

echo "\nLogging in"
./$executable login username password

echo "\nChanging password"
./$executable change_password password2

echo "\nLogging out"
./$executable logout

echo "\nLogging in with new password"
./$executable login username password2

# ---------------------------

echo "\nLisiting files"
./$executable list /

echo "\nCreating new folders"
./$executable create_folder /folder1
./$executable create_folder /folder2
./$executable create_folder /folder3

echo "\nLisiting folders"
./$executable list /

echo "\nCreating embedded folders"
./$executable create_folder /folder1/folder1.1
./$executable create_folder /folder1/folder1.2
./$executable create_folder /folder1/folder1.3
./$executable create_folder /folder2/folder2.1
./$executable create_folder /folder2/folder2.2
./$executable create_folder /folder2/folder2.3
./$executable create_folder /folder3/folder3.1
./$executable create_folder /folder3/folder3.2
./$executable create_folder /folder3/folder3.3

echo "\nLisiting embedded folders"
echo "\nFolder 1"
./$executable list /folder1
echo "\nFolder 2"
./$executable list /folder2
echo "\nFolder 3"
./$executable list /folder3

# Create local file to upload
echo $file_content > example.txt

echo "\nCreating files"
./$executable upload example.txt /secret.txt
./$executable upload example.txt /folder1/secret.txt
./$executable upload example.txt /folder1/folder1.1/secret.txt
./$executable upload example.txt /folder1/folder1.2/secret.txt
./$executable upload example.txt /folder1/folder1.3/secret.txt
./$executable upload example.txt /folder2/secret.txt
./$executable upload example.txt /folder2/folder2.1/secret.txt
./$executable upload example.txt /folder2/folder2.2/secret.txt
./$executable upload example.txt /folder2/folder2.3/secret.txt
./$executable upload example.txt /folder3/secret.txt
./$executable upload example.txt /folder3/folder3.1/secret.txt
./$executable upload example.txt /folder3/folder3.2/secret.txt
./$executable upload example.txt /folder3/folder3.3/secret.txt

echo "\nLisiting files"
echo "\nRoot"
./$executable list /
echo "\nFolder 1"
./$executable list /folder1
echo "\nFolder 1.1"
./$executable list /folder1/folder1.1

echo "\nDownloading files and checking their content"

./$executable download /secret.txt
diff example.txt secret.txt
rm secret.txt

./$executable download /folder1/secret.txt
diff example.txt secret.txt
rm secret.txt

./$executable download /folder1/folder1.1/secret.txt
diff example.txt secret.txt
rm secret.txt

# ---------------------------

echo "\nRenaming /secret.txt to /secret2.txt"
./$executable rename /secret.txt secret2.txt

echo "\nRenaming /folder1/secret.txt to /folder1/secret2.txt"
./$executable rename /folder1/secret.txt secret2.txt

echo "\nLisiting files"
echo "\nRoot"
./$executable list /
echo "\nFolder 1"
./$executable list /folder1

echo "\nDownloading files and checking their content"

./$executable download /secret2.txt
diff example.txt secret2.txt
rm secret2.txt

./$executable download /folder1/secret2.txt
diff example.txt secret2.txt
rm secret2.txt

# ---------------------------

echo "\nRenaming /folder1 to /folder4"
./$executable rename_folder /folder1 folder4

echo "\nLisiting files"
echo "\nRoot"
./$executable list /
echo "\nFolder 4"
./$executable list /folder4

echo "\nDownloading files and checking their content"

./$executable download /folder4/secret2.txt
diff example.txt secret2.txt
rm secret2.txt

# ---------------------------

echo "\nDeleting /folder4/secret2.txt"
./$executable delete /folder4/secret2.txt

echo "\nLisiting /folder4"
echo "\nFolder 4"
./$executable list /folder4

# ---------------------------

echo "\nDeleting /folder4"
./$executable delete_folder /folder4

echo "\nLisiting root folder"
./$executable list /

# ---------------------------

# Delete local file
rm example.txt

# Go back to the current directory
cd $current_dir

# Kill the server
kill $pid
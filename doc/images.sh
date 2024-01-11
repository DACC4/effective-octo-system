mmd_files=$(find project_mermaid -name "*.mmd")
for mmd_file in $mmd_files
do
    img_file=$(echo $mmd_file | sed 's/project_mermaid/project_images/g' | sed 's/.mmd/.png/g')
    
    echo "Converting $mmd_file to $img_file"

    mmdc -i $mmd_file -o $img_file
done

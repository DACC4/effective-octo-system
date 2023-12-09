mmd_files=$(find project_mermaid -name "*.mmd")
for mmd_file in $mmd_files
do
    svg_file=$(echo $mmd_file | sed 's/project_mermaid/project_images/g' | sed 's/.mmd/.svg/g')
    
    echo "Converting $mmd_file to $svg_file"

    mmdc -i $mmd_file -o $svg_file
done

#!/bin/bash

# Arguments passed to both the custom scanner and Nmap
tcpPorts="21,80"
target="2a00:1450:4014:80f::200e"

# Run your program and save the output, while also displaying it in real-time
(dotnet run --interface tun0 -t "$tcpPorts" -w 1200 "$target" | tee my_scan_output_raw.txt) 2>&1

# Run Nmap and format its output similarly to your program
nmap -6 -p "$tcpPorts" "$target" | awk '/^[0-9]+\/(tcp|udp)/ {split($1, a, "/"); print "'$target'", a[1], a[2], $2}' > nmap_output.txt

# Save original Nmap output for comparison
nmap -6 -p "$tcpPorts" "$target" > original_nmap_output.txt

# Filter out lines that do not start with the target address
grep "^$target" my_scan_output_raw.txt > my_scan_output.txt

# Compare the outputs and save to diff_output.txt
diff -u <(sort my_scan_output.txt) <(sort nmap_output.txt) > diff_output.txt

# Check if there are differences
if [[ -s diff_output.txt ]]; then
    # If differences are found, print in red
    echo -e "\033[0;31mDifferences found. Check diff_output.txt for details.\033[0m"
else
    # If no differences, print in green
    echo -e "\033[0;32mOK - The outputs match!\033[0m"
fi

# Display original Nmap output
echo -e "\n\033[0;34mOriginal Nmap Output:\033[0m"
cat original_nmap_output.txt
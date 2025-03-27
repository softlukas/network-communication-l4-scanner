#!/bin/bash

run_test() {
    local interface="$1"
    local tcpPorts="$2"
    local udpPorts="$3"
    local timeout="$4"
    local target="$5"
    local test_name="$6"
    local ip_version="$7" # Accepts "ipv4", "ipv6", or "both"

    # Create a directory for the test logs
    mkdir -p "$test_name"

    # Define filenames in the test-specific directory
    my_output_file="$test_name/${test_name}_my_scan_output.txt"
    nmap_output_file="$test_name/${test_name}_nmap_output.txt"
    diff_output_file="$test_name/${test_name}_diff_output.txt"

    # Run your program (located one directory up) and save the output silently
    cd ..
    ./ipk-l4-scan --interface "$interface" -t "$tcpPorts" -u "$udpPorts" -w "$timeout" "$target" > tests/"$my_output_file"
    cd tests

    # Run Nmap based on IP version selection
    > "$nmap_output_file"  # Clear the file before writing
    if [[ "$ip_version" == "ipv4" || "$ip_version" == "both" ]]; then
        nmap -4 -p "$tcpPorts" "$target" | awk '/^[0-9]+\/(tcp|udp)/ {split($1, a, "/"); print "'$target'", a[1], a[2], $2}' >> "$nmap_output_file"
        
        nmap -4 -sU -p "$udpPorts" "$target" | awk '/^[0-9]+\/(tcp|udp)/ {gsub("open\\|filtered", "open", $3); gsub("filtered", "open", $3); split($1, a, "/"); print "'$target'", a[1], a[2], $2}' >> "$nmap_output_file"


    fi

    if [[ "$ip_version" == "ipv6" || "$ip_version" == "both" ]]; then
        nmap -6 -p "$tcpPorts" "$target" | awk '/^[0-9]+\/(tcp|udp)/ {split($1, a, "/"); print "'$target'", a[1], a[2], $2}' >> "$nmap_output_file"
        
        nmap -6 -sU -p "$udpPorts" "$target" | awk '/^[0-9]+\/(tcp|udp)/ {gsub("open\\|filtered", "open", $3); gsub("filtered", "open", $3); split($1, a, "/"); print "'$target'", a[1], a[2], $2}' >> "$nmap_output_file"
    fi

    if [[ "$ip_version" == "lo" || "$ip_version" == "both" ]]; then
        nmap -p "$tcpPorts" "$target" | awk '/^[0-9]+\/(tcp|udp)/ {split($1, a, "/"); print "'$target'", a[1], a[2], $2}' >> "$nmap_output_file"
    fi

    # Save original Nmap output for comparison  
    if [[ "$ip_version" == "ipv4" || "$ip_version" == "both" ]]; then
        nmap -4 -p "$tcpPorts" "$target" > "$test_name/${test_name}_original_nmap_ipv4_output.txt"
        nmap -4 -sU -p "$udpPorts" "$target" > "$test_name/${test_name}_original_nmap_ipv6_output.txt"
    fi
    if [[ "$ip_version" == "ipv6" || "$ip_version" == "both" ]]; then
        nmap -6 -p "$tcpPorts" "$target" > "$test_name/${test_name}_original_nmap_ipv6_output.txt"
        nmap -6 -sU -p "$udpPorts" "$target" > "$test_name/${test_name}_original_nmap_ipv6_output.txt"
    fi

    # Filter out lines that do not start with the target address
    grep "^$target" "$my_output_file" > "$test_name/${test_name}_filtered_my_output.txt"

    # Compare the outputs and save to diff_output_file
    diff -u <(sort "$test_name/${test_name}_filtered_my_output.txt") <(sort "$nmap_output_file") > "$diff_output_file"

    # Check if there are differences
    if [[ -s "$diff_output_file" ]]; then
        echo -e "\033[0;31mTest $test_name (Ports: $tcpPorts, Target: $target, Timeout: $timeout, IP: $ip_version): FAILURE\033[0m"
    else
        echo -e "\033[0;32mTest $test_name (Ports: $tcpPorts, Target: $target, Timeout: $timeout, IP: $ip_version): SUCCESS\033[0m"
    fi
}

# Ipv6 test - google public ipv6
run_test "tun0" "21,22,80,143" "67" "1500" "2a00:1450:4014:80f::200e" "test1" "ipv6"

# Ipv6 test - server from nmap org

run_test "tun0" "21,22,80,143" "67" "1500" "2600:3c01::f03c:91ff:fe18:bb2f" "test2" "ipv6"

#Ipv4 test nmap
run_test "enp0s3" "21,22,80,143" "67" "1500" "45.33.32.156" "test3" "ipv4"





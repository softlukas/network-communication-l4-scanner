#!/bin/bash

run_test() {
    local interface="$1"
    local tcpPorts="$2"
    local udpPorts="$3"
    local timeout="$4"
    local target="$5"
    local test_name="$6"
    local ip_version="$7" # Accepts "ipv4", "ipv6", or "both"

    # Define filenames
    my_output_file="${test_name}_my_scan_output.txt"
    nmap_output_file="${test_name}_nmap_output.txt"
    diff_output_file="${test_name}_diff_output.txt"

    # Run your program (located one directory up) and save the output silently
    dotnet run --project ../ --interface "$interface" -t "$tcpPorts" -u "$udpPorts" -w "$timeout" "$target" > "$my_output_file" 2>/dev/null

    # Run Nmap based on IP version selection
    > "$nmap_output_file"  # Clear the file before writing
    if [[ "$ip_version" == "ipv4" || "$ip_version" == "both" ]]; then
        nmap -4 -p "$tcpPorts" "$target" | awk '/^[0-9]+\/(tcp|udp)/ {split($1, a, "/"); print "'$target'", a[1], a[2], $2}' >> "$nmap_output_file"
    fi

    if [[ "$ip_version" == "ipv6" || "$ip_version" == "both" ]]; then
        nmap -6 -p "$tcpPorts" "$target" | awk '/^[0-9]+\/(tcp|udp)/ {split($1, a, "/"); print "'$target'", a[1], a[2], $2}' >> "$nmap_output_file"
    fi

    # Save original Nmap output for comparison
    if [[ "$ip_version" == "ipv4" || "$ip_version" == "both" ]]; then
        nmap -4 -p "$tcpPorts" "$target" > "${test_name}_original_nmap_ipv4_output.txt"
    fi
    if [[ "$ip_version" == "ipv6" || "$ip_version" == "both" ]]; then
        nmap -6 -p "$tcpPorts" "$target" > "${test_name}_original_nmap_ipv6_output.txt"
    fi

    # Filter out lines that do not start with the target address
    grep "^$target" "$my_output_file" > "${test_name}_filtered_my_output.txt"

    # Compare the outputs and save to diff_output_file
    diff -u <(sort "${test_name}_filtered_my_output.txt") <(sort "$nmap_output_file") > "$diff_output_file"

    # Check if there are differences
    if [[ -s "$diff_output_file" ]]; then
        echo -e "\033[0;31mTest $test_name (Ports: $tcpPorts, Target: $target, Timeout: $timeout, IP: $ip_version): FAILURE\033[0m"
    else
        echo -e "\033[0;32mTest $test_name (Ports: $tcpPorts, Target: $target, Timeout: $timeout, IP: $ip_version): SUCCESS\033[0m"
    fi
}

# Example tests
run_test "tun0" "21,22,80,143" "" "900" "2a00:1450:4014:80f::200e"  "test1" "ipv6"
#run_test "enp0s3" "21,22,80,143" "1500" "142.251.37.110"  "test2" "ipv4"
#un_test "enp0s3" "" "53,67" "1500" "142.251.37.110"  "test3" "ipv4"

#!/bin/bash
# Function for banner grabbing using Netcat
netcat_banner_grabbing() {
    target_ip=$(zenity --entry --title="Netcat Banner Grabbing" --text="Enter target IP address:")
    if [ -z "$target_ip" ]; then
        zenity --error --title="Error" --text="IP address cannot be empty."
        exit 1
    fi

    port=$(zenity --entry --title="Netcat Banner Grabbing" --text="Enter target port:")
    if [ -z "$port" ]; then
        zenity --error --title="Error" --text="Port cannot be empty."
        exit 1
    fi

    zenity --info --title="Netcat Banner Grabbing" --text="Performing banner grabbing on $target_ip:$port..."

    # Use Netcat to grab the banner
    banner=$(nc "$target_ip" "$port")

    if [ -z "$banner" ]; then
        zenity --info --title="Netcat Banner Grabbing" --text="No banner information retrieved from $target_ip:$port."
    else
        zenity --text-info --title="Netcat Banner Grabbing Results" --text="$banner"
    fi
}

# Function for password cracking using John the Ripper
john_the_ripper() {
    # Get file paths and options from user
    wordlist=$(zenity --file-selection --title="Select Password Wordlist" --text="Choose the wordlist file:")
    if [ ! -f "$wordlist" ]; then
        zenity --error --title="Error" --text="Wordlist file does not exist."
        exit 1
    fi

    hash_file=$(zenity --file-selection --title="Select Hash File" --text="Choose the hash file to crack:")
    if [ ! -f "$hash_file" ]; then
        zenity --error --title="Error" --text="Hash file does not exist."
        exit 1
    fi

    zenity --info --title="John the Ripper" --text="Starting password cracking using John the Ripper with the provided wordlist and hash file."

    # Run John the Ripper
    john --wordlist="$wordlist" "$hash_file"

    # Display the results
    results=$(john --show "$hash_file")
    zenity --text-info --title="Crack Results" --text="$results"
}

# Function to perform ARP Spoofing
arp_spoofing() {
    target_ip=$(zenity --entry --title="ARP Spoofing" --text="Enter target IP address:")
    if [ -z "$target_ip" ]; then
        zenity --error --title="Error" --text="Target IP address cannot be empty."
        exit 1
    fi

    gateway_ip=$(zenity --entry --title="ARP Spoofing" --text="Enter gateway IP address:")
    if [ -z "$gateway_ip" ]; then
        zenity --error --title="Error" --text="Gateway IP address cannot be empty."
        exit 1
    fi

    interface=$(zenity --entry --title="ARP Spoofing" --text="Enter network interface (e.g., eth0):")
    if [ -z "$interface" ]; then
        zenity --error --title="Error" --text="Network interface cannot be empty."
        exit 1
    fi

    zenity --info --title="ARP Spoofing" --text="Starting ARP spoofing. This will target $target_ip and redirect traffic to $gateway_ip."

    # Start ARP spoofing
    sudo arpspoof -i "$interface" -t "$target_ip" "$gateway_ip" &
    arpspoof_pid1=$!

    sudo arpspoof -i "$interface" -t "$gateway_ip" "$target_ip" &
    arpspoof_pid2=$!

    zenity --info --title="ARP Spoofing" --text="ARP spoofing started. Press OK to stop it."

    # Stop the arpspoof processes
    sleep 1  # Give it a second to ensure processes start
    kill "$arpspoof_pid1" 2>/dev/null
    kill "$arpspoof_pid2" 2>/dev/null

    zenity --info --title="ARP Spoofing" --text="ARP spoofing stopped."
}

# Function for IP stress testing
stress_test_ip() {
    target_ip=$(zenity --entry --title="Stress Test IP" --text="Enter target IP address:")
    if [ -z "$target_ip" ]; then
        zenity --error --title="Error" --text="IP address cannot be empty."
        exit 1
    fi

    duration=$(zenity --entry --title="Stress Test IP" --text="Enter duration for stress test (e.g., 60s for 60 seconds):")
    if [ -z "$duration" ]; then
        zenity --error --title="Error" --text="Duration cannot be empty."
        exit 1
    fi

    zenity --info --title="Stress Test" --text="Starting stress test on $target_ip for $duration..."

    # Perform stress test using HPing with sudo
    sudo hping3 --flood --rand-source "$target_ip" &

    # Capture the PID of the HPing process
    hping_pid=$!

    # Inform the user and wait for the specified duration
    zenity --info --title="Stress Test" --text="Stress test started on $target_ip. Test will run for $duration."
    sleep "$duration"

    # Stop the HPing process
    kill $hping_pid
    zenity --info --title="Stress Test" --text="Stress test completed."
}


# Function for DNS reconnaissance
dns_recon() {
    domain=$(zenity --entry --title="DNS Reconnaissance" --text="Enter domain name:")

    if [ -z "$domain" ]; then
        zenity --error --title="Error" --text="Domain name cannot be empty."
        exit 1
    fi

    # Perform DNS lookup
    dns_result=$(dig "$domain" ANY +short)

    if [ -z "$dns_result" ]; then
        zenity --info --title="DNS Recon Results" --text="No DNS records found for $domain."
    else
        zenity --text-info --title="DNS Recon Results" --text="$dns_result"
    fi
}

# Function for IP-based password cracking using Hydra
password_cracker() {
    target_ip=$(zenity --entry --title="Password Cracker" --text="Enter target IP:")
    service=$(zenity --entry --title="Password Cracker" --text="Enter service (e.g., ssh, ftp):")
    method=$(zenity --list --title="Password Cracker" --text="Choose cracking method:" --radiolist --column="Select" --column="Method" TRUE "Brute-force" FALSE "Pattern-based")
    user_list=$(zenity --file-selection --title="Password Cracker" --text="Select username list file:")

    if [ ! -f "$user_list" ]; then
        zenity --error --title="Error" --text="Username list file does not exist."
        exit 1
    fi

    if [ "$method" = "Brute-force" ]; then
        password_list=$(zenity --file-selection --title="Password Cracker" --text="Select password list file:")
        if [ ! -f "$password_list" ]; then
            zenity --error --title="Error" --text="Password list file does not exist."
            exit 1
        fi
        zenity --info --title="Hydra Attack" --text="Starting Hydra brute-force attack on $target_ip using $service..."
        hydra -L "$user_list" -P "$password_list" "$target_ip" "$service"
    else
        pattern=$(zenity --entry --title="Pattern-based Cracking" --text="Enter password pattern (e.g., 'pass123[1-9]'):")
        zenity --info --title="Hydra Attack" --text="Starting Hydra pattern-based attack on $target_ip using $service..."
        hydra -L "$user_list" -p "$pattern" "$target_ip" "$service"
    fi
}

# Function to get IP geolocation from ip-api.com
ip_geolocator() {
    public_ip=$(zenity --entry --title="IP Geolocator" --text="Enter public IP:")
    curl "http://ip-api.com/json/$public_ip" | zenity --text-info --title="IP Geolocation"
}

# Function to scan a range of IP addresses and save active IPs to a file
ip_scanner() {
    start_ip=$(zenity --entry --title="IP Scanner" --text="Enter start IP:")
    end_ip=$(zenity --entry --title="IP Scanner" --text="Enter end IP:")

    # Create a temporary file for IPs
    ip_file=$(mktemp)

    # Generate IPs and write to file
    IFS=. read -r i1 i2 i3 i4 <<< "$start_ip"
    start=$((i1 * 256**3 + i2 * 256**2 + i3 * 256 + i4))
    IFS=. read -r i1 i2 i3 i4 <<< "$end_ip"
    end=$((i1 * 256**3 + i2 * 256**2 + i3 * 256 + i4))

    for ((ip=$start; ip<=$end; ip++)); do
        octet1=$((ip >> 24 & 255))
        octet2=$((ip >> 16 & 255))
        octet3=$((ip >> 8 & 255))
        octet4=$((ip & 255))
        echo "$octet1.$octet2.$octet3.$octet4" >> "$ip_file"
    done

    zenity --info --title="IP Scanner" --text="Scanning IP range from $start_ip to $end_ip..."
    
    # Perform the scan and store active IPs
    active_ips=$(nmap -sn -n -T4 --min-rate=1000 --max-retries=1 -iL "$ip_file" | grep "Nmap scan report for" | awk '{print $NF}')
    
    # Save active IPs to active_ips.txt
    if [ -n "$active_ips" ]; then
        echo "$active_ips" > active_ips.txt
        zenity --info --title="Active IPs" --text="Active IPs saved to active_ips.txt:\n$active_ips"
    else
        zenity --info --title="Active IPs" --text="No active IPs found."
    fi

    # Clean up
    rm "$ip_file"
}
nwip() {
    weburl=$(zenity --entry --title="URL to IP" --text="Enter URL:")
    nmap -v $weburl | zenity --text-info --title="IP"
}

# Function to list network users using Nmap (SMB/SSH scan)
list_network_users() {
    start_ip=$(zenity --entry --title="Network User Scanner" --text="Enter start IP:")
    end_ip=$(zenity --entry --title="Network User Scanner" --text="Enter end IP:")

    # Create a temporary file for IPs
    ip_file=$(mktemp)

    # Generate IPs and write to file
    IFS=. read -r i1 i2 i3 i4 <<< "$start_ip"
    start=$((i1 * 256**3 + i2 * 256**2 + i3 * 256 + i4))
    IFS=. read -r i1 i2 i3 i4 <<< "$end_ip"
    end=$((i1 * 256**3 + i2 * 256**2 + i3 * 256 + i4))

    for ((ip=$start; ip<=$end; ip++)); do
        octet1=$((ip >> 24 & 255))
        octet2=$((ip >> 16 & 255))
        octet3=$((ip >> 8 & 255))
        octet4=$((ip & 255))
        echo "$octet1.$octet2.$octet3.$octet4" >> "$ip_file"
    done

    zenity --info --title="Network User Scanner" --text="Scanning for users from $start_ip to $end_ip..."

    # Perform Nmap scan on SMB and SSH services
    scan_output=$(nmap -p 22,445 --script smb-os-discovery,smb-enum-users -iL "$ip_file")

    # Extract IPs and usernames from Nmap output
    network_users=$(echo "$scan_output" | grep -E "Nmap scan report for|account:")

    # Display network users
    if [ -n "$network_users" ]; then
        zenity --text-info --title="Network Users" --text="$network_users"
    else
        zenity --info --title="Network Users" --text="No network users found."
    fi

    # Clean up
    rm "$ip_file"
}

# Function to scan open ports on a target IP
port_scanner() {
    target_ip=$(zenity --entry --title="Port Scanner" --text="Enter target IP address:")
    if [ -z "$target_ip" ]; then
        zenity --error --title="Error" --text="IP address cannot be empty."
        exit 1
    fi

    zenity --info --title="Port Scanner" --text="Scanning open ports on $target_ip..."
    nmap -T4 -F "$target_ip" | zenity --text-info --title="Port Scan Results"
}

# Function to scan Wi-Fi networks
wifi_networks() {
    zenity --info --title="Wi-Fi Network Scanner" --text="Scanning for nearby Wi-Fi networks..."

    # Perform Wi-Fi scan using iwlist or nmcli
    wifi_scan=$(sudo iwlist scan 2>/dev/null | grep -E 'ESSID|Signal|Quality' | awk -F ':' '{print $2}' | tr -d '"')

    # Display Wi-Fi networks
    if [ -n "$wifi_scan" ]; then
        zenity --text-info --title="Wi-Fi Networks" --text="$wifi_scan"
    else
        zenity --info --title="Wi-Fi Networks" --text="No Wi-Fi networks found."
    fi
}

# Function to sniff network traffic using tcpdump and save to a text file
traffic_sniffer() {
    interface=$(zenity --entry --title="Traffic Sniffer" --text="Enter network interface (e.g., eth0, wlan0):")
    if [ -z "$interface" ]; then
        zenity --error --title="Error" --text="Network interface cannot be empty."
        exit 1
    fi

    duration=$(zenity --entry --title="Traffic Sniffer" --text="Enter duration for capture (e.g., 60s for 60 seconds):")
    if [ -z "$duration" ]; then
        zenity --error --title="Error" --text="Duration cannot be empty."
        exit 1
    fi

    filter=$(zenity --entry --title="Traffic Sniffer" --text="Enter filter expression (e.g., 'tcp port 80' for HTTP traffic, leave empty for all traffic):")

    # Generate a unique filename based on timestamp
    output_file="capture_$(date +%Y%m%d_%H%M%S).txt"

    zenity --info --title="Traffic Sniffer" --text="Starting network traffic capture on $interface for $duration..."
    if [ -z "$filter" ]; then
        sudo tcpdump -i "$interface" -l > "$output_file" &
    else
        sudo tcpdump -i "$interface" "$filter" -l > "$output_file" &
    fi
    tcpdump_pid=$!

    # Wait for the specified duration
    sleep "$duration"

    # Stop tcpdump
    kill $tcpdump_pid 2>/dev/null
    zenity --info --title="Traffic Sniffer" --text="Network traffic capture completed. File saved as $output_file."

    # Optionally, display the first few lines of the text file
    zenity --info --title="Captured Traffic" --text="Displaying the first few lines from the capture file..."
    head -n 20 "$output_file" | zenity --text-info --title="Captured Traffic"
}




# Main menu using Zenity
zenity --info --title="By Alliance Group 2024" --text="This tool is provided by Alliance Group 2024."
selected_option=$(zenity --list --title="NetHacks" --text="Choose a tool" --radiolist --column="Select" --column="Tool" TRUE "Geolocate public IP" FALSE "IP Scanner" FALSE "Stress Test IP" FALSE "Password Cracker" FALSE "Active Ports Scanner" FALSE "Wi-Fi Networks" FALSE "Network Traffic Sniffer" FALSE "List Network Users" FALSE "DNS Reconnaissance" FALSE "ARP Spoofing" FALSE "Netcat Banner Grabbing" FALSE "Johnny" FALSE "URL to IP")

case $selected_option in
    "Geolocate public IP")
        ip_geolocator
        ;;
    "IP Scanner")
        ip_scanner
        ;;
    "Stress Test IP")
        stress_test_ip
        ;;
    "Password Cracker")
        password_cracker
        ;;
    "Active Ports Scanner")
        port_scanner
        ;;
    "Wi-Fi Networks")
        wifi_networks
        ;;
    "URL to IP")
        nwip
        ;;    
    "Network Traffic Sniffer")
        traffic_sniffer
        ;;
    "List Network Users")
        list_network_users
        ;;
    "DNS Reconnaissance")
        dns_recon
        ;;
    "ARP Spoofing")
        arp_spoofing
        ;;
    "Johnny")
        john_the_ripper
        ;;   
    "Netcat Banner Grabbing")
        netcat_banner_grabbing
        ;;
    *)
        zenity --error --title="Error" --text="Invalid option selected."
        ;;
esac

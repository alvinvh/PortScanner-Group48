import ipaddress
import socket
import sys
import webbrowser
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
import pyfiglet

result_dict = [] # variable to store the result
open_port = []  # variable to store open ports
close_port = []  # variable to store close ports
scanStart = ''  # variable to store time when the scan started
scanFinish = ''  # variable to store time when the scan started


#  Function for port scanning
def scan(ip,port):
    global open_port
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        socket.setdefaulttimeout(0.5)

        # returns an error indicator

        result = s.connect_ex((ip, port))
        if result == 0:  # when the port is open, the socket library will return 0
            print("Port {} is open".format(port))
            open_port.append(port)  # adding the opened port to the list
        else:
            close_port.append(port)
        s.close()  # closing connection
    except KeyboardInterrupt:
        print("\n Exiting Program !!!!")
        sys.exit()
    except socket.gaierror:
        print("\n Hostname Could Not Be Resolved !!!!")
        sys.exit()
    except socket.error:
        print("\n Server not responding !!!!")
        sys.exit()


# function to do threading and loop through each port that specify by the user
# giving the default value to start 1, finish 65535, and the maximum threading
def port_range(ip, start = 1, finish = 65535, max_threads=500):
    with ThreadPoolExecutor(max_workers=max_threads) as executor:  # creating the threads
        for port in range(start, finish):  # loop through the ports
            executor.submit(scan, ip, port)


# function to create the initial banner
def banner(ip):
    # Add Banner
    global scanStart
    scanStart = datetime.now()  # logging the starting time
    print("-" * 50)
    print("Scanning Target: " + ip)
    print("Scanning started at:" + str(scanStart))
    print("-" * 50)
    return scanStart


# function to create the ending banner
def end_banner():
    global scanFinish
    scanFinish = datetime.now()  # logging the finish time

    # Calculate scan duration
    scan_duration = scanFinish - scanStart

    print("-" * 50)
    print("Port Scan Finished!")
    print(f"Scanning finished at: {scanFinish}")
    print(f"Scanning duration: {scan_duration}")
    print("-" * 50)

    # Check if any ports are open and if not display message on the terminal
    if not open_port:  # If open_port list is empty
        print("No open ports found.")
    else:
        print(f"Open ports: {', '.join(map(str, open_port))}")

    print("\n\n")


# function to create a dashboard by creating a single html page
def dashboard(result_dict):
    with open("port_scanner_result.html", "w") as f:
        f.write('''
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Port Scanner Result</title>
        <style>
            body {
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 0;
                background-color: #f5f5f5;
            }

            .container {
                max-width: 800px;
                margin: 50px auto;
                padding: 20px;
                background-color: #fff;
                border-radius: 5px;
                box-shadow: 0 0 10px rgba(0, 0, 0, 0.1);
            }

            h1 {
                color: #333;
                text-align: center;
            }

            h2 {
                color: #666;
            }

            table {
                width: 100%;
                border-collapse: collapse;
                margin-bottom: 20px;
            }

            th, td {
                padding: 8px;
                text-align: left;
                border-bottom: 1px solid #ddd;
                vertical-align: top; /* Align content to the top */
            }

            th {
                background-color: #f2f2f2;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Port Scanner</h1>
            <h2>Group 48</h2>
        ''')

        for result in result_dict:
            f.write(f'<h2>Scan Result for {result["IP"]}:</h2>\n')
            f.write('<table>\n')
            f.write('<tr><th>Open Ports</th><th>Closed Ports</th></tr>\n')
            f.write('<tr>\n')

            # Write open ports
            f.write('<td>\n')
            if result["ports"]:
                open_ports_str = ', '.join(map(str, sorted(result["ports"])))
                f.write(f'{open_ports_str}<br>\n')
            else:
                f.write('No open ports found\n')
            f.write('</td>\n')

            # Write closed ports
            f.write('<td>\n')
            if result["close-ports"]:
                closed_ports_str = ', '.join(map(str, sorted(result["close-ports"])))
                f.write(f'{closed_ports_str}<br>\n')
            else:
                f.write('No closed ports found\n')
            f.write('</td>\n')

            f.write('</tr>\n')
            f.write('</table>\n')

        f.write('''
        </div>
    </body>
    </html>
        ''')






# function to ask user whether to generate dashboard or not
# then open the dashboard using browser
def generate_dashboard():
    user_input = input("Do you want to generate dashboard? (Y/N): ")
    if user_input.lower() == 'y':  # Converts user input to lower case for comparison
        dashboard(result_dict)  # calling dashboard function and passing the open ports
        webbrowser.open('port_scanner_result.html', new=1)  # open the html page using browser
    else:
        print("Dashboard generation skipped.")  # handle if the customer enter other than y


# creating a logo
ascii_banner = pyfiglet.figlet_format("PORT SCANNER")
print(ascii_banner)

# Defining a target
# user input validation
while True:
    try:
        print("Input Specific IP address or multiple IP addresses using ',' to separate the address")
        target = input(str("Target IP: "))
        if "," in target:  # checking if there is a coma in the user input
            target = target.split(",")  # Splitting the multiple IP from user input
            target = [i.strip() for i in target]  # Stripping whitespace from each element
            for i in target:  # input validation for IP address
                ipaddress.ip_address(i)
        else:
            ipaddress.ip_address(target)  # input validation for IP address
            target = [target]
        break
    except:
        print("Please input valid IP address")

# Defining a port
# user input validation
while True:
    try:
        print("Input Specific Port or Enter to scan all or input range (ex: 1-1000)")
        target_port = input(str("Port(s): "))
        if target_port == '':  # for scanning all ports (1-65535)
            for ip in target:
                open_port = []  # making sure the list is empty
                close_port = []  # making sure the list is empty
                banner(ip)
                port_range(ip)
                end_banner()
                result_dict.append({"IP": ip, "ports": open_port, "close-ports": close_port})  # adding the result
        elif target_port.isdigit():  # for scanning single port
            target_port = int(target_port)
            for ip in target:
                open_port = []  # making sure the list is empty
                close_port = []  # making sure the list is empty
                banner(ip)
                port_range(ip, start=target_port, finish=target_port + 1)
                end_banner()
                result_dict.append({"IP": ip, "ports": open_port, "close-ports": close_port})  # adding the result
        elif '-' in target_port:  # for scanning a range of ports
            start, finish = target_port.strip(' ').split('-')
            for ip in target:
                open_port = []  # making sure the list is empty
                close_port = []  # making sure the list is empty
                banner(ip)
                port_range(ip, start=int(start), finish=int(finish)+1)
                end_banner()
                result_dict.append({"IP": ip, "ports": open_port, "close-ports": close_port})  # adding the result
        else:
            raise ValueError
        break
    except ValueError:
        print("Please input a specific port, range of ports (ex: 1-1000) or Enter to scan all")



generate_dashboard()

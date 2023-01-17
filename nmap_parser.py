import re
import sys
try:
    import xlsxwriter
except:
    print("Missing xlsxwriter package. Try 'pip install xlsxwriter'")
    exit()

# -----------------#
# GLOBAL VARIABLES #
# -----------------#

ip_index = -1
database = []
dedup_database = []
out_filename = 'nmap.xlsx'
file_to_format = 'nmap.txt'
verboseMode = False


class bColors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# ---------------#
# FUNCTIONS      #
# ---------------#


def help_menu():
    print("Title: NMAP Parser")
    print("Author: Luke Lauterbach - Sentinel Technologies")
    print("")
    print("Usage: python3 [script] [options]")
    print("")
    print("Optional Options:")
    print("    -f:   File to Format")
    print("    -o:   Output filename")
    print("")
    print("Dependencies:\txlsxwriter")
    quit()


def parse_parameters():
    # Assign arguments to variables
    for index, argument in enumerate(sys.argv[1:]):
        if argument == "--help" or argument == "-h":
            help_menu()
        elif argument == "-f" or argument == "--format-file":
            global file_to_format
            file_to_format = sys.argv[index + 2]
        elif argument == "-o" or argument == "--out-file":
            global out_filename
            out_filename = sys.argv[index + 2]
        elif argument == "-v" or argument == "--verbose":
            global verboseMode
            verboseMode = True
        elif sys.argv[index] == "-ms" or sys.argv[index] == "-s" or sys.argv[index] == "-f" or sys.argv[index] == "-o":
            # If an option has a value, add it to this condition so the script doesn't think it is its own argument.
            pass


def print_header():
    print(f'{bColors.HEADER}NMAP Parser{bColors.ENDC}\n')
    print(f"{bColors.UNDERLINE}Parameters{bColors.ENDC}")
    print(f"File to Parse: {file_to_format}")
    print(f"Output File: {out_filename}")


def write_to_xlsx():
    # Create Workbook
    global workbook
    global worksheet
    global cell_format
    workbook = xlsxwriter.Workbook(out_filename)
    worksheet = workbook.add_worksheet()
    cell_format = workbook.add_format()
    cell_format.set_text_wrap()
    cell_format.set_align('top')
    cell_format.set_align('left')
    cell_format.set_font_name('Barlow')
    cell_format.set_font_size('10')

    i = 0
    while i < len(database):
        if verboseMode:
            print(database[i])

        # Write IPs
        worksheet.write(i, 0, database[i][0], cell_format)

        # Write Ports
        j = 0
        l_port_to_write = ''
        while j < len(database[i][1]):
            if j == 0:
                l_port_to_write = ''.join(database[i][1][j])
            else:
                l_port_to_write += '\n' + ''.join(database[i][1][j])
            j += 1
        worksheet.write(i, 1, l_port_to_write, cell_format)

        # Write Notes
        j = 0
        l_notes_to_write = ''
        while j < len(database[i][2]):
            if j == 0:
                l_notes_to_write = ''.join(database[i][2][j])
            else:
                l_notes_to_write += '\n' + ''.join(database[i][2][j])
            j += 1
        worksheet.write(i, 2, l_notes_to_write, cell_format)

        i += 1

    workbook.close()


def parse_http_title(l_line):
    filter_strings = ["Not Found", "403", "502", "404", "redirect", "doesn't", "Error", "Unavailable"]
    filter_strings.extend(["IIS Windows Server", "Failed"])

    header_check = re.findall("http-title\:\s(.*)", nmap_file_row)
    if header_check:
        header = ''.join(header_check)

        if any(x in header for x in filter_strings):
            pass
        else:
            database[ip_index][2].append(f'HTTP Title:{header}')


# --------------------- #
# MAIN                  #
# --------------------- #

parse_parameters()
print_header()

with open(file_to_format, 'r', encoding="utf8", errors='ignore') as nmap_results:
    for nmap_file_row in nmap_results:

        # Assign IP, Hostname
        hostname = ''
        notes = []

        # Check to see if this line is a new IP address
        ip_check = re.findall("Nmap scan report for (?:(.*) \((.*)\)|([0-9\.]+))", nmap_file_row)
        if ip_check:
            # There are two places an IP address could be. Whichever one it is, assign it to the IP variable
            if ip_check[0][1]:
                ip = ip_check[0][1]
            elif ip_check[0][2]:
                ip = ip_check[0][2]

            # If a hostname was found
            if ip_check[0][0]:
                # Check to see if the hostname contains an IP address
                dns_ip_check = re.findall("[0-9]{1,3}[\-\.][0-9]{1,3}[\-\.][0-9]{1,3}[\-\.][0-9]{1,3}",ip_check[0][0])
                if not dns_ip_check:
                    hostname = ip_check[0][0]
                    notes = [f'DNS Entry:{hostname}']
            database.append([ip, [], notes])
            ip_index += 1

        # Assign Port
        port_check = re.findall("^([0-9]+\/tcp|[0-9]+\/udp)\ +open\ +[^ ]+(?:\ +(.*)|)", nmap_file_row)
        if port_check:
            if port_check[0][1]:
                port_string = f'{port_check[0][0]} - {port_check[0][1]}'
            else:
                port_string = f'{port_check[0][0]}'

            # Remove HTTPD from strings
            if "httpd" in port_string:
                port_string = port_string.replace('httpd', '')

            database[ip_index][1].append(port_string)

        # Check for SSL Hostname
        ssl_hostname_check = re.findall("Subject Alternative Name\: DNS\:(?:([A-Za-z0-9\.\-]+)\,|([A-Za-z0-9\.\-]+))", nmap_file_row)
        if ssl_hostname_check:
            if ssl_hostname_check[0][0]:
                hostname = ssl_hostname_check[0][0]
            elif ssl_hostname_check[0][1]:
                hostname = ssl_hostname_check[0][1]

            if database[ip_index][2]:
                database[ip_index][2].insert(0, f'DNS Entry:{hostname}')
            else:
                database[ip_index][2] = [f'DNS Entry:{hostname}']

        # Add the HTTP Title to the Notes field
        parse_http_title(nmap_file_row)

        # Check for Redirect
        redirect_check = re.findall("redirect to ([^\s]+)", nmap_file_row)
        if redirect_check:
            redirect_url = 'Redirect to ' + ''.join(redirect_check[0])

            #Filter out redirect
            if "login.microsoftonline.com" in redirect_check[0]:
                redirect_url = "Redirect to Microsoft Azure AD"

            while len(database[ip_index][2]) < len(database[ip_index][1]):
                database[ip_index][2].append('')

            if not database[ip_index][2][len(database[ip_index][1])-1]:
                database[ip_index][2][len(database[ip_index][1]) - 1] = redirect_url
            else:
                database[ip_index][2].append(redirect_url)

# Remove entries without ports
for row in database:
    if row[1]:
        dedup_database.append(row)
database = dedup_database

write_to_xlsx()

print(f'\nEntries Written: {len(database)}')

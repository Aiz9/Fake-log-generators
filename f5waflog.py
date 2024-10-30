import random
import json
import time
import faker
from datetime import datetime, timedelta


# Load data from the external JSON file
with open("list.json", "r") as f:
    data = json.load(f)

# Assigning lists from the loaded data
hostnames = data["hostnames"]
subdomains = data["subdomains"]
domains = data["domains"]
tlds = data["tlds"]
attacks = data["attacks"]
http_policy_names = data["http_policy_names"]
waf_actions = data["waf_actions"]
webkit_engines = data["webkit_engines"]
sql_payload = data["sql_payloads"]
command_injection_payloads = data["command_injection_payloads"]
xss_payloads = data["xss_payloads"]
file_inclusion_payloads = data["file_inclusion_payloads"]
brute_force_payloads = data["brute_force_payloads"]
DOS_payloads = data["DOS_payloads"]
Session_Fixation_payloads= data["Session_Fixation_payloads"]
HTTP_Response_Splitting_payloads= data["HTTP_Response_Splitting_payloads"]
Parameter_Tampering_payloads= data["Parameter_Tampering_payloads"]
XXE_payloads = data["XXE_payloads"]
Insecure_Deserialization_payloads= data["Insecure_Deserialization_payloads"]
Broken_Authentication_payloads = data["Broken_Authentication_payloads"]
Sensitive_Data_Exposure_payloads = data["Sensitive_Data_Exposure_payloads"]
No_payloads = data["No_payloads"]
uri=data["uri"]


# Map of attack types to their specific payload lists
payload_map = {
    "SQL Injection": sql_payload,
    "Command Injection": command_injection_payloads,
    "Cross-Site Scripting (XSS)": xss_payloads,
    "Local File Inclusion (LFI)": file_inclusion_payloads,
    "Remote File Inclusion (RFI)": file_inclusion_payloads,
    "Brute Force": brute_force_payloads,
    "Denial of Service (DoS)" : DOS_payloads,
    "Distributed Denial of Service (DoS)" : DOS_payloads,
    "Session Fixation" : Session_Fixation_payloads,
    "HTTP Response Splitting" : HTTP_Response_Splitting_payloads,
    "Parameter Tampering" : Parameter_Tampering_payloads,
    "XML External Entity (XXE)" : XXE_payloads,
    "Insecure Deserialization" : Insecure_Deserialization_payloads,
    "Broken Authentication" : Broken_Authentication_payloads,
    "Sensitive Data Exposure" : Sensitive_Data_Exposure_payloads,
    "Cross-Site Request Forgery (CSRF)" : No_payloads

}


# To generate a random IP address
def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

# To generate a random hostname
def random_fqdn():
    return f"{random.choice(hostnames)}-{random.randint(1, 100)}.{random.choice(subdomains)}.{random.choice(domains)}.{random.choice(tlds)}"


# To generate a random string
def random_string(length):
    letters = "abcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(random.choice(letters) for _ in range(length))

# Initialize Faker for random location generation
fake = faker.Faker()
# Generate a random location
random_location = fake.city()
random_state = fake.state_abbr()


def generate_random_http_status():
    # Common HTTP status code ranges
    ranges = {
        "Informational": (100, 199),
        "Successful": (200, 299),
        "Redirection": (300, 399),
        "Client Error": (400, 499),
        "Server Error": (500, 599)
    }

    # Select a random category
    category = random.choice(list(ranges.keys()))
    code_range = ranges[category]

    # Generate a random status code within the selected range
    status_code = random.randint(code_range[0], code_range[1])
    return status_code


# Generate and print a random HTTP response code
random_status_code = generate_random_http_status()

# To generate a random user-agent
def random_user_agent():
    browsers = ['Mozilla/5.0', 'Chrome/99.0', 'Safari/14.0', 'Opera/74.0']
    os_types = ['Windows NT 10.0', 'Macintosh; Intel Mac OS X 10_15_7', 'Linux x86_64', 'X11; Ubuntu; Linux x86_64']
    browser_version = str(random.randint(50, 99))
    os_version = str(random.randint(0, 15))
    
    return f"{random.choice(browsers)} ({random.choice(os_types)}) {random.choice(webkit_engines)}/{browser_version}.0 (KHTML, like Gecko) Version/{os_version}.0"
 # Randomly select a pair of attack type and corresponding signature name
attack_type, sig_name = random.choice(list(attacks.items()))

#Specifying port for protocol
protocol = random.choice(["HTTP", "HTTPS"])
dest_port = 80 if protocol == "HTTP" else 443




# generates a syslog format log entry
def generate_syslog_log():
    now = datetime.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    fqdn = random_fqdn()
    destip = random_ip()
    ruri = random.choice(uri)
    reqmethod = random.choice(["GET", "POST"])


    # Choose an attack type and get corresponding payload
    #attack_type = random.choice(list(attacks.keys()))
    attack_description = attacks[attack_type]
    payload_list = payload_map.get(attack_type, [attack_description])  # Default to description if no specific list exists
    payload = random.choice(payload_list)  # Randomly select payload from the list
    full_uri = f"{ruri}?{payload}"  # Construct full URI with payload


    log = (
        f"<134>{now.strftime('%b %d %H:%M:%S')} {fqdn} ASM:"
        f'unit_hostname="{fqdn}",'
        f'management_ip_address="{random_ip()}",'
        f'http_class_name="{random.choice(http_policy_names)}",'
        f'policy_name="My security policy",'
        f'violations="Attack signature detected",'
        f'support_id="{random.randint(0, 2**64 - 1)}",'
        f'request_status="{random.choice(waf_actions)}",'
        f'response_code="{random_status_code}",'
        f'ip_client="{random_ip()}",'
        f'route_domain="{random.randint(0, 100)}",'
        f'method="{reqmethod}",'
        f'protocol={protocol},'
        f'query_string="key1=val1&key2=val2",'
        f'x_forwarded_for_header_value="{random_ip()}",'
        f'sig_ids="{random.randint(1, 999999999)}",'
        f'sig_names="{sig_name}",'
        f'date_time="{now.strftime("%Y-%m-%d %H:%M:%S")}",'
        f'severity="Error",'
        f'attack_type="{attack_type}",'
        f'geo_location="{random_location}/{random_state}"'
        f'ip_address_intelligence="Botnets, Scanners",'
        f'session_id="{random_string(16)}",'
        f'src_port="{random.randint(1024, 65535)}",'
        f'dest_port="{dest_port}",'
        f'dest_ip="{destip}",'
        f'sub_violations="Bad request",'
        f'uri="{full_uri}",'
        f'request="{reqmethod} {full_uri} HTTP/1.0\\r\\nUser-Agent:  {random_user_agent()}\\r\\nAccept: */*\\r\\nHost: {destip}\\r\\nConnection: Keep-Alive\\r\\n\\r\\n",'
        f'headers="Host: myhost.com; Connection: close",'
        f'response="HTTP/1.1 {random_status_code} OK Content-type: text/html Content-Length: 7 <html/>",'
        f'violation_details="<?xml version=\'1.0\' encoding=\'UTF-8\'?><BAD_MSG><request-violations><violation><viol_index>14</viol_index><viol_name>VIOL_HTTP_PROTOCOL</viol_name><http_sanity_checks_status>65536</http_sanity_checks_status><http_sub_violation_status>65536</http_sub_violation><http_sub_violation>SFRUUCB2ZXJzaW9uIG5vdCBmb3VuZA==</http_sub_violation></violation></request-violations></BAD_MSG>"'
    )
    return log

# Function to generate a CEF format log entry
import random
from datetime import datetime, timedelta

def generate_cef_log():
    now = datetime.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    fqdn = random_fqdn()
    destip = random_ip()
    ruri = random.choice(uri)
    reqmethod = random.choice(["GET", "POST"])


    # Choose an attack type and get corresponding payload
    attack_description = attacks[attack_type]
    payload_list = payload_map.get(attack_type, [attack_description])  # Default to description if no specific list exists
    payload = random.choice(payload_list)  # Randomly select payload from the list
    full_uri = f"{ruri}?{payload}"  # Construct full URI with payload

    # CEF log format components
    cef_log = (
        f"CEF:0|MyCompany|WebAppFirewall|1.0|{random.randint(1000, 9999)}|{sig_name}|10|"
        f"src={random_ip()} "
        f"dst={destip} "
        f"spt={random.randint(1024, 65535)} "
        f"dpt={dest_port} "
        f"deviceExternalId={random.randint(100000, 999999)} "
        f"cn1Label=Route Domain cn1={random.randint(0, 100)} "
        f"method={reqmethod} "
        f"request={reqmethod} {full_uri} HTTP/1.0\\r\\nUser-Agent: {random_user_agent()}\\r\\nAccept: */*\\r\\nHost: {destip}\\r\\nConnection: Keep-Alive\\r\\n\\r\\n "
        f"shost={fqdn} "
        f"cs1Label=Policy Name cs1=\"{random.choice(http_policy_names)}\" "
        f"cs2Label=Attack Type cs2=\"{attack_type}\" "
        f"cs3Label=WAF Action cs3=\"{random.choice(waf_actions)}\" "
        f"cs4Label=Geo Location cs4=\"{random_location}/{random_state}\" "
        f"cs5Label=IP Intelligence cs5=\"Botnets, Scanners\" "
        f"cs6Label=Sub Violations cs6=\"Bad request\" "
        f"requestClientApplication=\"{random_user_agent()}\" "
        f"destinationTranslatedAddress={destip} "
        f"severity={random.randint(1, 10)} "
    )

    return cef_log

# Function to generate a JSON format log entry
import json
from datetime import datetime, timedelta
import random

def generate_json_log():
    now = datetime.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    ruri = random.choice(uri)
    attack_description = attacks[attack_type]
    payload_list = payload_map.get(attack_type, [attack_description])  # Default to description if no specific list exists
    payload = random.choice(payload_list)  # Randomly select payload from the list

    log = {
        "@timestamp": now.isoformat() + "Z",
        "unit_hostname": random_fqdn(),
        "management_ip_address": random_ip(),
        "http_class_name": random.choice(http_policy_names),
        "policy_name": "My security policy",
        "violations": "Attack signature detected",
        "support_id": random.randint(0, 2**64 - 1),
        "request_status": random.choice(waf_actions),
        "response_code": random_status_code,
        "ip_client": random_ip(),
        "route_domain": random.randint(0, 100),
        "method": random.choice(["GET", "POST"]),
        "protocol": protocol,
        "query_string": "key1=val1&key2=val2",
        "x_forwarded_for_header_value": random_ip(),
        "sig_ids": str(random.randint(1, 999999999)),
        "sig_names": random.choice(list(attacks.values())),
        "date_time": now.strftime("%Y-%m-%d %H:%M:%S"),
        "severity": "Error",
        "attack_type": random.choice(list(attacks.keys())),
        "geo_location": f"{random_location}/{random_state}",
        "ip_address_intelligence": "Botnets, Scanners",
        "session_id": random_string(16),
        "src_port": random.randint(1024, 65535),
        "dest_port": dest_port,
        "dest_ip": random_ip(),
        "sub_violations": "Bad request",
        "uri": f"{random.choice(uri)}?{random.choice(payload_map.get(attack_type, [attacks[attack_type]]))}",
        "request": {
            "method": random.choice(["GET", "POST"]),
            "url": f"{ruri}?{payload}",
            "http_version": "HTTP/1.0",
            "user_agent": random_user_agent(),
            "headers": {
                "Host": "myhost.com",
                "Connection": "close"
            }
        },
        "response": {
            "status_code": random_status_code,
            "content_type": "text/html",
            "content_length": 7,
            "body": "<html/>"
        },
        "violation_details": "<?xml version='1.0' encoding='UTF-8'?><BAD_MSG><request-violations><violation><viol_index>14</viol_index><viol_name>VIOL_HTTP_PROTOCOL</viol_name><http_sanity_checks_status>65536</http_sanity_checks_status><http_sub_violation_status>65536</http_sub_violation><http_sub_violation>SFRUUCB2ZXJzaW9uIG5vdCBmb3VuZA==</http_sub_violation></violation></request-violations></BAD_MSG>"
    }
    return json.dumps(log, indent=4)


# Function to generate logs in different formats based on user input
def generate_logs(log_format="json"):
    if log_format == "syslog":
        return generate_syslog_log()
    elif log_format == "cef":
        return generate_cef_log()
    elif log_format == "json":
        return generate_json_log()
    else:
        print("Invalid log format selected.")
        return None


# Ask user for log format and duration
user_input = input("Enter the log format (syslog, cef, json): ").strip().lower()
duration = int(input("Enter the duration in seconds for log generation: "))

# Start time for the log generation
start_time = time.time()

# Open the log file for writing
with open('generated_logs.log', 'w') as log_file:
    log_file.write(f"--- {user_input.upper()} LOGS ---\n")

    # Generate logs continuously for the specified duration
    while (time.time() - start_time) < duration:
        log_entry = generate_logs(log_format=user_input)

        if log_entry:  # Check if the log entry is valid
            log_file.write(log_entry + '\n')
            log_file.flush()  # Ensure the entry is written to the file
            time.sleep(1)  # Wait for 1 second before generating the next log

print(f"Logs have been written to generated_logs.log")

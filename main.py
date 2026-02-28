from locale import windows_locale

text = '4000 0012 3456 7899 fg5t 255.195.20.1kcxjnjv32.248.0.0  012.654.12.36 4000-0012-3456-7890-1111 192.168.1.1 10.0.0.255 dciuurti56_-iftd) support@example.com info@company.org report.docx image.jpg C:\Windows\system32\drives\etc\hosts'

import re
import base64
import codecs

def luna_check(number):
    total = 0
    reverse_card = number[::-1]
    for index in range(len(reverse_card)):
        digit = int(reverse_card[index])
        if index % 2 == 1:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0

def find_and_validate_credit_cards(text):
    reg = r'[0-9]{4}[- ][0-9]{4}[- ][0-9]{4}[- ][0-9]{4}'
    reg1 = rf'(?=({reg}))'
    result = {'valid': [], 'invalid': []}
    credit_cards = re.findall(reg1, text)

    for card in credit_cards:
        clean_card = re.sub(r'\D', '', card)
        if luna_check(clean_card):
            result['valid'].append(card)
        else:
            result['invalid'].append(card)
    return result

my_result = find_and_validate_credit_cards(text)
print(my_result['valid'])



def find_system_info(text):
    results = {
        "ips": [],
        "files": [],
        "emails": []
    }
    num = r'(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
    ip_pattern = rf'(?=({num}\.{num}\.{num}\.{num}))'
    ips = [x.group(1) for x in re.finditer(ip_pattern, text)]
    results["ips"] = ips

    extensions = ['txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 'jpg', 'png', 'gif',
              'exe', 'msi', 'ini', 'cfg', 'conf', 'log', 'tmp', 'temp',
              'zip', 'rar', '7z', 'tar', 'gz', 'py', 'js', 'html', 'css',
              'dll', 'sys', 'drv', 'bat', 'cmd', 'ps1', 'vbs']

    files_found = []

    windows_pattern = r'[A-Za-z]:\\(?:[^\\\s]+\\)*[^\\\s]+'
    windows_matches = re.findall(windows_pattern, text)
    files_found.extend(windows_matches)

    for ext in extensions:
        pattern = rf'\b\S+\.{ext}\b'
        matches = re.findall(pattern, text)
        files_found.extend(matches)
    results["files"] = files_found

    email_pattern = r'\b\S+@\S+\.\S+\b'
    emails = re.findall(email_pattern, text)
    results["emails"] = emails

    return results

results = find_system_info(text)
print(results)



def find_secrets(text):
    patterns = {
        'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24}',
        'Stripe Publishable Key': r'pk_test_[0-9a-zA-Z]{24}',
        'Generic API Key': r'(?i)(?:api_key|access_token|password)'
                                  r'[\s:=]+["\']?([a-zA-Z0-9!@#$%^&*()_+]'
                                  r'{8,})["\']?'
               }
    found_secrets = []
    for name, pattern in patterns.items():
        match = re.findall(pattern, text)
        if match:
            found_secrets.extend(match)
    return list(found_secrets)
print(find_secrets(text))


def decode_messages(text):
    results = {'base64': [], 'hex': [], 'rot13': []}
    reg = r'[A-Za-z0-9+/]{10,}={0,2}'
    found_base64 = re.findall(reg, text)
    for encoded in found_base64:
        try:
            decoded_bytes = base64.b64decode(encoded)
            decoded_text = decoded_bytes.decode('utf-8')
            results['base64'].append(decoded_text)
        except:
            pass
    reg_hex_1 = r'0x[A-Fa-f0-9]{2,}'
    reg_hex_2 = r'(?:\\x[A-Fa-f0-9]{2})+'
    found_hex_1 = re.findall(reg_hex_1, text)
    found_hex_2 = re.findall(reg_hex_2, text)
    found_hex = found_hex_1 + found_hex_2
    for hex_str in found_hex:
        try:
            if hex_str.startswith('0x'):
                clean = hex_str[2:]
            else:
                clean = hex_str.replace('\\x', '')
            decoded_bytes = bytes.fromhex(clean)
            decoded_text = decoded_bytes.decode('utf-8')
            results['hex'].append(decoded_text)
        except:
            pass
    reg_rot = r'\b[A-Za-z]{4,}\b'
    found_rot = re.findall(reg_rot, text)
    for word in found_rot:
        try:
            decoded = codecs.encode(word, 'rot_13')
            common_words = ['the', 'and', 'for', 'you', 'password', 'admin', 'user', 'secret', 'hello', 'world', 'this',
                            'that', 'with', 'from', 'have']
            if any(common in decoded.lower() for common in common_words):
                results['rot13'].append(decoded)
        except:
            pass
    return results

result = decode_messages(text)
print(result)
def analyze_logs_optimal(text):
    results = {
        'sql_injections': [],
        'xss_attempts': [],
        'suspicious_user_agents': [],
        'failed_logins': []
    }

    sql_patterns = [
        "' OR '1'='1", "' OR 1=1", "' OR ''='",
        " UNION SELECT ", "'; DROP TABLE ", "'; DELETE FROM ",
        "1=1--", "admin'--", "' OR 'x'='x", "' AND 1=1"
    ]

    xss_patterns = [
        "<script>", "alert(", "onerror=", "onload=",
        "onclick=", "javascript:", "<img src=", "<svg"
    ]

    suspicious_agents = [
        'sqlmap', 'nmap', 'nikto', 'burpsuite',
        'curl', 'wget', 'python-requests', 'go-http-client'
    ]

    failed_patterns = ['401', '403', 'failed login', 'invalid password', 'access denied']

    lines = text.split('\n')
    for line_num, line in enumerate(lines, 1):
        line_lower = line.lower()

        for pattern in sql_patterns:
            if pattern.lower() in line_lower:
                results['sql_injections'].append(f"Строка {line_num}: {line}")
                break

        for pattern in xss_patterns:
            if pattern.lower() in line_lower:
                results['xss_attempts'].append(f"Строка {line_num}: {line}")
                break

        for agent in suspicious_agents:
            if agent in line_lower:
                results['suspicious_user_agents'].append(f"Строка {line_num}: {line}")
                break

        for pattern in failed_patterns:
            if pattern in line_lower:
                results['failed_logins'].append(f"Строка {line_num}: {line}")
                break

    return results
results = analyze_logs_optimal(text)

print(results)
from locale import windows_locale

text = '4000 0012 3456 7899 fg5t 255.195.20.1 kcxjnjv 32.248.0.0   01/01/1849 07.11.2011 32.248.0.0  012.654.12.36 4000-0012-3456-7890-1111 192.168.1.1 10.0.0.255 dciuurti56_-iftd)012.654.12.36 4000-0012-3456-7890-1111 192.168.1.1 10.0.0.255 dciuurti56_-iftd) support@example.com info@company.org report.docx image.jpg C:\Windows\system32\drives\etc\hosts'

from datetime import datetime
import re
import base64
import codecs


def find_system_info(text):
    '''
    3 role. Find ips, files, emails.
    '''
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


def find_password(text):
    '''
    Functions for password.
    '''
    passwords =  r'(?=.*[A-Za-z])(?=.*\d)(?=.*[!@#$%^&*()_+])[A-Za-z\d!@#$%^&*()_+]{8,}'
    potential_passwords = re.findall(passwords, text)
    found_passwords = []

    for password in potential_passwords:
        found_passwords.append(password)
    return found_passwords

def find_key(text):
    '''
    Functions for key.
    '''
    patterns = {
        'Stripe Secret Key': r'sk_live_[0-9a-zA-Z]{24}',
        'Stripe Publishable Key': r'pk_test_[0-9a-zA-Z]{24}',
        'Generic API Key': r'(?i)(?:api_key|access_token|password)'
                                  r'[\s:=]+["\']?([a-zA-Z0-9!@#$%^&*()_+]'
                                  r'{8,})["\']?'
               }
    found_key = []

    for name, pattern in patterns.items():
        match = re.findall(pattern, text)
        if match:
            found_key.extend(match)

    return list(found_key)


def find_secrets(text):
    '''
    2 role. Find secret keys and passwords.
    '''
    secrets=[]
    secrets.extend(find_key(text))
    secrets.extend(find_password(text))
    return secrets

print(find_secrets(text))


def decode_messages(text):
    '''
    4 role. Find and decipher hidden messages.
    '''
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


def analyze_logs(text):
    '''
    5 role. Analyze logs for example attacks.
    '''
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
results = analyze_logs(text)
print(results)


def validate_phones(text):
    '''
    Functions for phones.
    '''
    phone_patterns = [r'\+7[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}', # +7 XXX XXX XX XX
                        r'8[\s-]?\d{3}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}', # 8 XXX XXX XX XX
                        r'\d{3}[\s-]?\d{3}[\s-]?\d{2}[\s-]?\d{2}', # XXX XXX XX XX
    ]
    found_phones = {'valid': [], 'invalid': []}

    for pattern in phone_patterns:
        found = re.findall(pattern, text)

        for phone in found:
            normalized = re.sub(r'\D', '', phone)
            if len(normalized) == 10:
                normalized = '7' + normalized
            elif len(normalized) == 11 and normalized.startswith('8'):
                normalized = '7' + normalized[1:]

            if len(normalized) == 11 and normalized.startswith('7'):
                found_phones['valid'].append(normalized)
            else:
                found_phones['invalid'].append(phone)

    return found_phones


def luna_check(number):
    '''
    Luna algorithm.
    '''
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


def find_credit_cards(text):
    '''
    1 role. Functions for credit cards.
    '''
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


def validate_dates(text):
    '''
    Functions for dates.
    '''
    date_patterns =  [
        (r'\b(0[1-9]|[12][0-9]|3[01])\.(0[1-9]|1[0-2])\.(\d{4})\b', "%d.%m.%Y"),
        (r'\b(\d{4})/(0[1-9]|1[0-2])/(0[1-9]|[12][0-9]|3[01])\b', "%Y/%m/%d"),
        (r'\b(0[1-9]|[12][0-9]|3[01])-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-(\d{4})\b', "%d-%b-%Y")
    ]
    result = {'valid': [], 'invalid': []}

    for pattern, date_format in date_patterns:
        found = re.findall(pattern, text)
        for date_tuple in found:
            if date_format == "%Y/%m/%d":
                date_str = f"{date_tuple[0]}/{date_tuple[1]}/{date_tuple[2]}"
            elif date_format == "%d-%b-%Y":
                date_str = f"{date_tuple[0]}-{date_tuple[1]}-{date_tuple[2]}"
            else:
                date_str = f"{date_tuple[0]}.{date_tuple[1]}.{date_tuple[2]}"

            try:
                dt_obj = datetime.strptime(date_str, date_format)
                result['valid'].append(dt_obj.strftime("%Y-%m-%d"))
            except ValueError:
                result['invalid'].append(date_str)

    return result


def validate_inn(inn):
    '''
    Functions for inn.
    '''
    if len(inn) == 10:
        coefficients = [2, 4, 10, 3, 5, 9, 4, 6, 8]
        checksum = sum(int(inn[i]) * coefficients[i] for i in range(9))
        return (checksum % 11 % 10) == int(inn[9])

    elif len(inn) == 12:
        coefficients_1 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
        coefficients_2 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]

        checksum1 = sum(int(inn[i]) * coefficients_1[i] for i in range(10))
        checksum2 = sum(int(inn[i]) * coefficients_2[i] for i in range(11))

        return ((checksum1 % 11 % 10) == int(inn[10]) and
                (checksum2 % 11 % 10) == int(inn[11]))

    return False


def find_inn(text):
    '''
    Functions for inn.
    '''
    result = {'valid': [], 'invalid': []}
    reg_inn = r'\b\d{10}\b|\b\d{12}\b'
    found_inn = re.findall(reg_inn, text)

    for inn in found_inn:
        if validate_inn(inn):
            result['valid'].append(inn)
        else:
            result['invalid'].append(inn)

    return result


def normalize_and_validate(text):
    '''
    6 role. Normalize and validate data.
    '''
    result = { 'phones': {'valid': [], 'invalid': []},'dates': {'valid': [], 'invalid': []},
               'inn': {'valid': [], 'invalid': []}, 'cards': {'valid': [], 'invalid': []} }

    phones_data = validate_phones(text)
    result['phones'].update(phones_data)

    dates_data = validate_dates(text)
    result['dates'].update(dates_data)

    inn_data = find_inn(text)
    result['inn'].update(inn_data)

    cards_data = find_credit_cards(text)
    result['cards'].update(cards_data)

    return result
print(normalize_and_validate(text))


    

from datetime import datetime
import re
import base64
import codecs

with open('text.txt', 'r', encoding='utf-8') as file:
    text = file.read()


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
    ip_pattern = rf'\b{num}\.{num}\.{num}\.{num}\b'
    ips = re.findall(ip_pattern, text)
    ips = ['.'.join(ip) for ip in ips] 
    results["ips"] = list(set(ips))

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
    results["files"] = list(set(files_found))

    email_pattern = r'\b[a-zA-Z0-9][a-zA-Z0-9._%+-]*@[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*\.[a-zA-Z]{2,}\b'
    emails = re.findall(email_pattern, text)
    results["emails"] = list(set(emails))

    return results

results = find_system_info(text)



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




def decode_messages(text):
    '''
    4 role. Find and decipher hidden messages.
    '''
    results = {'base64': [], 'hex': [], 'rot13': []}
    reg = r'[A-Za-z0-9+/]{10,}={0,2}'
    for encoded in re.findall(reg, text):
        try:
            if '@' in encoded:
                continue

            decoded = base64.b64decode(encoded).decode('utf-8')

            if (not decoded.startswith('{')
                    and not decoded.startswith('[')
                    and any(c.isalpha() for c in decoded)
                    and len(decoded) > 4):
                if decoded not in results['base64']:
                    results['base64'].append(decoded)
        except:
            pass

    reg_hex = r'0x[A-Fa-f0-9]{2,}|(?:\\x[A-Fa-f0-9]{2})+'
    for hex_str in re.findall(reg_hex, text):
        try:
            if hex_str.startswith('0x'):
                clean = hex_str[2:]
            else:
                clean = hex_str.replace('\\x', '')
            decoded = bytes.fromhex(clean).decode('utf-8')

            if len(decoded) >= 3 and decoded not in results['hex']:
                results['hex'].append(decoded)
        except:
            pass

    reg_rot = r'ROT13:\s*(.+)'
    for phrase in re.findall(reg_rot, text):
        try:
            decoded = codecs.encode(phrase, 'rot_13')
            results['rot13'].append(decoded)
        except:
            pass

    return results



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
    for line in lines:
        line_lower = line.lower()

        for pattern in sql_patterns:
            if pattern.lower() in line_lower:
                results['sql_injections'].append(line)
                break

        for pattern in xss_patterns:
            if pattern.lower() in line_lower:
                results['xss_attempts'].append(line)
                break

        for agent in suspicious_agents:
            if agent in line_lower:
                results['suspicious_user_agents'].append(line)
                break

        for pattern in failed_patterns:
            if pattern in line_lower:
                results['failed_logins'].append(line)
                break
    return results
results = analyze_logs(text)



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
    credit_cards = list(set(credit_cards))

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


def generate_comprehensive_report(text):
    report = { 'financial_data': find_credit_cards(text),
               'secrets': find_secrets(text),
               'system_info': find_system_info(text),
               'encoded_messages': decode_messages(text),
               'security_threats': analyze_logs(text),
               'normalized_data': normalize_and_validate(text)
               }
    return report


def print_report(report):
    print("=" * 50)
    print("ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'")
    print("=" * 50)
    sections = [ ("ФИНАНСОВЫЕ ДАННЫЕ", report['financial_data']),
                 ("СЕКРЕТНЫЕ КЛЮЧИ", report['secrets']),
                 ("СИСТЕМНАЯ ИНФОРМАЦИЯ", report['system_info']),
                 ("РАСШИФРОВАННЫЕ СООБЩЕНИЯ", report['encoded_messages']),
                 ("УГРОЗЫ БЕЗОПАСНОСТИ", report['security_threats']),
                 ("НОРМАЛИЗОВАННЫЕ ДАННЫЕ", report['normalized_data']) ]
    for title, data in sections:
        print(f"\n{title}:")
        print("-" * 30)
        print(data)


if __name__ == "__main__":
    with open('text.txt', 'r', encoding='utf-8') as f:
        text = f.read()
        report = generate_comprehensive_report(text)
        print_report(report)


def universal_save(report, filename="result3.txt"):
    def extract(obj):
        items = []
        if isinstance(obj, dict):
            for name, value in obj.items():
                if name == 'invalid':
                    continue
                items.extend(extract(value))
        elif isinstance(obj, list):
            for i in obj:
                if isinstance(i, (list, dict)):
                    items.extend(extract(i))
                else:
                    val = str(i).strip()
                    if val and val.lower() not in ['phones', 'dates', 'inn', 'cards']:
                        items.append(val)
        return items

    all_data = extract(report)

    with open("result3.txt", 'w', encoding='utf-8') as f:
        for line in all_data:
            f.write(f"{line}\n")

    

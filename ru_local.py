text = '4000 0012 3456 7899 fg5t 255.195.20.1kcxjnjv32.248.0.0  012.654.12.36 4000-0012-3456-7890-1111 192.168.1.1 10.0.0.255 dciuurti56_-iftd)'

import re


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
    num = r'(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])'
    reg = rf'({num}\.)({num}\.)({num}\.)({num})'
    ip = [x.group() for x in re.finditer(reg, text)]
    return ip
print(find_system_info(text))





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

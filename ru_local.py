text = '4000 0012 3456 7899 fg5t 4000-0012-3456-7890'
import re


def luna_check(card):
    total = 0
    clean_card = re.sub(r'\D', '', card)
    reverse_card = clean_card[::-1]
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
    result = {'valid': [], 'invalid': []}
    credit_cards = re.findall(reg, text)

    for card in credit_cards:
        if luna_check(card):
            result['valid'].append(card)
        else:
            result['invalid'].append(card)
    return result

find_and_validate_credit_cards(text)


#find_and_validate_credit_cards(text)
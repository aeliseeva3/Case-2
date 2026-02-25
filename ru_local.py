text = '4000 0012 3456 7899 fg5t 4000-0012-3456-7890-1111'
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


#find_and_validate_credit_cards(text)
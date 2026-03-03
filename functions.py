def compare_results(my_num, num_groups=3):
    my_file = f'result{my_num}.txt'
    with open(my_file, 'r', encoding='utf-8') as f:
        my_data = set([line.strip() for line in f])
    other_data = {}
    
    for i in range(1, num_groups + 1):
        if i == my_num:
            continue
        file_name = f'result{i}.txt'
        with open(file_name, 'r', encoding='utf-8') as f:
            other_data[i] = set([line.strip() for line in f])
    
    print("Артефакты, которые есть у меня, но отсутствуют у других:")
    print("-" * 50)
    for artifact in my_data:
        missing = []
        for group_num, group_set in other_data.items():
            if artifact not in group_set:
                missing.append(str(group_num))
        if missing:
            print(f"{artifact} - отсутствует у групп {', '.join(missing)}")
    
    
    print("\nАртефакты, которые есть у других, но нет у меня:")
    print("-" * 50)
    for group_num, group_set in other_data.items():
        for artifact in group_set:
            if artifact not in my_data:
                print(f"{artifact} - есть в группе {group_num}, но нет у меня")

compare_results(my_num=3, num_groups=3)

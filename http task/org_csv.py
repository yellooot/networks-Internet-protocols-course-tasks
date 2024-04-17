import requests
import argparse
import threading
import csv

PER_PAGE = 100


def start_and_join_threads(threads):
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()


def get_all_commits_from_organization(name):
    def extend_all_commits(repo):
        nonlocal lock
        elements = get_all_elements_from_url(f'https://api.github.com/repos/{name}'
                                             f'/{repo}/commits', property_element='commit')
        with lock:
            result.extend(elements)

    lock = threading.Lock()
    result = []
    repo_names = get_all_elements_from_url(f'https://api.github.com/orgs/{name}/repos',
                                           property_element='name')
    threads = []
    for current_repo in repo_names:
        threads.append(threading.Thread(target=extend_all_commits, args=(current_repo,)))
        if len(threads) > 100:
            start_and_join_threads(threads)
            threads.clear()

    start_and_join_threads(threads)

    return result


def get_all_elements_from_url(url, property_element):
    all_elements = []
    current_page = 1
    while True:
        current_response = requests.get(url, params={'page': current_page, 'per_page': PER_PAGE},
                                        headers=headers)
        if current_response.status_code == 200:
            response_elements = current_response.json()
            if not response_elements:
                break
            all_elements.extend([element[property_element] for element in response_elements])
        current_page += 1

    return all_elements


def write_csv(data):
    sorted_data = dict(sorted(data.items(), key=lambda item: item[1],
                              reverse=True)[:100])
    data_to_write = []
    for item in sorted_data.items():
        data_to_write.append({'Автор': item[0], 'Количество коммитов': item[1]})

    with open(f'data_{org_name}.csv', 'w') as f:
        writer = csv.DictWriter(f, fieldnames=['Автор', 'Количество коммитов'])
        writer.writeheader()
        writer.writerows(data_to_write)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Диаграмма 100 самых активных авторов организации')
    parser.add_argument('org_name', type=str, help='Название организации')
    parser.add_argument('api_token', type=str, help='GitHub API токен')
    args = parser.parse_args()
    org_name = args.org_name
    api_token = args.api_token
    headers = {'Authorization': f'Bearer {api_token}'}

    all_commits = get_all_commits_from_organization(org_name)
    users_active_commit_counts = {}

    for commit in all_commits:
        commit_user_email = commit['author']['email']
        if 'Merge pull request #' not in commit['message']:
            if commit_user_email in users_active_commit_counts:
                users_active_commit_counts[commit_user_email] += 1
            else:
                users_active_commit_counts[commit_user_email] = 1

    write_csv(users_active_commit_counts)






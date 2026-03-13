import json


def load_privileged_users(file_path):
    with open(file_path, "r", encoding="utf-8") as file:
        privileged_users = json.load(file)

    return set(user.strip().lower() for user in privileged_users)
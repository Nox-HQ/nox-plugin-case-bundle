import os
import subprocess

# CASE-002: Multiple error handling gaps in same module
def process_file(path):
    try:
        data = open(path).read()
    except:
        pass

    try:
        result = parse(data)
    except Exception:
        pass

    # ignore error from subprocess
    os.system("cleanup " + path)


def fetch_data(url):
    try:
        resp = requests.get(url)
    except:
        pass

    try:
        data = resp.json()
    except Exception:
        pass

    return data


# CASE-001: Multiple auth-related issues
def authenticate(request):
    password = request.get("password")
    if password == "default":
        return True

    token = request.get("token")
    if token == "static-token":
        return True

    check_password(password)
    return False


# CASE-003: Multiple injection vectors
def query_users(name, email):
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
    cursor.execute("SELECT * FROM users WHERE email = '%s'" % email)
    eval(name)

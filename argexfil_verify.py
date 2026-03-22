import requests
import argparse
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

parser = argparse.ArgumentParser()
parser.add_argument('--server', help="https://localhost:8080", required=True)
parser.add_argument('--username', help="admin", required=True)
parser.add_argument('--password', help="password", required=True)
args = parser.parse_args()

def login(server, username, password):
    session = requests.Session()
    data = {"username": username, "password": password}
    response = session.post(f"{server}/api/v1/session", json=data, verify=False)
    if response.status_code == 200:
        print("Login successful.")
    else:
        print("Login failed.")
    return session

def resource_action(server, resource, action, session):
    response = session.get(f"{server}/api/v1/account/can-i/{resource}/{action}/*/", verify=False)
    if response.status_code == 200 and response.json().get("value") == "yes":
        print(f"User has permission to {action} {resource}.")
        return 1
    else:
        if resource == "logs" or resource == "applications" and action == "get":
            print(f"User does not have permission to {action} {resource}, but it's optional.")
        else:    
            print(f"User does not have permission to {action} {resource}.")
        return 0
    

def verify_user_permissions(server, username, password):
    num = 0
    #Authenticate and get a token
    session = login(server, username, password)

    #Check certificates creation permission
    num += resource_action(server, "certificates", "create", session)

    #Check applications get and creation permission
    resource_action(server, "applications", "get", session)
    num += resource_action(server, "applications", "create", session)

    #Check clusters get permission
    num += resource_action(server, "clusters", "get", session)

    #Check repositories get permission
    num += resource_action(server, "repositories", "get", session)

    #Check projects get permission
    num += resource_action(server, "projects", "get", session)

    #Check logs get permission
    resource_action(server, "logs", "get", session)
    return num

if __name__ == "__main__":
    num = verify_user_permissions(args.server, args.username, args.password)
    if num >= 5:
        print(f"[+] The user {args.username} has enough permissions ({num}) to use Argexfil.")
    else:
        print(f"[-] The user {args.username} does not have enough permissions to use Argexfil.")

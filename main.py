# Add choice for registration or login at startup
from tinydb import TinyDB  # for database creation
from tinydb import Query  # for query lookup
import bcrypt  # encrypt the passwords
# import os
to_operate = Query()


def check_value(val):
    db_check = db.get(to_operate.username == val)
    if db_check is None:
        print("Username not found!")


def main_menu_choices():
    print("Register or Login?\n 1-Register\n 2-Login")


username_not_found_counter = 0
db = TinyDB('C:/Users/xtrop/Desktop/PyProjects/bin/tinydb/db.json')
while True:
    main_menu_choices()
    answer = int(input("Enter answer: "))
    if answer == 1:
        username = input("Enter username /0 to exit/: ")
        if username == "0":
            break
    while len(username) <= 0:
        username = input("Enter valid username: ")
    if len(username) > 0:
        password = str(input("Enter password /0 to exit/: "))
        while len(password) <= 0:
            password = str(input("Enter valid password /0 to exit/: "))
            if password == "0":
                break
        if password == "0":
            break
        password = password.encode('utf-8')  # encode the password, so we can encrypt it
        hashed = bcrypt.hashpw(password, bcrypt.gensalt(10))  # encrypt the passwords by 10 rounds of encrypt
        if len(password) > 0:
            new_profile = {"username": username, "password": hashed.decode()}
            db.insert(new_profile)  # store username and hashed password as JSON
            print("Successfully registered!")
            print("User: {}".format(username))
#  TO-DO: Make the login menu to check for the password stored in the Database
if answer == 2:
    usernameEnter = input("Enter username: ")
    check_value(usernameEnter)
    while db.get(to_operate.username == usernameEnter) is None:
        username_not_found_counter += 1
        usernameEnter = input("Enter username: ")
        check = db.get(to_operate.username == usernameEnter)
        if check is None:
            print("Username not found!")
        if check is True:
            break
        if username_not_found_counter == 10:
            print("Too many attempts, restart the console application")
            break

# Add choice for registration or login at startup
from tinydb import TinyDB  # for database creation
from tinydb import Query, where  # for query lookup
import bcrypt  # encrypt the passwords
to_operate = Query()
toFind = where('key')
db = TinyDB('C:/Users/xtrop/Desktop/PyProjects/bin/tinydb/db.json')


def check_value(val):
    db_check = db.get(to_operate.username == val)
    if db_check is None:
        print("Username not found!")


def check_user(value):
    db_user = db.get(where("username") == value)
    while db_user is not None:
        value = str(input("Enter new username: "))
        check_available = db.get(to_operate.username == value)
        if check_available is None:
            print("Username available!")
            return_value_name = value
            break


def main_menu_choices():
    print("Register or Login? \n0-Exit\n1-Register\n2-Login\n")


username_not_found_counter = 0
while True:
    main_menu_choices()
    answer = int(input("Enter answer: "))
    if answer == 0:
        break
    if answer == 1:
        print("Valid username is a string with more than 3 characters!")
        print("_______________________________________________________")
        username = input("Enter username /0 to exit/: ")
        if username == "0":
            break
    while len(username) < 4:
        username = input("Enter valid username: ")
    if len(username) >= 3:
        check_user(username)
        print("_______________________________________________________")
        print("Valid password is a string with more than 8 characters!")
        print("_______________________________________________________")
        password = str(input("Enter password /0 to exit/: "))
        if password == "0":
            break
        while len(password) <= 7:
            password = str(input("Enter valid password /0 to exit/: "))
            if password == "0":
                break
        password = password.encode('utf-8')  # encode the password, so we can encrypt it
        hashed = bcrypt.hashpw(password, bcrypt.gensalt(10))  # encrypt the passwords by 10 rounds of encrypt
        if len(password) >= 8:
            new_profile = {"username": username, "password": hashed.decode()}
            db.insert(new_profile)  # store username and hashed password as JSON
            print("Successfully registered!")
            print("User: {}".format(username))
    #  TO-DO: Make the login menu to check for the password stored in the Database
    if answer == 2:
        usernameEnter = str(input("Enter username: "))
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

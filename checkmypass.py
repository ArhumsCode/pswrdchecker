import requests
from hashlib import sha1
import sys

url = 'https://api.pwnedpasswords.com/range/' + 'CBFDA'


# obtaining the pwned passwords api and adding the characters 'CBFDA' to the end due to the sha1 hashing standards


def request_api_data(query_char):
    url = 'https://api.pwnedpasswords.com/range/' + query_char
    # ALLOWS for a more dynamic range of passwords as query_char can be changed depending on the password
    # the user inputs
    res = requests.get(url)
    # We are able to obtain the url's API functionality into our program now
    # by passing it as an argument to our .get() method
    if res.status_code != 200:
        # A status code of 200 indicates that we were able to fetch the API with no problem
        # So if it is anything else then 200 we want to do a check for that because something may have went
        # wrong in our code
        raise RuntimeError(f'Error Fetching: {res.status_code}, check the api and try again!')
        # the runtime Error is raised in order to account for the mistake
    return res

def password_leaks_count(hashes, hash_to_check):
    hashes = (line.split(':') for line in hashes.text.splitlines())
    for h, count in hashes:
        if h == hash_to_check:
            return count
    return 0




def pwned_api_check(password):
    sha1password = sha1(password.encode('utf-8')).hexdigest().upper()
    first5_char, tail = sha1password[:5], sha1password[5:]
    response = request_api_data(first5_char)

    return password_leaks_count(response, tail)
    # When a password is passed into this function it is encoded with utf-8
    # and passed into the sha1 function from the hashlib library
    # We then convert the sha1 object into hexidecimal form and then make it uppercase

def main(arg):
    for password in arg:
        count = pwned_api_check(password)
        if count:
            print(f'{password} was found {count} times.. you should probably change your password')
        else:
            print(f'{password} was NOT found. Carry ON!')
    return 'done!'


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
    #This allows you to run the program and add multiple passwords to check in your terminal

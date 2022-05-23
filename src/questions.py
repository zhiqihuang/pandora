import pwinput
import bcrypt
from hashlib import sha512

def security_questions():
    answers = []
    bcrypt_hashed = b'$2b$16$SIQnBmW944x2sx15a3ksv.kF0cb6KZbXrpfLAWl0gCIhYpF26N8SC'

    # 1. childhood nickname
    nickname = input("What is my childhood nickname(小名)? Answer in simplied Chinese.  ")
    answers.append(nickname)
    
    # 2. birthday
    dob = input("When is my birthday? Answer in MM/DD/YYYY.  ")
    answers.append(dob)

    # 3. mom‘s name
    mom = input("What is my mother's full name (Last+First). Answer in simplied Chinese.  ")
    answers.append(mom)

    # 4. a secret num
    passwd = pwinput.pwinput("Please input the 7-disgits(七位) password:  ")
    answers.append(passwd)

    # 5. a bad habit
    habit = input("What is my childhood bad habit(小时候的坏习惯)? Two words in simplied Chinese.  ")
    answers.append(habit)
    
    hashed = sha512('|'.join(answers).encode('utf-8')).hexdigest().encode()
    
    print("checking answers...")
    assert bcrypt.checkpw(hashed, bcrypt_hashed), 'incorrect answer.'
    print("answers are correct.")
    return hashed




    


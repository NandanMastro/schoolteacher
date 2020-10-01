import jwt
from datetime import datetime


def tokenIsExpire(token):
    decodedPayload = jwt.decode(token,None, None)
    print(decodedPayload['exp'])

    dateJWT = datetime.fromtimestamp(decodedPayload['exp']).isoformat()
    # print(readable)
    dateJWT = dateJWT.replace('T', ' ')
    # print(readable)
    dateJWT = datetime.strptime(dateJWT, '%Y-%m-%d %H:%M:%S')
    # print(dateJWT)
    # print(type(dateJWT))

    current_time = datetime.now()
    print(current_time)
    print(type(current_time))

    expiry_flag = current_time > dateJWT
    # print(expiry_flag)
    return expiry_flag


def userid_from_token(token):
    decodedPayload = jwt.decode(token,None, None)
    print(decodedPayload['username'])
    return decodedPayload['username']

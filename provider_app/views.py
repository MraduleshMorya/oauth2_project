from audioop import reverse
from email.mime import application
from typing import final
from django.shortcuts import redirect, render
import requests
from rest_framework.permissions import IsAuthenticated
from rest_framework.views import APIView
from rest_framework.decorators import api_view
from django.contrib.auth.models import User
from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt
from rest_framework.parsers import JSONParser
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import authenticate
from rest_framework.permissions import AllowAny
from rest_framework.status import (
    HTTP_400_BAD_REQUEST,
    HTTP_404_NOT_FOUND,
    HTTP_200_OK
)
from rest_framework.authtoken.models import Token
from rest_framework.decorators import api_view, permission_classes
from django.conf import settings
from rest_framework_simplejwt.tokens import RefreshToken
import base64
from requests import request

from datetime import timedelta
from django.utils import timezone
from django.conf import settings
from rest_framework_simplejwt.views import TokenObtainPairView
from rest_framework.authentication import TokenAuthentication
from rest_framework.authtoken.models import Token
from rest_framework.exceptions import AuthenticationFailed
from datetime import datetime
import pytz
import base64
import json
from .models import login_with_records
import jwt
utc = pytz.UTC

# Create your views here.

def encode_string(target):
    return str((base64.b64encode(target.encode("ascii"))).decode("ascii"))
    
def decode_string(target):
    return str((base64.b64decode(target.encode("ascii"))).decode("ascii"))


#this return left time
def expires_in(token):
    time_elapsed = (token.created + timedelta(seconds=300)) - timezone.now()
    left_time = timedelta(seconds=300) - time_elapsed
    print("left time-", left_time)
    return time_elapsed

# token checker if token expired or not


def is_token_expired(token):
    current_time = datetime.now()
    token_expiration_time = token.created + timedelta(seconds=600)
    print("compared time my", token_expiration_time)
    if utc.localize(current_time) < token_expiration_time:
        return False
    else:
        return True

# if token is expired new token will be established
# If token is expired then it will be removed


def token_expire_handler(token):
    is_expired = is_token_expired(token)
    print("is expired", is_expired)
    if is_expired:
        token.delete()
        #token = Token.objects.create(user = token.user)
        #print(" new token generated ")
    return is_expired, token


def authenticate_credentials(key):
    try:
        token = Token.objects.get(key=key)
        print("key == ", token.key)
        print("user == ", token.user)
    except Token.DoesNotExist:
        raise AuthenticationFailed("Invalid Token")

    if not token.user.is_active:
        raise AuthenticationFailed("User is not active")

    is_expired, token = token_expire_handler(token)
    if is_expired:
        raise AuthenticationFailed("The Token is expired")

    return (token.user, token)



@csrf_exempt
@api_view(["POST"])
@permission_classes((AllowAny,))
def authenticate_user(request,app_name):
    print("\n running authentication function ===")
    print("request.data",request.data)
    print("request.POST", request.POST)
    print("request.headers",request.headers["Permission"])
    input_username = request.data.get("username")
    input_password = request.data.get("password")
    input_application = app_name

    print("username", input_username)
    print("password", input_password)

    # temp = requests.post(
    #     "http://127.0.0.1:8000/api/token/", data={"username":input_username,"password":input_password})
    # print("temp",temp)
    # for x in temp:
    #     print(x.decode("ascii"))

    if input_username is None or input_password is None:
        return Response({'error': 'Please provide both username and password'},
                        status=HTTP_400_BAD_REQUEST)
    user = authenticate(username=input_username, password=input_password)
    print("\n \n user -- ", user)

    if not user:
        return Response({'error': 'Invalid Credentials'},
                        status=HTTP_404_NOT_FOUND)
    
    try:
        obj = login_with_records.objects.get(username=input_username,application_name=app_name,status=True,permission=True)
        print("\n user already signed up with that application so returning the previous data directly ")
        users_data = User.objects.filter(username=decode_string(
            request.session["username"])).values("username", "first_name", "last_name", "email")
        return Response({"status": "success", "data": users_data},
                        status=HTTP_200_OK)
    except:
        pass
    
    #token creation 
    token, _ = Token.objects.get_or_create(user=user)
    if is_token_expired(token):
        print("\n entered token expired ")
        token.delete()
        if "username" in request.session:
            del request.session["username"]
            del request.session["password"]
            token, _ = Token.objects.get_or_create(user=user)

    request.session["username"] = encode_string(input_username)
    request.session["password"] = encode_string(input_password)
    request.session.modified = True
    print("token type ",token)
    
    
    db_obj = login_with_records(username=input_username, application_name=app_name, auth_token= token.key)
    db_obj.save()
    
    
    return Response({'authorizatio_token': f"Token {token.key}",
                     'expires in': expires_in(token)},
                    status=HTTP_200_OK)
    

@csrf_exempt
@api_view(["POST","GET"])
def authorize_user(request,app_name):
    permission_classes = (IsAuthenticated,)
    print("\n running Authorization Function == ")
    
    print("\n passed authentication ")
    
    if "username" not in request.session:
        return Response({"Login Error": "you are not logged in "},
                        status=HTTP_400_BAD_REQUEST)
        
    try:
        
        user = authenticate(username=decode_string(request.session["username"]), password=decode_string(request.session["password"]))
        token= Token.objects.get(user=user)
        print("try finished")
        
    except Token.DoesNotExist:
        print("entered except of doest exists ")
        if "username" in request.session:
            del request.session["username"]
            del request.session["password"]
        return Response({"Token Error ": "Token Doesnt match / Invlid Token"},
                        status=HTTP_400_BAD_REQUEST)
        
    if str(token.key) != str(request.auth):
        print("\n enterd jwt token instead of basic authentication == ")
        print("token.key == ", token.key)
        print("request.auth == ",request.auth)
        print("key didnt matched ")
        if "username" in request.session:
            del request.session["username"]
            del request.session["password"]
        return Response({"Token Error ": "Token Doesnt match / Invlid Token"},
                        status=HTTP_400_BAD_REQUEST)
        
    if is_token_expired(token):
        print("\n entered token expired ")
        token.delete()
        if "username" in request.session:
            del request.session["username"]
            del request.session["password"]
        return Response({"Token Error ": "Token Expired"},
                        status=HTTP_400_BAD_REQUEST)
        
    user_obj = login_with_records.objects.get(
            username=decode_string(request.session["username"]), auth_token=str(token.key))
    
    try:
        temp = request.headers["Permission"]
    except:
        user_obj.permission = False
        user_obj.status = False
        user_obj.save()
        token.delete()
        return Response({"Permission Error ": "Permission Required"},
                        status=HTTP_400_BAD_REQUEST)
        
    #checking for the user provided permission 
    if str(request.headers["Permission"]) != 'Allow':
        print("\n entered permission function  ")
        user_obj.permission = False
        user_obj.status = False
        user_obj.delete()
        token.delete()
        if "username" in request.session:
            del request.session["username"]
            del request.session["password"]
        return Response({"Permission  Error ": "Permissions Denied By User "},
                        status=HTTP_400_BAD_REQUEST)
                
        
    temp = requests.post(
        "http://127.0.0.1:8000/api/token/", data={"username":decode_string(request.session["username"]),"password":decode_string(request.session["password"])})
   
    print("temp", temp.text)
    print("temp", type(temp.text))
    jwt_token = json.loads(temp.text)
    print("res: ", jwt_token['access'])
    
    user_obj.permission = True
    user_obj.access_token = jwt_token['access']
    user_obj.save()
    token.delete()
    
    return Response({"authorization_token":jwt_token,"expires_in":"secods"},
                    status=HTTP_200_OK)
    

@api_view(["GET"])
def get_response(request,app_name):
    permission_classes = (IsAuthenticated,)
    print("\n running Get Response Function == ")
    
    
    # checking if the passed token is basic token 
    if "username" not in request.session:
        return  Response({"Login Error": "you are not logged in "},
                                       status=HTTP_400_BAD_REQUEST)
    try:

        user = authenticate(username=decode_string(
            request.session["username"]), password=decode_string(request.session["password"]))
        token = Token.objects.get(user=user)
        print("try finished")

    except Token.DoesNotExist:
        print("entered except block token  doest exists ")

        users_data = User.objects.filter(username=decode_string(request.session["username"])).values("username","first_name","last_name","email")
        print(users_data)
        
        user_obj = login_with_records.objects.get(
            username=decode_string(request.session["username"]), access_token=str(request.auth))
        user_obj.status = True
        user_obj.save()

        if "username" in request.session:
            del request.session["username"]
            del request.session["password"]
        return Response({"status": "success", "data":users_data},
                    status=HTTP_200_OK)
        
    else:
        if str(token.key) == str(request.auth):
            print("\n enterd basic token instead of jwt authentication == ")
            print("token.key == ", token.key)
            print("request.auth == ", request.auth)
            print("key didnt matched ")
            return Response({"Token Error ": "Token Doesnt match / Invlid Token"},
                            status=HTTP_400_BAD_REQUEST)
        
    #checking that the jwt acceess token isn't expired    

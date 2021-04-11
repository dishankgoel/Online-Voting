#!/bin/bash

export GOOGLE_OAUTH_CLIENT_ID="--REDACTED--"
export GOOGLE_OAUTH_CLIENT_SECRET="--REDACTED--"
export OAUTHLIB_INSECURE_TRANSPORT=1
export OAUTHLIB_RELAX_TOKEN_SCOPE=1

export GOOGLE_APPLICATION_CREDENTIALS=iitgn-online-voting-f75cd1c50bc3.json
export DB_HOST='127.0.0.1:3306'
export DB_USER='root'
export DB_PASS='--REDACTED--'
export DB_NAME='voting2020'

export FLASK_APP=main.py
export FLASK_DEBUG=1
export FLASK_SECRET_KEY="lolnotrandom"
python3 -m flask run -p 8040
# gunicorn wsgi:app -b 127.0.0.1:8040 #-t 1000 --workers 1 --threads 1

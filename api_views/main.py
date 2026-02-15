from flask import Response, request

from models.user_model import *
from app import vuln
from api_views.users import token_validator, error_message_helper

def populate_db():
    resp = token_validator(request.headers.get('Authorization'))
    if "error" in resp:
        return Response(error_message_helper(resp), 401, mimetype='application/json')
    user = User.query.filter_by(username=resp['sub']).first()
    if not user or not user.admin:
        return Response(error_message_helper("Admin access required"), 403, mimetype='application/json')
    db.drop_all()
    db.create_all()
    User.init_db_users()
    response_text = '{ "message": "Database populated." }'
    response = Response(response_text, 200, mimetype='application/json')
    return response

def basic():
    response_text = '{ "message": "VAmPI the Vulnerable API", "help": "VAmPI is a vulnerable on purpose API. It was ' \
                    'created in order to evaluate the efficiency of third party tools in identifying vulnerabilities ' \
                    'in APIs but it can also be used in learning/teaching purposes.", "vulnerable":' + "{}".format(vuln) + "}"
    response = Response(response_text, 200, mimetype='application/json')
    return response

from functools import wraps
from flask import Flask, request, jsonify, abort
import json
from flask_cors import CORS

from .database.models import db_drop_and_create_all, setup_db, Drink
from .auth.auth import AuthError, requires_auth


# Decorator for check in request have json;
# Check keys in json;
def valid_json(keys=None, func=any):
    if keys is None:
        keys = []

    def valid_json_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            if not request.is_json:
                abort(415)
            data = request.get_json()
            if not func([item in data for item in keys]):
                abort(422)
            return f(data, *args, **kwargs)

        return wrapper

    return valid_json_decorator


app = Flask(__name__)
setup_db(app)
CORS(app)

db_drop_and_create_all()


# ROUTES


@app.route('/drinks')
def get_drinks():
    return jsonify({
        'success': True,
        'drinks': [drink.short() for drink in Drink.query.all()]
    })


@app.route('/drinks-detail')
@requires_auth(permission='get:drinks-detail')
def get_drinks_detail():
    return jsonify({
        'success': True,
        'drinks': [drink.long() for drink in Drink.query.all()]
    })


@app.route('/drinks', methods=['POST'])
@requires_auth(permission='post:drinks')
@valid_json(keys=['title', 'recipe'], func=all)
def create_drink(data):
    drink = Drink.query.filter_by(title=data['title']).one_or_none()
    if drink:
        abort(409)
    drink = Drink(title=data['title'], recipe=json.dumps(data['recipe']))
    drink.insert()
    return jsonify({
        'success': True,
        'drinks': [drink.long()]
    })


@app.route('/drinks/<int:id>', methods=['PATCH'])
@requires_auth(permission='patch:drinks')
@valid_json(keys=['title', 'recipe'], func=any)
def update_drink(data, id):
    drink = Drink.query.filter_by(id=id).one_or_none()
    if drink is None:
        abort(404)
    _drink = Drink.query.filter_by(title=data['title']).one_or_none()
    if _drink and _drink.id != id:
        abort(409)
    if 'title' in data:
        drink.title = data['title']
    if 'recipe' in data:
        drink.recipe = json.dumps(data['recipe'])
    drink.update()
    return jsonify({
        'success': True,
        'drinks': [drink.long()]
    })


@app.route('/drinks/<int:id>', methods=['DELETE'])
@requires_auth(permission='delete:drinks')
def delete_drink(id):
    drink = Drink.query.filter_by(id=id).one_or_none()
    if drink is None:
        abort(404)
    drink.delete()
    return jsonify({
        'success': True,
        'delete': id
    })


@app.errorhandler(401)
def unathorized(error):
    return jsonify({
        "success": False,
        "error": error.description
    }), 401


@app.errorhandler(404)
def not_found(error):
    return jsonify({
        "success": False,
        "error": {
            "code": "not_found",
            "message": "Resource not found"
        }
    }), 404


@app.errorhandler(409)
def conflict(error):
    return jsonify({
        "success": False,
        "error": {
            "code": "conflict",
            "message": "Data already have in db"
        }
    }), 409


@app.errorhandler(415)
def unsupported_media(error):
    return jsonify({
        "success": False,
        "error": {
            "code": "unsupported_media_type",
            "message": "Unsupported media type"
        }
    }), 415


@app.errorhandler(422)
def unprocessable(error):
    return jsonify({
        "success": False,
        "error": {
            "code": "unprocessable",
            "message": "Data is not fully"
        }
    }), 422


@app.errorhandler(500)
def server_error(error):
    return jsonify({
        "success": False,
        "error": {
            "code": "internal_server_error",
            "message": "Internal server error"
        }
    }), 500


@app.errorhandler(AuthError)
def auth_error(exp):
    return jsonify({
        "success": False,
        "error": exp.error
    }), exp.status_code

"""
This module takes care of starting the API Server, Loading the DB and Adding the endpoints
"""
import os
from flask import Flask, request, jsonify, url_for, redirect
from flask_migrate import Migrate
from flask_swagger import swagger
from flask_cors import CORS
from utils import APIException, generate_sitemap
from admin import setup_admin
from models import db, User
#from models import Person
#Clase JWT 25 abril '23
import datetime # necesito saber el tiempo que dura el token
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
#JWTManager = mi aplicación en Flask va a trabajar con JWT
#create_access_token = crea el token
#jwt_required = valida si el usuario tiene permiso para entrar al sitio
#get_jwt_identity = permite traer la información que se encuentra encriptada en el token


app = Flask(__name__)
#Vamos a trabajar con JWT:
jwt = JWTManager(app)

app.url_map.strict_slashes = False

db_url = os.getenv("DATABASE_URL")
if db_url is not None:
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url.replace("postgres://", "postgresql://")
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:////tmp/test.db"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

MIGRATE = Migrate(app, db)
db.init_app(app)
CORS(app)
setup_admin(app)

# Handle/serialize errors like a JSON object
@app.errorhandler(APIException)
def handle_invalid_usage(error):
    return jsonify(error.to_dict()), error.status_code

# generate sitemap with all your endpoints
@app.route('/')
def sitemap():
    return generate_sitemap(app)

@app.route('/user', methods=['GET'])
def handle_hello():

    response_body = {
        "msg": "Hello, this is your GET /user response "
    }

    return jsonify(response_body), 200

#Para validar que el usuario y contraseña existen, debo crear una ruta:
@app.route('/login', methods=['POST'])
def login():
    body = request.get_json()
    user = User.query.filter_by(email=body['email']).first()
    #print(user) #si el usuario no existe, me retorna None (tipo undefined en JS)
    if (user is None):
        return jsonify({"mensaje": "el usuario no existe, regístrate por favor"}), 404
    else:   
        if(user.password != body['password']):
            return "la contraseña está mala"    #en la realidad, se pone el usuario o la contraseña son incorrectos; no hay que indicar dónde está el error
        else:   #usuario y contraseña ok, ahora creo el token
            expiration = datetime.timedelta(minutes=60) #tiempo que le doy al token par que sea válido
            token = create_access_token(identity=user.serialize(), expires_delta=expiration)
            return jsonify({
                "mensaje": "bienvenido!",
                "token": token,
                "tiempo": expiration.total_seconds(),
                "data": user.serialize()
            }), 200
@app.route('/check', methods=['GET'])   #vamos a chequear si el token es válido
@jwt_required()       #jwt hace la validación solo
def check_user(): 
    return jsonify({
        "logeado": True
    })
#en Postman, se pone GET>Auth>Type Bearer Token; 3 respuestas: token OK, token expired, algún error en el token.

@app.route('/signup', methods=['POST'])
def signup():
    body = request.get_json()
    email = body.get('email')
    password = body.get('password')

    #para verificar si el email ya está registrado:
    if User.query.filter_by(email=email).first() is not None:
        return jsonify({
            "mensaje": "El email ingresado ya se encuentra registrado"
        }), 400
    
    #para crear el nuevo usuario:
    user = User(email=email, password=password, is_active=True)
    db.session.add(user)
    db.session.commit()

    return jsonify({
        "mensaje": "usuario creado"
    })
    #para redireccionar al usuario a la página de inicio de sesión
    #return redirect('/login')

@app.route('/private', methods=['GET'])
@jwt_required()
def private_page():
    current_user_id = get_jwt_identity()
    user = User.query.get(current_user_id)
    if user is None or not user.is_active:
        return jsonify({
            "mensaje": "Debes iniciar sesión"
        })
    return jsonify({
        "mensaje": "sí tienes permiso para ver esta página"
    })


# this only runs if `$ python src/app.py` is executed
if __name__ == '__main__':
    PORT = int(os.environ.get('PORT', 3000))
    app.run(host='0.0.0.0', port=PORT, debug=False)

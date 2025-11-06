from app.app import run
from sys import platform
import os
from flask import Flask, request, jsonify
from app.exceptions.exception import RegraNegocioException
from dotenv import load_dotenv
load_dotenv()

def process(request_process):
    code = 200
    message = 'success'
    url_request = "*"

    headers = {
        'Access-Control-Allow-Origin': url_request
    }

    if request.method == 'OPTIONS':
        headers = {
            'Access-Control-Allow-Origin': url_request,  # Allow your function to be called from any domain
            'Access-Control-Allow-Methods': '*',  # Allow all HTTP methods
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Max-Age': '1',
        }
        return '', 204, headers

    try:
        _header = {}

        if request_process.headers.get('Webhook-Retry') is not None and \
                request_process.headers.get('Webhook-Retry').lower() == 'true':
            print("headers:", list(request_process.headers))
            print("request:", request_process.json)
            raise RegraNegocioException("Requisição já processada")

        if request_process.headers.get('env') is not None and \
                request_process.headers.get('env').lower() == 'hml':
            print('Ambiente de Homologação')
        else:
            print('Ambiente de Produção')

        response_data = run(request_process.get_json(), request_process.headers)

    except RegraNegocioException as e:
        _header = {}
        print(e)
        message = str(e)
    except Exception as ex:
        _header = {}
        print(ex)
        message = str(ex)
        code = 500
        if len(ex.args) > 1:
            message = ex.args[0]
            code = ex.args[1]

    headers.update(_header)
    response = {
        'gcp_function': {
            'name': os.getenv("PYTHON_NAME"),
            'version': os.getenv("PYTHON_VERSION"),
            'data': response_data
        },
        'status': {
            'code': code,
            'message': message
        }
    }
    print("response:", response)
    return jsonify(response), response['status']['code'], headers


# Region Metodo para a Google Cloud Plataform
def main(request_main):
    return process(request_main)


# End Region

# Region Metodo para Testar Local via Postman/Rest Client
# url:http://127.0.0.1:8090/main


app = Flask(__name__)


@app.route('/', methods=['POST'])
def main():
    return jsonify({"STATUS":"OK"})

@app.route('/main', methods=['POST'])
def main_flask():
    return process(request)

if __name__ == "__main__":
    if platform in ["win32", "win64"]:
        app.run(host='localhost', port=8090, debug=True)


# End Region

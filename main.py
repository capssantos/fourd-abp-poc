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
    response_data = None

    headers = {
        'Access-Control-Allow-Origin': url_request
    }

    if request.method == 'OPTIONS':
        headers = {
            'Access-Control-Allow-Origin': url_request,
            'Access-Control-Allow-Methods': '*',
            'Access-Control-Allow-Headers': 'Content-Type, Authorization',
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


# ===== Entrypoint GCP (renomeado para não colidir) =====
def gcp_entrypoint(request_main):
    return process(request_main)


# ===== App Flask para execução via Gunicorn =====
app = Flask(__name__)

@app.route('/', methods=['POST'])
def root():
    return jsonify({"STATUS":"OK"})

@app.route('/main', methods=['POST'])
def main_flask():
    return process(request)

if __name__ == "__main__":
    # Observação: sys.platform em Windows é 'win32' mesmo em 64 bits.
    port = int(os.getenv("PORT", "8090"))
    app.run(host='0.0.0.0', port=port, debug=True)

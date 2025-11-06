import os
import uuid as _uuid
import json
from flask import jsonify

from .services.pipefy import Pipefy

def run(request, headers):
    print("INÍCIO REGRA DE NEGÓCIO")
    print(f"headers: {list(headers)}")
    print(f"request: {request}")

    pipefy = Pipefy()

    pipefy.createComment(card_id=request.get("data").get('card').get('id'), text="OK")
    
    return pipefy.card(id=request.get("data").get('card').get('id'))
import requests, json, re, os, base64, tempfile, logging
from time import sleep
from datetime import datetime
from urllib.parse import unquote
from ..exceptions.exception import PipefyException
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


import os
import json
import logging
import tempfile
from time import sleep

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

class Pipefy:
    """
    Suporta:
      - PAT: usa PFY_PAT_TOKEN
      - Service Account: OAuth2 client_credentials
    """

    def __init__(self):
        get = os.environ.get

        # --- Comuns (ambos os modos) ---
        self.qtdTentativasReconexao = int(get("PFY_QTD_TENTATIVAS_RECONEXAO", "3"))
        self.timeoutConexao = int(get("PFY_TIMEOUT_CONEXAO", "60"))

        self.base_url = (get("PFY_BASE_URL") or "").rstrip("/")
        self.api_url = get("PFY_API_URL") or ""
        if not self.base_url or not self.api_url:
            raise PipefyException("PFY_BASE_URL e PFY_API_URL são obrigatórios.")

        self.api_endpoint = f"{self.base_url}{self.api_url}"

        verify_ssl_env = (get("REQUESTS_SSL", "true") or "").strip().lower()
        self.verify_ssl = verify_ssl_env in ("true", "1", "yes", "y")

        # --- Sessão HTTP com retry robusto ---
        self.session_request = requests.Session()
        retry = Retry(
            total=5,
            backoff_factor=0.8,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=("POST", "GET"),
            raise_on_status=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        self.session_request.mount("https://", adapter)
        self.session_request.mount("http://", adapter)

        self.tmp = tempfile.gettempdir()

        # --- Seleção do modo ---
        self.token_source = None
        self.token = None

        # Modo PAT
        self.pat_token = get("PFY_PAT_TOKEN")

        # Modo SA
        self.sa_oauth_url = get("PFY_SA_OAUTH_URL")
        self.sa_client_id = get("PFY_SA_CLIENT_ID")
        self.sa_secret = get("PFY_SA_SECRET")
        self.sa_email = get("PFY_SA_EMAIL")

        if self.pat_token:
            self.token_source = "PAT"
            self.token = self.pat_token
        else:
            # Verifica se SA está completo
            if not (self.sa_oauth_url and self.sa_client_id and self.sa_secret):
                raise PipefyException(
                    "Sem PFY_PAT_TOKEN e credenciais de Service Account incompletas. "
                    "Defina: PFY_SA_OAUTH_URL, PFY_SA_CLIENT_ID, PFY_SA_SECRET."
                )
            self.token_source = "SA"
            self.token = self._get_pipefy_jwt()

        if not self.token:
            raise PipefyException("Falha ao obter token de autenticação do Pipefy.")

        self.base_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.token}",
        }

    # -------- SA: OAuth client_credentials --------
    def _get_pipefy_jwt(self) -> str:
        url = f"{self.base_url}{self.sa_oauth_url}" if self.sa_oauth_url.startswith("/") else self.sa_oauth_url
        info = self.sa_email or "(sem email)"
        logging.info(f"[Pipefy] OAuth SA iniciando (email: {info})")

        last_exc = None
        for i in range(self.qtdTentativasReconexao):
            try:
                payload = {
                    "grant_type": "client_credentials",
                    "client_id": self.sa_client_id,
                    "client_secret": self.sa_secret,
                }
                resp = self.session_request.post(
                    url,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    verify=self.verify_ssl,
                    timeout=self.timeoutConexao,
                )

                text = resp.text or ""
                if "<!DOCTYPE html" in text:
                    raise PipefyException("HTTP 429/HTML no OAuth. Tente novamente.")

                data = resp.json() if resp.headers.get("Content-Type", "").startswith("application/json") else {}
                if resp.status_code < 200 or resp.status_code >= 300:
                    raise PipefyException(
                        f"OAuth falhou ({resp.status_code}): "
                        f"{data.get('error')} {data.get('error_description', '') or text[:200]}"
                    )

                token = data.get("access_token")
                if not token:
                    raise PipefyException("OAuth OK, mas sem access_token no payload.")
                logging.info("[Pipefy] OAuth SA ok")
                return token

            except Exception as e:
                last_exc = e
                if i < self.qtdTentativasReconexao - 1:
                    logging.warning(f"[Pipefy][OAuth] Tentativa {i+1} falhou: {e}. Retry em {self.timeoutConexao}s…")
                    sleep(self.timeoutConexao)

        raise last_exc or PipefyException("Falha desconhecida no OAuth SA.")

    # -------- GraphQL --------
    def request(self, query: str, variables: dict | None = None, headers: dict | None = None) -> dict:
        if not isinstance(query, str) or not query.strip():
            raise ValueError("query (GraphQL) deve ser string não vazia.")

        payload = {"query": query}
        print(payload)
        if variables:
            payload["variables"] = variables

        last_exc = None
        for attempt in range(self.qtdTentativasReconexao):
            try:
                req_headers = dict(self.base_headers)
                if headers:
                    req_headers.update(headers)

                resp = self.session_request.post(
                    self.api_endpoint,
                    json=payload,
                    headers=req_headers,
                    verify=self.verify_ssl,
                    timeout=self.timeoutConexao,
                )

                text = resp.text or ""
                if "<!DOCTYPE html" in text:
                    raise PipefyException("Recebido HTML (possível 429/proxy).")

                # Auto-refresh quando SA receber 401
                if resp.status_code == 401 and self.token_source == "SA":
                    logging.info("[Pipefy] 401. Renovando token SA e repetindo a requisição…")
                    self.token = self._get_pipefy_jwt()
                    self.base_headers["Authorization"] = f"Bearer {self.token}"
                    continue  # tenta novamente com o novo token

                # Decodifica JSON
                try:
                    data = resp.json()
                except ValueError:
                    resp.raise_for_status()
                    raise PipefyException(text)

                if resp.status_code < 200 or resp.status_code >= 300:
                    raise PipefyException(
                        f"HTTP {resp.status_code}: {data.get('error')} {data.get('error_description', '')}"
                    )

                if "errors" in data and data["errors"]:
                    msgs = "; ".join(
                        (e.get("message") or json.dumps(e, ensure_ascii=False)) for e in data["errors"]
                    )
                    raise PipefyException(f"GraphQL errors: {msgs}")

                return data  # sucesso

            except Exception as e:
                last_exc = e
                if attempt < self.qtdTentativasReconexao - 1:
                    logging.warning(f"[Pipefy] Tentativa {attempt+1} falhou: {e}. Retry em {self.timeoutConexao}s…")
                    sleep(self.timeoutConexao)

        raise last_exc or PipefyException("Falha desconhecida ao chamar a API Pipefy.")


    def __prepare_json_dict(self, data_dict):
        data_response = json.dumps(data_dict)
        rex = re.compile(r'"(\S+)":')
        for field in rex.findall(data_response):
            data_response = data_response.replace('"%s"' % field, field)
        return data_response

    def __prepare_json_list(self, data_list):
        return '[ %s ]' % ', '.join([self.__prepare_json_dict(data) for data in data_list])

    def organization(self, org_id, response_fields=None, headers={}):
        """ List fields: Get organization by their identifiers. """

        response_fields = response_fields or 'id name pipes { id name }  '

        query = '{ organization (id: %(org_id)s) { %(response_fields)s } }' % {
            'org_id': json.dumps(org_id),
            'response_fields': response_fields,
        }
        return self.request(query, headers).get('data', {}).get('organization', [])

    def pipes(self, ids=[], response_fields=None, headers={}):
        """ List pipes: Get pipes by their identifiers. """

        response_fields = response_fields or 'id name phases { name cards (first: 5)' \
                                             ' { edges { node { id title } } } }'
        query = '{ pipes (ids: [%(ids)s]) { %(response_fields)s } }' % {
            'ids': ', '.join([json.dumps(id) for id in ids]),
            'response_fields': response_fields,
        }

        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('pipes', [])

    def pipe(self, id, response_fields=None, headers={}):
        """ Show pipe: Get a pipe by its identifier. """

        response_fields = response_fields or 'id name start_form_fields { label id type index_name }' \
                                             ' labels { name id } phases {id name fields { label id type index_name }' \
                                             ' cards(first: 5) { edges { node { id, title } } } }'
        query = '{ pipe (id: %(id)s) { %(response_fields)s } }' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('pipe', [])

    def clonePipes(self, organization_id, pipe_template_ids=[], response_fields=None, headers={}):
        """ Clone pipe: Mutation to clone a pipe, in case of success a query is returned. """

        response_fields = response_fields or 'pipes { id name }'
        query = 'mutation { clonePipes(input: { organization_id: %(organization_id)s' \
                ' pipe_template_ids: [%(pipe_template_ids)s] }) { %(response_fields)s } }' % {
                    'organization_id': json.dumps(organization_id),
                    'pipe_template_ids': ', '.join([json.dumps(id) for id in pipe_template_ids]),
                    'response_fields': response_fields,
                }

        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('clonePipes', {}).get('pipe', [])

    def createPipe(self, organization_id, name, labels=[], members=[], phases=[],
                   start_form_fields=[], preferences={}, response_fields=None, headers={}):
        """ Create pipe: Mutation to create a pipe, in case of success a query is returned. """

        response_fields = response_fields or 'pipe { id name }'
        query = '''
            mutation {
              createPipe(
                input: {
                  organization_id: %(organization_id)s
                  name: %(name)s
                  labels: %(labels)s
                  members: %(members)s
                  phases: %(phases)s
                  start_form_fields: %(start_form_fields)s
                  preferences: %(preferences)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'organization_id': json.dumps(organization_id),
            'name': json.dumps(name),
            'labels': self.__prepare_json_list(labels),
            'members': self.__prepare_json_list(members),
            'phases': self.__prepare_json_list(phases),
            'start_form_fields': self.__prepare_json_list(start_form_fields),
            'preferences': self.__prepare_json_dict(preferences),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createPipe', {}).get('pipe', [])

    def updatePipe(self, id, icon=None, title_field_id=None, public=None, public_form=None,
                   only_assignees_can_edit_cards=None, anyone_can_create_card=None,
                   expiration_time_by_unit=None, expiration_unit=None, response_fields=None, headers={}):
        """ Update pipe: Mutation to update a pipe, in case of success a query is returned. """

        response_fields = response_fields or 'pipe { id name }'
        query = '''
            mutation {
              updatePipe(
                input: {
                  id: %(id)s
                  icon: %(icon)s
                  title_field_id: %(title_field_id)s
                  public: %(public)s
                  public_form: %(public_form)s
                  only_assignees_can_edit_cards: %(only_assignees_can_edit_cards)s
                  anyone_can_create_card: %(anyone_can_create_card)s
                  expiration_time_by_unit: %(expiration_time_by_unit)s
                  expiration_unit: %(expiration_unit)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'id': json.dumps(id),
            'icon': json.dumps(icon),
            'title_field_id': json.dumps(title_field_id),
            'public': json.dumps(public),
            'public_form': json.dumps(public_form),
            'only_assignees_can_edit_cards': json.dumps(only_assignees_can_edit_cards),
            'anyone_can_create_card': json.dumps(anyone_can_create_card),
            'expiration_time_by_unit': json.dumps(expiration_time_by_unit),
            'expiration_unit': json.dumps(expiration_unit),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updatePipe', {}).get('pipe', [])

    def deletePipe(self, id, response_fields=None, headers={}):
        """ Delete pipe: Mutation to delete a pipe, in case of success success: true is returned. """

        response_fields = response_fields or 'success'
        query = 'mutation { deletePipe(input: { id: %(id)s }) { %(response_fields)s }' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deletePipe', {})

    def findCards(self, pipe_id, field_id: str, field_value, limit_search_card=0,
                  response_card_fields=None, headers: dict = {}, pagination: bool = None, endCursor=None,
                  count: int = 50, recuperar_card_mais_recente: bool = False):
        """
        This function can return the data from pipefy, using only the search fields. It's possible to use some default
        parameters in the response payload or the search process (like pagination for example). Se the doc below:
        Args:
            count: Cards count to return on the request
            pipe_id: Pipe id to search the cards
            field_id:  field_id (must provide the text ID)
            field_value: value to search on the field
            response_card_fields: Fields to map the response of the payload of the cards
            headers: Custom Headers for the Application
            limit_search_card: Parameter to set
            pagination: True or False, in case to return more then 30 on the query
            endCursor: Pipefy pagination cursor.

        Returns: Default payload or the definied on the parameters \n
        How to Use \n:
        --> pipefy.findCards(11787, "cpf", "098.000.876-19")
            Will return the 30 first cards, who match the search fields.

        --> pipefy.findCards(11787, "cpf", "098.000.876-19", pagination=True)
            Will return all cards who match the fields, note that in case of more then 30 cards matching will
            make automatically the pagination by 30 cards per page (pipefy default).

        --> pipefy.findCards(11787, "cpf", "098.000.867-19", pagination=True, limit_search_card=200)
            Will return all cards who match the fields, in case of more then 30 cards matching will
            make automatically the pagination by 30 cards, but will limit the count in limi_search_card, so,
            In case existing 400 cards with this match, and the parameter is set to 100, for example, will return
            only the first 100 cards. \n
        """

        response_card_fields = response_card_fields or 'edges { node { id title assignees { id name email }' \
                                                       ' comments { text } comments_count current_phase { id name } createdAt done due_date ' \
                                                       'fields { field{id type} name value array_value} labels { id name } phases_history { phase { id name } firstTimeIn lastTimeOut } url } }'
        if limit_search_card > 0 and count != limit_search_card:
            count = limit_search_card

        if pagination is None and endCursor is None:

            query = '{findCards(pipeId: %(pipe_id)s, search: {fieldId: %(field_id)s, ' \
                    'fieldValue: %(field_value)s}) {%(response_card)s}}' \
                    % {
                        "pipe_id": json.dumps(pipe_id),
                        "field_id": json.dumps(field_id),
                        "field_value": self.__prepare_json_dict(field_value),
                        "response_card": response_card_fields
                    }

            response = self.request(query, headers)
            if response.get('error'):
                return {'error': response.get('error')}
            elif response.get('errors'):
                return {'errors': response.get('errors')}
            edges = response.get('data').get('findCards').get('edges')
            if not recuperar_card_mais_recente:
                return edges
            # region Validação para pegar o card mais atual
            card_mais_atualizado = None
            cards_tmp = edges
            if cards_tmp not in ['', None] and len(cards_tmp) > 0:
                for edge in cards_tmp:
                    card_tmp = edge['node']
                    data_criacao_atual = datetime.strptime(card_tmp['createdAt'], '%Y-%m-%dT%H:%M:%S%z')

                    if card_mais_atualizado is None:
                        card_mais_atualizado = card_tmp
                    else:
                        data_criacao_mais_atualizado = datetime.strptime(card_mais_atualizado['createdAt'], '%Y-%m-%dT%H:%M:%S%z')
                        if data_criacao_mais_atualizado < data_criacao_atual:
                            card_mais_atualizado = card_tmp
            logging.info(f'card_mais_atualizado:{card_mais_atualizado}')
            return card_mais_atualizado
            # endregion Validação para pegar o card mais atual


        if pagination:
            cards: list = []
            query = '{ findCards(pipeId: %(pipe_id)s, search: {fieldId: %(field_id)s, ' \
                    'fieldValue: %(field_value)s}) {%(response_card)s pageInfo {endCursor hasNextPage }}}' \
                    % {
                        "pipe_id": json.dumps(pipe_id),
                        "field_id": json.dumps(field_id),
                        "field_value": self.__prepare_json_dict(field_value),
                        "response_card": response_card_fields
                    }
            response = self.request(query, headers)
            if response.get('error'):
                return {'error': response.get('error')}
            elif response.get('errors'):
                return {'errors': response.get('errors')}

            hasNextPage = response['data']['findCards']['pageInfo']['hasNextPage']
            endCursor = response['data']['findCards']['pageInfo']['endCursor']
            cards.append(response['data']['findCards']['edges'])

            while hasNextPage:
                query = '{ findCards(pipeId: %(pipe_id)s, after: %(after)s , search: {fieldId: %(field_id)s, ' \
                        'fieldValue: %(field_value)s}) {%(response_card)s pageInfo {endCursor hasNextPage }}}' \
                        % {
                            "pipe_id": json.dumps(pipe_id),
                            "field_id": json.dumps(field_id),
                            "after": json.dumps(endCursor),
                            "field_value": self.__prepare_json_dict(field_value),
                            "response_card": response_card_fields
                        }
                response = self.request(query, headers)
                if response.get('error'):
                    return {'error': response.get('error')}
                elif response.get('errors'):
                    return {'errors': response.get('errors')}

                hasNextPage = response['data']['findCards']['pageInfo']['hasNextPage']
                endCursor = response['data']['findCards']['pageInfo']['endCursor']
                cards.append(response['data']['findCards']['edges'])

            if not recuperar_card_mais_recente:
                return cards
            # region Validação para pegar o card mais atual
            card_mais_atualizado = None
            cards_tmp = cards[0]
            if cards_tmp not in ['', None] and len(cards_tmp) > 0:
                for edge in cards_tmp:
                    card_tmp = edge['node']
                    data_criacao_atual = datetime.strptime(card_tmp['createdAt'], '%Y-%m-%dT%H:%M:%S%z')

                    if card_mais_atualizado is None:
                        card_mais_atualizado = card_tmp
                    else:
                        data_criacao_mais_atualizado = datetime.strptime(card_mais_atualizado['createdAt'],
                                                                         '%Y-%m-%dT%H:%M:%S%z')
                        if data_criacao_mais_atualizado < data_criacao_atual:
                            card_mais_atualizado = card_tmp
            logging.info(f'card_mais_atualizado:{card_mais_atualizado}')
            return card_mais_atualizado
            # endregion Validação para pegar o card mais atual

    def phase(self, id, count=50, search={}, response_fields=None, response_card_fields=None, headers={},
              pagination=None, endCursor=None, limit_pagination_cards_number=0):
        """ Show phase: Get a phase by its identifier and get cards by pipe identifier. """
        """
            Modo de Usar:
                pipefy.phase(9999):
                    -> Pega as infos da fase com os 30 primeiros cards
                pipefy.phase(9999, pagination=True):
                    -> Pega as infos da fase e realiza a paginação para devolver todos os cards da fase
                pipefy.phase(9999, endCursor="ABCD"):
                    -> Pega as infos da fase e realiza a paginação de acordo com o cursor
                pipefy.phase(9999, pagination=True, limit_pagination_cards_number=999):
                    -> Pega as infos da fase e realiza a paginação para devolver todos os cards até alcançar o numero da variavel limit_pagination_cards_number
        """

        response_fields = response_fields or 'id name cards_count'

        response_card_fields = response_card_fields or 'edges { node { id title assignees { id name email }' \
                                                       ' comments { text } comments_count current_phase { id name } createdAt done due_date ' \
                                                       'fields { field{id type} name value array_value} labels { id name } phases_history { phase { id name } firstTimeIn lastTimeOut } url } }'

        if limit_pagination_cards_number > 0 and count != limit_pagination_cards_number:
            count = limit_pagination_cards_number

        if pagination is None and endCursor is None:

            query = '{ phase(id: %(phase_id)s ) { %(response_fields)s cards(first:%(count)s, search: %(search)s) {pageInfo{endCursor hasNextPage} %(response_card_fields)s } } }' % {
                'phase_id': json.dumps(id),
                'count': json.dumps(count),
                'search': self.__prepare_json_dict(search),
                'response_fields': response_fields,
                'response_card_fields': response_card_fields
            }

            response_phase = self.request(query, headers)

            if response_phase.get('error'):
                return {'error': response_phase.get('error')}
            elif response_phase.get('errors'):
                return {'errors': response_phase.get('errors')};

        elif endCursor is not None:

            query = '{ phase(id: %(phase_id)s ) { %(response_fields)s cards(first:%(count)s, search: %(search)s , after:%(endCursor)s) {pageInfo{endCursor hasNextPage} %(response_card_fields)s } } }' % {
                'phase_id': json.dumps(id),
                'count': json.dumps(count),
                'search': self.__prepare_json_dict(search),
                'response_fields': response_fields,
                'response_card_fields': response_card_fields,
                'endCursor': json.dumps(endCursor)
            }

            response_phase = self.request(query, headers)

            if response_phase.get('error'):
                return {'error': response_phase.get('error')}
            elif response_phase.get('errors'):
                return {'errors': response_phase.get('errors')}

        else:
            query = '{ phase(id: %(phase_id)s ) { %(response_fields)s cards(first:%(count)s, search: %(search)s) {pageInfo{endCursor hasNextPage} %(response_card_fields)s } } }' % {
                'phase_id': json.dumps(id),
                'count': json.dumps(count),
                'search': self.__prepare_json_dict(search),
                'response_fields': response_fields,
                'response_card_fields': response_card_fields
            }

            response_phase = self.request(query, headers)

            if response_phase.get('error'):
                return {'error': response_phase.get('error')}
            elif response_phase.get('errors'):
                return {'errors': response_phase.get('errors')}

            qtd_cards = len(response_phase['data']['phase']['cards']['edges'])

            if limit_pagination_cards_number > 0 and qtd_cards >= limit_pagination_cards_number:
                # Pula a parte da paginação devido a limitação ser menor que a proxima paginação
                qtd_cards = 0

            if qtd_cards > 0:

                hasNextPage = response_phase['data']['phase']['cards']['pageInfo']['hasNextPage']
                endCursor = response_phase['data']['phase']['cards']['pageInfo']['endCursor']

                cards_count = response_phase['data']['phase']['cards_count']
                limit_count = 0

                while hasNextPage:

                    limit_count = qtd_cards + limit_count
                    logging.info(f'Paginando {limit_count} de {cards_count}')

                    query = '{ phase(id: %(phase_id)s ) { %(response_fields)s cards(first:%(count)s, search: %(search)s , after:%(endCursor)s) {pageInfo{endCursor hasNextPage} %(response_card_fields)s } } }' % {
                        'phase_id': json.dumps(id),
                        'count': json.dumps(count),
                        'search': self.__prepare_json_dict(search),
                        'response_fields': response_fields,
                        'response_card_fields': response_card_fields,
                        'endCursor': json.dumps(endCursor)
                    }

                    response_phase_tmp = self.request(query, headers)

                    if response_phase_tmp.get('error'):
                        return {'error': response_phase_tmp.get('error')}
                    elif response_phase_tmp.get('errors'):
                        return {'errors': response_phase_tmp.get('errors')}

                    hasNextPage = response_phase_tmp['data']['phase']['cards']['pageInfo']['hasNextPage']
                    endCursor = response_phase_tmp['data']['phase']['cards']['pageInfo']['endCursor']

                    qtd_cards = len(response_phase['data']['phase']['cards']['edges'])

                    if qtd_cards > 0 and len(response_phase_tmp['data']['phase']['cards']['edges']) > 0:
                        response_phase['data']['phase']['cards']['pageInfo']['hasNextPage'] = hasNextPage
                        response_phase['data']['phase']['cards']['pageInfo']['endCursor'] = endCursor
                        response_phase['data']['phase']['cards']['edges'].extend(
                            response_phase_tmp['data']['phase']['cards']['edges'])

                    if limit_pagination_cards_number > 0 and limit_count >= limit_pagination_cards_number:
                        break

        lista_cards = []
        cards = response_phase.get('data', {}).get('phase').get('cards', {})
        edges = response_phase.get('data', {}).get('phase').get('cards', {}).get('edges', {})
        if len(edges) > 0:
            for edge in response_phase.get('data', {}).get('phase').get('cards', {}).get('edges', {}):
                lista_cards.append(edge['node'])

        if len(cards) > 0:
            response_phase['data']['phase']['cards'] = lista_cards

        return response_phase.get('data', {}).get('phase')

    def createPhase(self, pipe_id, name, done, lateness_time, description, can_receive_card_directly_from_draft,
                    response_fields=None, headers={}):
        """ Create phase: Mutation to create a phase, in case of success a query is returned. """

        response_fields = response_fields or 'phase { id name }'
        query = '''
            mutation {
              createPhase(
                input: {
                  pipe_id: %(pipe_id)s
                  name: %(name)s
                  done: %(done)s
                  lateness_time: %(lateness_time)s
                  description: %(description)s
                  can_receive_card_directly_from_draft: %(can_receive_card_directly_from_draft)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'pipe_id': json.dumps(pipe_id),
            'name': json.dumps(name),
            'done': json.dumps(done),
            'lateness_time': json.dumps(lateness_time),
            'description': json.dumps(description),
            'can_receive_card_directly_from_draft': json.dumps(can_receive_card_directly_from_draft),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createPhase', {}).get('phase')

    def updatePhase(self, id, name, done, description, can_receive_card_directly_from_draft, lateness_time,
                    response_fields=None, headers={}):
        """ Update phase: Mutation to update a phase, in case of success a query is returned. """

        response_fields = response_fields or 'phase { id name }'
        query = '''
            mutation {
              updatePhase(
                input: {
                  id: %(id)s
                  name: %(name)s
                  done: %(done)s
                  description: %(description)s
                  can_receive_card_directly_from_draft: %(can_receive_card_directly_from_draft)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'id': json.dumps(id),
            'name': json.dumps(name),
            'done': json.dumps(done),
            'lateness_time': json.dumps(lateness_time),
            'description': json.dumps(description),
            'can_receive_card_directly_from_draft': json.dumps(can_receive_card_directly_from_draft),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updatePhase', {}).get('phase')

    def deletePhase(self, id, response_fields=None, headers={}):
        """ Delete phase: Mutation to delete a phase of a pipe, in case of success success: true is returned. """

        response_fields = response_fields or 'success'
        query = 'mutation { deletePhase(input: { id: %(id)s }) { %(response_fields)s }' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deletePhase', {})

    def createPhaseField(self, phase_id, type, label, options, description, required, editable,
                         response_fields=None, headers={}):
        """ Create phase field: Mutation to create a phase field, in case of success a query is returned. """

        response_fields = response_fields or 'phase_field { id label }'
        query = '''
            mutation {
              createPhaseField(
                input: {
                  phase_id: %(phase_id)s
                  type: %(type)s
                  label: %(label)s
                  options: %(options)s
                  description: %(description)s
                  required: %(required)s
                  editable: %(editable)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'phase_id': json.dumps(phase_id),
            'type': json.dumps(type),
            'label': json.dumps(label),
            'options': self.__prepare_json_list(options),
            'description': json.dumps(description),
            'required': json.dumps(required),
            'editable': json.dumps(editable),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createPhaseField', {}).get('phase_field')

    def updatePhaseField(self, id, label, options, required, editable, response_fields=None, headers={}):
        """ Update phase field: Mutation to update a phase field, in case of success a query is returned. """

        response_fields = response_fields or 'phase_field { id label }'
        query = '''
            mutation {
              updatePhaseField(
                input: {
                  id: %(id)s
                  label: %(label)s
                  options: %(options)s
                  required: %(required)s
                  editable: %(editable)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'id': json.dumps(id),
            'label': json.dumps(label),
            'options': self.__prepare_json_list(options),
            'required': json.dumps(required),
            'editable': json.dumps(editable),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updatePhaseField', {}).get('phase_field')

    def deletePhaseField(self, id, response_fields=None, headers={}):
        """ Delete phase field: Mutation to delete a phase field, in case of success success: true is returned. """

        response_fields = response_fields or 'success'
        query = 'mutation { deletePhaseField(input: { id: %(id)s }) { %(response_fields)s }' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deletePhaseField', {})

    def createLabel(self, pipe_id, name, color, response_fields=None, headers={}):
        """ Create label: Mutation to create a label, in case of success a query is returned. """

        response_fields = response_fields or 'label { id name }'
        query = '''
            mutation {
              createLabel(
                input: {
                  pipe_id: %(pipe_id)s
                  name: %(name)s
                  color: %(color)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'pipe_id': json.dumps(pipe_id),
            'name': json.dumps(name),
            'color': json.dumps(color),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createLabel', {}).get('label')

    def updateLabel(self, id, name, color, response_fields=None, headers={}):
        """ Update label: Mutation to update a label, in case of success a query is returned. """

        response_fields = response_fields or 'label { id name }'
        query = '''
            mutation {
              updateLabel(
                input: {
                  id: %(id)s
                  name: %(name)s
                  color: %(color)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'id': json.dumps(id),
            'name': json.dumps(name),
            'color': json.dumps(color),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updateLabel', {}).get('label')

    def deleteLabel(self, id, response_fields=None, headers={}):
        """ Delete label: Mutation to delete a label, in case of success success: true is returned. """

        response_fields = response_fields or 'success'
        query = 'mutation { deleteLabel(input: { id: %(id)s }) { %(response_fields)s }' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deleteLabel', {})

    def cards(self, pipe_id, count=999, search={}, response_fields=None, headers={}, pagination=True):
        """ List cards: Get cards by pipe identifier. """
        lista_cards = []
        response_fields = response_fields or '  pageInfo{endCursor hasNextPage} edges { node { id  title }}'
        if pagination:
            query = '{ cards(pipe_id: %(pipe_id)s, first: %(count)s, search: %(search)s) { %(response_fields)s } }' % {
                'pipe_id': json.dumps(pipe_id),
                'count': json.dumps(count),
                'search': self.__prepare_json_dict(search),
                'response_fields': response_fields,
            }

            response = self.request(query, headers)
            if response.get('error'):
                return {'error': response.get('error')}
            elif response.get('errors'):
                return {'errors': response.get('errors')}
            edges = response.get('data', {}).get('cards', {}).get('edges', {})
            if len(edges) > 0:
                for edge in response.get('data', {}).get('cards', {}).get('edges', {}):
                    lista_cards.append(edge['node'])
            hasNextPage = response['data']['cards']['pageInfo']['hasNextPage']
            while hasNextPage:
                endCursor = response['data']['cards']['pageInfo']['endCursor']
                query = '{ cards(pipe_id: %(pipe_id)s, first: %(count)s, search: %(search)s, after: %(after)s) { %(response_fields)s } }' % {
                    'pipe_id': json.dumps(pipe_id),
                    'count': json.dumps(count),
                    'search': self.__prepare_json_dict(search),
                    'after': json.dumps(endCursor),
                    'response_fields': response_fields,
                }
                response = self.request(query, headers)
                edges = response.get('data', {}).get('cards', {}).get('edges', {})
                if len(edges) > 0:
                    for edge in response.get('data', {}).get('cards', {}).get('edges', {}):
                        lista_cards.append(edge['node'])
                hasNextPage = response['data']['cards']['pageInfo']['hasNextPage']

            return lista_cards

    def allCards(self, pipe_id, filter={}, response_fields=None, headers={}, pagination=None, endCursor=None):
        """ List cards: Get cards by pipe identifier. """

        response_fields = response_fields or 'edges { node { id title assignees { id }' \
                                             ' comments { text } comments_count current_phase { name } createdAt done due_date ' \
                                             'fields { name value } labels { name } phases_history { phase { name } firstTimeIn lastTimeOut } url } }'

        if pagination is None and endCursor is None:
            query = '{ allCards(pipeId: %(pipe_id)s, filter: %(filter)s) { %(response_fields)s } }' % {
                'pipe_id': json.dumps(pipe_id),
                'filter': filter,
                'response_fields': response_fields,
            }
        elif endCursor is not None:
            query = '{ allCards(pipeId: %(pipe_id)s, filter: %(filter)s, after:%(endCursor)s) { %(response_fields)s } }' % {
                'pipe_id': json.dumps(pipe_id),
                'filter': filter,
                'response_fields': response_fields,
                'endCursor': json.dumps(endCursor)
            }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('allCards', [])

    def card(self, id, response_fields=None, headers={}):
        """ Show card: Get a card by its identifier. """

        response_fields = response_fields or 'title assignees { id name email } comments { id } comments_count' \
                                             ' current_phase { id name } pipe { id name } createdAt done due_date fields { field{id type} name value array_value } labels { id name } phases_history ' \
                                             '{ phase { id name } firstTimeIn lastTimeOut } url '
        query = '{ card(id: %(id)s) { %(response_fields)s } }' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('card', [])

    def organizationMembers(self, organization_id, response_fields=None, headers={}):
        """
        This function get the information of the Organization members, by passing the organization id
        @param organization_id: Organization ID on Pipefy
        @param response_fields: Response fields custom, otherwise will be returned the default value
        @param headers: to don't use the default headers of POC
        @return: dict with the organization members, if exists
        """

        response_fields = response_fields or 'members { user {  createdAt displayName  id' \
                                             ' email name  username  uuid  avatarUrl confirmationTokenHasExpired confirmed departmentKey hasUnreadNotifications' \
                                             ' intercomHash intercomId invited locale signupData timezone } role_name }'

        query = '{ organization(id: %(organization_id)s) { %(response_fields)s } }' % {
            'organization_id': json.dumps(organization_id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {})

    def createCard(self, pipe_id, fields_attributes, parent_ids=[], response_fields=None, headers={}):
        """ Create card: Mutation to create a card, in case of success a query is returned. """

        response_fields = response_fields or 'card { id title }'
        query = '''
            mutation {
              createCard(
                input: {
                  pipe_id: %(pipe_id)s
                  fields_attributes: %(fields_attributes)s
                  parent_ids: [ %(parent_ids)s ]
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'pipe_id': json.dumps(pipe_id),
            'fields_attributes': self.__prepare_json_dict(fields_attributes),
            'parent_ids': ', '.join([json.dumps(id) for id in parent_ids]),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createCard', {}).get('card')

    def updateCard(self, id, title=None, due_date=None, assignee_ids=[], label_ids=[], response_fields=None,
                   headers={}):
        """ Update card: Mutation to update a card, in case of success a query is returned. """

        response_fields = response_fields or 'card { id title }'
        query = '''
            mutation {
              updateCard(
                input: {
                  id: %(id)s
                  title: %(title)s
                  due_date: %(due_date)s
                  assignee_ids: [ %(assignee_ids)s ]
                  label_ids: [ %(label_ids)s ]
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'id': json.dumps(id),
            'title': json.dumps(title),
            'due_date': due_date.strftime('%Y-%m-%dT%H:%M:%S+00:00') if due_date else json.dumps(due_date),
            'assignee_ids': ', '.join([json.dumps(id) for id in assignee_ids]),
            'label_ids': ', '.join([json.dumps(id) for id in label_ids]),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updateCard', {}).get('card')

    def updateFieldsValues(self, card_id, values, response_fields=None, headers={}):
        """ Update card fields values: Mutation to update a card fields, in case of success a query is returned. """

        response_fields = response_fields or 'clientMutationId'
        query = '''
            mutation {
              updateFieldsValues(
                input: {
                  nodeId: %(card_id)s
                  values: %(values)s
                }
              ) {success %(response_fields)s }
            }
        ''' % {
            'card_id': json.dumps(card_id),
            'values': self.__prepare_json_dict(values),
            'response_fields': response_fields,
        }

        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updateCardField', {})

    def deleteCard(self, id, response_fields=None, headers={}):
        """ Delete card: Mutation to delete a card, in case of success success: true is returned. """

        response_fields = response_fields or 'success'
        query = 'mutation { deleteCard(input: { id: %(id)s }) { %(response_fields)s }}' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deleteCard', {})

    def moveCardToPhase(self, card_id, destination_phase_id, response_fields=None, headers={}):
        """ Move card to phase: Mutation to move a card to a phase, in case of success a query is returned. """

        response_fields = response_fields or 'card{ id current_phase { name } }'
        query = '''
            mutation {
              moveCardToPhase(
                input: {
                  card_id: %(card_id)s
                  destination_phase_id: %(destination_phase_id)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'card_id': json.dumps(card_id),
            'destination_phase_id': json.dumps(destination_phase_id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('moveCardToPhase', {}).get('card')

    def updateCardField(self, card_id, field_id, new_value, response_fields=None, headers={}):
        """ Update card field: Mutation to update a card field, in case of success a query is returned. """

        response_fields = response_fields or 'card{ id }'
        query = '''
            mutation {
              updateCardField(
                input: {
                  card_id: %(card_id)s
                  field_id: %(field_id)s
                  new_value: %(new_value)s
                }
              ) {success %(response_fields)s }
            }
        ''' % {
            'card_id': json.dumps(card_id),
            'field_id': json.dumps(field_id),
            'new_value': json.dumps(new_value),
            'response_fields': response_fields,
        }

        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updateCardField', {})

    def createComment(self, card_id, text, response_fields=None, headers={}):
        """ Create comment: Mutation to create a comment, in case of success a query is returned. """

        response_fields = response_fields or 'comment { id text }'
        query = '''
            mutation {
              createComment(
                input: {
                  card_id: %(card_id)s
                  text: %(text)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'card_id': json.dumps(card_id),
            'text': json.dumps(text),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createComment', {}).get('comment')

    def updateComment(self, id, text, response_fields=None, headers={}):
        """ Update comment: Mutation to update a comment, in case of success a query is returned. """

        response_fields = response_fields or 'comment { id text }'
        query = '''
            mutation {
              updateComment(
                input: {
                  id: %(id)s
                  text: %(text)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'id': json.dumps(id),
            'text': json.dumps(text),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updateComment', {}).get('comment')

    def deleteComment(self, id, response_fields=None, headers={}):
        """ Delete comment: Mutation to delete a comment, in case of success success: true is returned. """

        response_fields = response_fields or 'success'
        query = 'mutation { deleteComment(input: { id: %(id)s }) { %(response_fields)s }}' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deleteComment', {})

    def setRole(self, pipe_id, member, response_fields=None, headers={}):
        """ Set role: Mutation to set a user's role, in case of success a query is returned. """

        response_fields = response_fields or 'member{ user{ id } role_name }'
        query = '''
            mutation {
              setRole(
                input: {
                  pipe_id: %(pipe_id)s
                  member: %(member)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'pipe_id': json.dumps(pipe_id),
            'member': self.__prepare_json_dict(member),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('setRole', {}).get('comment')

    def pipe_relations(self, ids, response_fields=None, headers={}):
        """ Show pipe relations: Get pipe relations by their identifiers. """

        response_fields = response_fields or 'id name allChildrenMustBeDoneToMoveParent allChildrenMustBeDoneToFinishParent' \
                                             ' canCreateNewItems canConnectExistingItems canConnectMultipleItems childMustExistToMoveParent ' \
                                             'childMustExistToFinishParent'
        query = '{ pipe_relations(ids: [%(ids)s]) { %(response_fields)s } }' % {
            'ids': ', '.join([json.dumps(id) for id in ids]),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('pipe_relations')

    def createPipeRelation(self, parentId, childId, name, allChildrenMustBeDoneToFinishParent,
                           childMustExistToMoveParent,
                           childMustExistToFinishParent, allChildrenMustBeDoneToMoveParent, canCreateNewItems,
                           canConnectExistingItems,
                           canConnectMultipleItems, response_fields=None, headers={}):
        """ Create pipe relation: Mutation to create a pipe relation between two pipes, in case of success a query is returned. """

        response_fields = response_fields or 'pipeRelation { id name }'
        query = '''
            mutation {
              createPipeRelation(
                input: {
                  parentId: %(parentId)s
                  childId: %(childId)s
                  name: %(name)s
                  allChildrenMustBeDoneToFinishParent: %(allChildrenMustBeDoneToFinishParent)s
                  childMustExistToMoveParent: %(childMustExistToMoveParent)s
                  childMustExistToFinishParent: %(childMustExistToFinishParent)s
                  allChildrenMustBeDoneToMoveParent: %(allChildrenMustBeDoneToMoveParent)s
                  canCreateNewItems: %(canCreateNewItems)s
                  canConnectExistingItems: %(canConnectExistingItems)s
                  canConnectMultipleItems: %(canConnectMultipleItems)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'parentId': json.dumps(parentId),
            'childId': json.dumps(childId),
            'name': json.dumps(name),
            'allChildrenMustBeDoneToFinishParent': json.dumps(allChildrenMustBeDoneToFinishParent),
            'childMustExistToMoveParent': json.dumps(childMustExistToMoveParent),
            'childMustExistToFinishParent': json.dumps(childMustExistToFinishParent),
            'allChildrenMustBeDoneToMoveParent': json.dumps(allChildrenMustBeDoneToMoveParent),
            'canCreateNewItems': json.dumps(canCreateNewItems),
            'canConnectExistingItems': json.dumps(canConnectExistingItems),
            'canConnectMultipleItems': json.dumps(canConnectMultipleItems),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createPipeRelation', {}).get('pipeRelation')

    def updatePipeRelation(self, id, name, allChildrenMustBeDoneToFinishParent, childMustExistToMoveParent,
                           childMustExistToFinishParent, allChildrenMustBeDoneToMoveParent, canCreateNewItems,
                           canConnectExistingItems,
                           canConnectMultipleItems, response_fields=None, headers={}):
        """ Update pipe relation: Mutation to update a pipe relation, in case of success a query is returned. """

        response_fields = response_fields or 'pipeRelation { id name }'
        query = '''
            mutation {
              updatePipeRelation(
                input: {
                  id: %(id)s
                  name: %(name)s
                  allChildrenMustBeDoneToFinishParent: %(allChildrenMustBeDoneToFinishParent)s
                  childMustExistToMoveParent: %(childMustExistToMoveParent)s
                  childMustExistToFinishParent: %(childMustExistToFinishParent)s
                  allChildrenMustBeDoneToMoveParent: %(allChildrenMustBeDoneToMoveParent)s
                  canCreateNewItems: %(canCreateNewItems)s
                  canConnectExistingItems: %(canConnectExistingItems)s
                  canConnectMultipleItems: %(canConnectMultipleItems)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'id': json.dumps(id),
            'name': json.dumps(name),
            'allChildrenMustBeDoneToFinishParent': json.dumps(allChildrenMustBeDoneToFinishParent),
            'childMustExistToMoveParent': json.dumps(childMustExistToMoveParent),
            'childMustExistToFinishParent': json.dumps(childMustExistToFinishParent),
            'allChildrenMustBeDoneToMoveParent': json.dumps(allChildrenMustBeDoneToMoveParent),
            'canCreateNewItems': json.dumps(canCreateNewItems),
            'canConnectExistingItems': json.dumps(canConnectExistingItems),
            'canConnectMultipleItems': json.dumps(canConnectMultipleItems),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updatePipeRelation', {}).get('pipeRelation')

    def deletePipeRelation(self, id, response_fields=None, headers={}):
        """ Delete pipe relation: Mutation to delete a pipe relation, in case of success success: true is returned. """

        response_fields = response_fields or 'success'
        query = 'mutation { deletePipeRelation(input: { id: %(id)s }) { %(response_fields)s }' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deletePipeRelation', {})

    def tables(self, ids, response_fields=None, headers={}):
        """ List tables: Get tables through table ids. """

        response_fields = response_fields or 'id name url'
        query = '{ tables(ids: [%(ids)s]) { %(response_fields)s } }' % {
            'ids': ', '.join([json.dumps(id) for id in ids]),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('tables')

    def table(self, id, response_fields=None, headers={}):
        """ Show table: Get a table through table id. """

        response_fields = response_fields or 'authorization create_record_button_label description' \
                                             ' icon id labels { id } members { role_name user { id } } my_permissions { can_manage_record ' \
                                             'can_manage_table } name public public_form summary_attributes { id } summary_options { name } ' \
                                             'table_fields { id } table_records { edges { node { id } } } table_records_count title_field { id } url }'
        query = '{ table(id: %(id)s) { %(response_fields)s } }' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('table')

    def tableRecords(self, table_id, count=10, search={}, response_fields=None, headers={}):
        """ List table Records: Get records by table identifier. """

        response_fields = response_fields or 'edges { node { id title created_at status {id name}' \
                                             'record_fields {array_value value field {id type}}}}'

        query = '{ table_records(table_id: %(table_id)s, first: %(count)s, search: %(search)s) { %(response_fields)s } }' % {
            'table_id': json.dumps(table_id),
            'count': json.dumps(count),
            'search': self.__prepare_json_dict(search),
            'response_fields': response_fields,
        }

        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('table_records', [])

    def createTable(self, organization_id, name, description, public, authorization, response_fields=None, headers={}):
        """ Create table: Mutation to create a table, in case of success a query is returned. """

        response_fields = response_fields or 'table { id name description public authorization }'
        query = '''
            mutation {
              createTable(
                input: {
                  organization_id: %(organization_id)s
                  name: %(name)s
                  description: %(description)s
                  public: %(public)s
                  authorization: %(authorization)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'organization_id': json.dumps(organization_id),
            'name': json.dumps(name),
            'description': json.dumps(description),
            'public': json.dumps(public),
            'authorization': json.dumps(authorization),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createTable', {}).get('table')

    def updateTable(self, id, name, description, public, authorization, icon, create_record_button_label,
                    title_field_id, public_form, summary_attributes, response_fields=None, headers={}):
        """ Update table: Mutation to update a table, in case of success a query is returned. """

        response_fields = response_fields or 'table { id name description public authorization }'
        query = '''
            mutation {
              updateTable(
                input: {
                  id: %(id)s
                  name: %(name)s
                  description: %(description)s
                  public: %(public)s
                  authorization: %(authorization)s
                  icon: %(icon)s
                  create_record_button_label: %(create_record_button_label)s
                  title_field_id: %(title_field_id)s
                  public_form: %(public_form)s
                  summary_attributes: [ %(summary_attributes)s ]
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'id': json.dumps(id),
            'name': json.dumps(name),
            'description': json.dumps(description),
            'public': json.dumps(public),
            'authorization': json.dumps(authorization),
            'icon': json.dumps(icon),
            'create_record_button_label': json.dumps(create_record_button_label),
            'title_field_id': json.dumps(title_field_id),
            'public_form': json.dumps(public_form),
            'summary_attributes': ', '.join([json.dumps(summary) for summary in summary_attributes]),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updateTable', {}).get('table')

    def deleteTable(self, id, response_fields=None, headers={}):
        """ Delete table: Mutation to delete a table, in case of success a query with the field success is returned. """

        response_fields = response_fields or 'success'
        query = 'mutation { deleteTable(input: { id: %(id)s }) { %(response_fields)s }' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deleteTable', {})

    def createTableField(self, table_id, type, label, options, description, help, required,
                         minimal_view, custom_validation, response_fields=None, headers={}):
        """ Create table field: Mutation to create a table field, in case of success a query is returned. """

        response_fields = response_fields or 'table_field { id label type options description help required minimal_view custom_validation }'
        query = '''
            mutation {
              createTableField(
                input: {
                  table_id: %(table_id)s
                  type: %(type)s
                  label: %(label)s
                  options: %(options)s
                  description: %(description)s
                  help: %(help)s
                  required: %(required)s
                  minimal_view: %(minimal_view)s
                  custom_validation: %(custom_validation)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'table_id': json.dumps(table_id),
            'type': json.dumps(type),
            'label': json.dumps(label),
            'options': self.__prepare_json_list(options),
            'description': json.dumps(description),
            'help': json.dumps(help),
            'required': json.dumps(required),
            'minimal_view': json.dumps(minimal_view),
            'custom_validation': json.dumps(custom_validation),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createTableField', {}).get('table_field')

    def updateTableField(self, table_id, id, label, options, description, help, required,
                         minimal_view, custom_validation, response_fields=None, headers={}):
        """ Update table field: Mutation to update a table field, in case of success a query is returned. """

        response_fields = response_fields or 'table_field { id label type options description help required minimal_view custom_validation }'
        query = '''
            mutation {
              updateTableField(
                input: {
                  table_id: %(table_id)s
                  id: %(id)s
                  label: %(label)s
                  options: %(options)s
                  description: %(description)s
                  help: %(help)s
                  required: %(required)s
                  minimal_view: %(minimal_view)s
                  custom_validation: %(custom_validation)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'table_id': json.dumps(table_id),
            'id': json.dumps(id),
            'label': json.dumps(label),
            'options': self.__prepare_json_list(options),
            'description': json.dumps(description),
            'help': json.dumps(help),
            'required': json.dumps(required),
            'minimal_view': json.dumps(minimal_view),
            'custom_validation': json.dumps(custom_validation),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updateTableField', {}).get('table_field')

    def setTableFieldOrder(self, table_id, field_ids, response_fields=None, headers={}):
        """ Set table record field value Mutation to set a table field order, in case of success a query with the field success is returned. """

        response_fields = response_fields or 'table_field { id }'
        query = '''
            mutation {
              setTableFieldOrder(
                input: {
                  table_id: %(table_id)s
                  field_ids: %(field_ids)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'table_id': json.dumps(table_id),
            'field_ids': self.__prepare_json_list(field_ids),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('setTableFieldOrder', {}).get('table_field')

    def deleteTableField(self, table_id, id, response_fields=None, headers={}):
        """ Delete table field: Mutation to delete a table field, in case of success a query with the field success is returned. """

        response_fields = response_fields or 'success'
        query = 'mutation { deleteTableField(input: { table_id: %(table_id)s id: %(id)s }) { %(response_fields)s }' % {
            'table_id': json.dumps(table_id),
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deleteTableField', {})

    def table_records(self, table_id, first=10, response_fields=None, headers={}, search={}):
        """ List table records: Get table records with pagination through table id. """

        response_fields = response_fields or 'edges { cursor node { id title url } } pageInfo { endCursor hasNextPage hasPreviousPage startCursor }'
        query = '{ table_records(first: %(first)s, table_id: %(table_id)s, search: %(search)s) { %(response_fields)s } }' % {
            'first': json.dumps(first),
            'table_id': json.dumps(table_id),
            'response_fields': response_fields,
            'search': self.__prepare_json_dict(search),
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('table_records')

    def table_record(self, id, response_fields=None, headers={}):
        """ Show table record: Get table record through table record id. """

        response_fields = response_fields or 'assignees { id name } created_at created_by { id name } due_date' \
                                             ' finished_at id labels { id name } parent_relations { name source_type } record_fields { array_value ' \
                                             'field {id type} date_value datetime_value filled_at float_value name required updated_at value } summary { title value } ' \
                                             'table { id } title updated_at url }'
        query = '{ table_record(id: %(id)s) { %(response_fields)s } ' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('table_record')

    def createTableRecord(self, table_id, title='', due_date=None, fields_attributes=[], response_fields=None,
                          headers={}):
        """ Create table record: Mutation to create a table record, in case of success a query is returned. """

        response_fields = response_fields or 'table_record { id title due_date record_fields { name value } }'
        query = '''
            mutation {
              createTableRecord(
                input: {
                  table_id: %(table_id)s
                  %(title)s
                  %(due_date)s
                  fields_attributes: %(fields_attributes)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'table_id': json.dumps(table_id),
            'title': u'title: %s' % json.dumps(title) if title else '',
            'due_date': u'due_date: %s' % due_date.strftime('%Y-%m-%dT%H:%M:%S+00:00') if due_date else '',
            'fields_attributes': self.__prepare_json_list(fields_attributes),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createTableRecord', {}).get('table_record')

    def updateTableRecord(self, id, title, due_date, response_fields=None, headers={}):
        """ Update table record: Mutation to update a table record, in case of success a query is returned. """

        response_fields = response_fields or 'table_record { id title due_date record_fields { name value } }'
        query = '''
            mutation {
              updateTableRecord(
                input: {
                  id: %(id)s
                  title: %(title)s
                  due_date: %(due_date)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'id': json.dumps(id),
            'title': json.dumps(title),
            'due_date': due_date.strftime('%Y-%m-%dT%H:%M:%S+00:00'),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('updateTableRecord', {}).get('table_record')

    def setTableRecordFieldValue(self, table_record_id, field_id, value, response_fields=None, headers={}):
        """ Set table record field value: Mutation to set a table record field value, in case of success a query with the field success is returned. """

        response_fields = response_fields or 'table_record { id title } table_record_field { value }'
        query = '''
            mutation {
              setTableRecordFieldValue(
                input: {
                  table_record_id: %(table_record_id)s
                  field_id: %(field_id)s
                  value: %(value)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'table_record_id': json.dumps(table_record_id),
            'field_id': json.dumps(field_id),
            'value': json.dumps(value),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('setTableRecordFieldValue', {})

    def deleteTableRecord(self, id, response_fields=None, headers={}):
        """ Delete table record: Mutation to delete a table record, in case of success a query with the field success is returned. """

        response_fields = response_fields or 'success'
        query = '''
                    mutation {
                        deleteTableRecord(
                            input: {
                                id: %(id)s
                            }) { %(response_fields)s
                        }
                    }
                ''' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deleteTableRecord', {})

    def getFieldValueById(self, payload, field_id, array_value: bool = True, is_number: bool = False, is_int_number: bool = False):
        """ Recupera o valor do campo informado"""
        valor_final = ""

        try:
            payload_field = payload['fields']
        except:
            payload_field = payload['record_fields']

        field_tmp = {}
        for field in payload_field:
            valor_array = field['array_value']
            valor = field['value']
            field = field['field']
            if valor is None:
                valor = ""
            else:
                valor = valor.strip()

            if field['id'] == field_id:
                field_tmp = field

            if field['id'] == field_id and valor != '':
                if field['type'] in ['connector', 'attachment', 'label_select', 'checklist_vertical',
                                     'assignee_select'] and array_value is True:
                    valor_final = valor_array
                else:
                    if array_value is True:
                        valor_final = valor
                    else:
                        valor_final = json.loads(valor)

        if is_number or is_int_number:
            if valor_final in ['', None]:
                valor_final = 0
            else:
                if field_tmp['type'] in ['number']:
                    valor_final = float(valor_final)
                    if is_int_number:
                        valor_final = int(valor_final)
                else:
                    valor_final = float(valor_final.replace('.', '').replace(',', '.'))
                    if is_int_number:
                        valor_final = int(valor_final)

        return valor_final

    def createPresignedUrl(self, organization_id, filename, response_fields=None, headers={}):
        """ Create the PresignedUrl: Mutation that returns a url based on organization id and filename. """

        response_fields = response_fields or 'url'
        query = '''
                    mutation{
                        createPresignedUrl(
                            input: {
                                organizationId: %(organizationId)s,
                                fileName: %(fileName)s
                            }){ %(response_fields)s
                        }
                    }
                ''' % {
            'organizationId': json.dumps(organization_id),
            'fileName': json.dumps(filename),
            'response_fields': response_fields
        }

        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createPresignedUrl', {})

    def uploadFileToAws(self, url, data):
        logging.info('SENDING FILE TO PIPEFY AWS - INICIO')
        payload = data

        for i in range(self.qtdTentativasReconexao):
            try:

                r = self.session_request.put(url, data=payload, verify=self.verify_ssl, timeout=self.timeoutConexao)

            except Exception as e:
                logging.info(f"Tentativa: {i} Error Message: {e}")
                logging.info(f"Aguardando {self.timeoutConexao} seg para realizar nova tentativa")
                # sleep(self.timeoutConexao)
                if i > self.qtdTentativasReconexao:
                    raise e

        logging.info('SENDING FILE TO PIPEFY AWS - FIM')
        return r.status_code == 200

    def updateAttachmentFilesToCard(self, data, return_attachments_url_pipefy=False):
        """ Attach a File to Card: Mutation that make a upload to a specific attachment field  """
        '''
        is_local=True -> Test Local Upload setting file on C:\tmp
        Must send a dictionary like follows:

            data = {
                'organization_id': 999,
                'card_id': 999,
                'field_id': '',
                'attachment': [
                    {
                        'type': '',  # local/url/base64/aws options
                        'data': '', # data following the type options above
                        'filename': ''  # filename with extension
                    }
                ]
            }

            Ex.
            data = {
            'organization_id': 99999,
            'card_id': 99999999,
            'field_id': 'anexo',
            'attachment': [
                {
                    'type': 'base64',
                    'data': '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',
                    'filename': 'image.jpg'
                },
                {
                    'type': 'url',
                    'data': 'https://www.tutorialspoint.com/3d_figures_and_volumes/images/logo.png',
                    'filename': 'logo.png'
                },
                {
                    'type': 'local',
                    'data': 'C:/Users/silvio.angelo/Downloads/ANEXO_TESTE.pdf',
                    'filename': 'ANEXO_TESTE.pdf'
                },
                {
                    'type': 'pipefy',
                    'data': 'https://pipefy-prd-us-east-1.s3.amazonaws.com/uploads/dbfd2e82-4ac3-4333-9634-e5e7a0e61582/ANEXO_TESTE_2.pdf',
                    'filename': 'ANEXO_TESTE_2.pdf'
                }
            ]
        }
        '''

        file_path = self.tmp
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        for attachment in data['attachment']:
            type_att = attachment['type']
            data_att = attachment['data']
            filename_att = attachment['filename']
            upload_aws = False

            if type_att == 'base64':
                upload_aws = True
                if not type(data_att) == 'binary':
                    data_att = data_att.encode('utf-8')

                with open(file_path + os.sep + filename_att, 'wb') as file_to_save:
                    decoded_data = base64.decodebytes(data_att)
                    file_to_save.write(decoded_data)

            elif type_att == 'url':
                upload_aws = True
                r = self.session_request.get(data_att, allow_redirects=True, verify=self.verify_ssl, timeout=self.timeoutConexao)
                open(file_path + os.sep + filename_att, 'wb').write(r.content)
                decoded_data = open(file_path + os.sep + filename_att, 'rb').read()

            elif type_att == 'local':
                upload_aws = True
                decoded_data = open(data_att, 'rb').read()

            elif type_att == 'pipefy':
                attachment['url_aws'] = data_att
                url_aws = data_att

            else:
                attachment['url_aws'] = ''

            if upload_aws:
                response = self.createPresignedUrl(data['organization_id'], filename_att)
                url_aws = response['url']
                self.uploadFileToAws(url_aws, decoded_data)

            attachment['url_aws'] = url_aws

            if url_aws.find('/orgs/') > 0:
                start = url_aws.find('/orgs/')
            else:
                start = url_aws.find('/uploads/')

            if url_aws.find('?') > 0:
                end = url_aws.find('?')
            else:
                end = len(url_aws)

            attachment['url_pipefy'] = unquote(url_aws[start + 1:end])

        attachments_url_pipefy = [attachment['url_pipefy'] for attachment in data['attachment']]

        if return_attachments_url_pipefy:
            return attachments_url_pipefy

        self.updateCardField(data['card_id'], data['field_id'], attachments_url_pipefy)

    def createEmail(self, card_id, pipe_ip, from_email, subject, to, text, from_name='', cc=[], email_attachments=[],
                    response_fields=None, headers={}):
        """ Create email: Mutation to create a email, in case of success a query is returned. """

        response_fields = response_fields or 'inbox_email{id}'
        query = '''
            mutation {
              createInboxEmail(
                input: {
                  card_id: %(card_id)s
                  repo_id: %(repo_id)s
                  from: %(from)s
                  from_name: %(from_name)s
                  subject: %(subject)s
                  to: %(to)s
                  cc: %(cc)s
                  emailAttachments: %(emailAttachments)s
                  text: %(text)s
                }
              ) { %(response_fields)s }
            }
        ''' % {
            'card_id': json.dumps(card_id),
            'repo_id': json.dumps(pipe_ip),
            'from': json.dumps(from_email),
            'from_name': json.dumps(from_name),
            'subject': json.dumps(subject),
            'to': json.dumps(to),
            'cc': self.__prepare_json_list(cc),
            'emailAttachments': self.__prepare_json_list(email_attachments),
            'text': json.dumps(text),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('createInboxEmail', {}).get('inbox_email')

    def deleteEmail(self, email_id, response_fields=None, headers={}):
        """ Delete email: Mutation to delete a email, in case of success success: true is returned. """

        response_fields = response_fields or 'success'
        query = 'mutation { deleteInboxEmail(input: { id: %(id)s }) { %(response_fields)s }}' % {
            'id': json.dumps(email_id),
            'response_fields': response_fields,
        }
        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('deleteInboxEmail', {})

    def updateTableRecordField(self, database_record_id, field_id, new_value, response_fields=None, headers={}):
        """ Update card field: Mutation to update a card field, in case of success a query is returned. """

        response_fields = response_fields or 'table_record{id} table_record_field{field{label} value}'
        query = '''
            mutation {
              setTableRecordFieldValue(
                input: {
                  table_record_id: %(database_record_id)s
                  field_id: %(field_id)s
                  value: %(new_value)s
                }
              ) {%(response_fields)s }
            }
        ''' % {
            'database_record_id': json.dumps(database_record_id),
            'field_id': json.dumps(field_id),
            'new_value': json.dumps(new_value),
            'response_fields': response_fields,
        }

        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('setTableRecordFieldValue', {})

    def updateAttachmentFilesToTableRecord(self, data):
        """ Attach a File to Card: Mutation that make a upload to a specific attachment field  """
        '''
        is_local=True -> Test Local Upload setting file on C:\tmp
        Must send a dictionary like follows:

            data = {
                'organization_id': 999,
                'table_record_id': 999,
                'field_id': '',
                'attachment': [
                    {
                        'type': '',  # local/url/base64/aws options
                        'data': '', # data following the type options above
                        'filename': ''  # filename with extension
                    }
                ]
            }

            Ex.
            data = {
            'organization_id': 99999,
            'table_record_id': 99999999,
            'field_id': 'anexo',
            'attachment': [
                {
                    'type': 'base64',
                    'data': '/9j/4AAQSkZJRgABAQAAAQABAAD/2wBDAAIBAQEBAQIBAQECAgICAgQDAgICAgUEBAMEBgUGBgYFBgYGBwkIBgcJBwYGCAsICQoKCgoKBggLDAsKDAkKCgr/2wBDAQICAgICAgUDAwUKBwYHCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgr/wAARCAB4AFoDASIAAhEBAxEB/8QAHwAAAQUBAQEBAQEAAAAAAAAAAAECAwQFBgcICQoL/8QAtRAAAgEDAwIEAwUFBAQAAAF9AQIDAAQRBRIhMUEGE1FhByJxFDKBkaEII0KxwRVS0fAkM2JyggkKFhcYGRolJicoKSo0NTY3ODk6Q0RFRkdISUpTVFVWV1hZWmNkZWZnaGlqc3R1dnd4eXqDhIWGh4iJipKTlJWWl5iZmqKjpKWmp6ipqrKztLW2t7i5usLDxMXGx8jJytLT1NXW19jZ2uHi4+Tl5ufo6erx8vP09fb3+Pn6/8QAHwEAAwEBAQEBAQEBAQAAAAAAAAECAwQFBgcICQoL/8QAtREAAgECBAQDBAcFBAQAAQJ3AAECAxEEBSExBhJBUQdhcRMiMoEIFEKRobHBCSMzUvAVYnLRChYkNOEl8RcYGRomJygpKjU2Nzg5OkNERUZHSElKU1RVVldYWVpjZGVmZ2hpanN0dXZ3eHl6goOEhYaHiImKkpOUlZaXmJmaoqOkpaanqKmqsrO0tba3uLm6wsPExcbHyMnK0tPU1dbX2Nna4uPk5ebn6Onq8vP09fb3+Pn6/9oADAMBAAIRAxEAPwD9/KKKKACiivC/+Cjf7fHwh/4JsfsneJP2pvjC7TwaXELfQ9EglCz61qcgIt7KInOC7AlmwdkaSPghCKTaSGk5OyPVfiT8Vfhh8GvClz47+L3xG0Hwrodmu681nxJq8NjaQDIGXmmZUUZI6nvXyJq3/Bxj/wAEYdH1i90Kf9t/SZZ9Pn8q4e18NatLCxy3zRzLaGOZPlOHjZlOVwTuXP8AK7+3d/wUb/a4/wCClHxwvvir+0R8Rr/Unurtho3hq1lddN0eHe/l29rADtVVDld5BkfJLMxNebeFvhv4o1eV7HS9CuLi42DzQi7hECwHbgc9+xNY1ajprc9LL8A8bNpJtLd7L8n+h/af+y1/wU1/YM/bU1C70T9mX9pvw34n1KxYLc6SkslreL7iC5SORx/tKpHTnkV7sDmv4UdC0b46fs66vZ/E+y07WtJFleRj7aLVlRSckAl1K84ypIPOCOQK/cn/AIJO/wDBx54u+FupeFvhL+29ql9rXgHxH5dro/j+7ujc3uj3JLAR3DZLXEWVOeS6ZwowERxVopK7HPLK1pcqd1una/yfXqfvLRVfSNW0vXtKttc0TUYLyyvbdJ7S7tZlkinidQyujqSGUggggkEHIqxW55YUUUUAFFFFACMcKT7V/MP/AMHKX7XXxB/4KFf8FANJ/Ze+Fc0moeHvCGoS6D4M0q0cMt7qLSLHe6idpOd0kZgQnIEUG4AeYSf6Af8Agpj+1Np/7Gn7D/xC+PdzcyR3emaDJBpHkOBJ9sn/AHMTrnrsZ/NPfbGx7V/N5/wRo8JXP7UP/BUWP4n6hcPeQeHtIE7NKCzW9xMBFhSMdC0hGcYUdBzjy8fiHTdl0V3+SX3n0WQ4SFRyqzV/sr82/W2x9q/8Ewv+DbL4M/D3SdO+If7T08mv+IV8uf8As+LK28DdTHjkOOACT154AOK/Snw1/wAEz/2O9OvLS9079n3w9am2dBC9taBD8vQ/L1PXJPPJ7mvV/AtnaWFnEJIsoqZB9cdq7XS9St50UInQ7lGOVOa+ehia1afNKR62NrPDrkpQslofL/7Vf/BKz9lz41/A3UvhFdfCPTYbGe3OySKD51Ycpz3CnBGcgED0r+ev9s79hLxJ+xBq+p/BnU7y4/4Q/VATa3V5KB9ju1xL97GQOMrszkRch5Aqy/1g3l2s1tLHNGcGMrjHtX54/wDBYf8AYx8P/tB/DWa9XTFE/lvE0sYAILIyBs+uHbHvtHAzWssRUpu6ehpk1eNdOnWXzOW/4Nbv+Cj2p/tHfs66j+x/8W9amuvGnw2LS2F1c53XelO4Ckk870kZs5J4fAACYH6t1/Lr/wAEZ/iHqf7Lf7dnw3+J0mqpY2+r66/h3xC00hG5HuGt2GA/zKvMKkh182J343At/USpBUENkeor6LAV5VqOu6Pnc+wtPDY5umrRlr/mLRRRXceKFBopD0oA/Fj/AIO/f2w38K/C/wAFfsa+E9cjjvtaD6/4nhRyJYLIia3tm4BzHLsv4WGBy8ZyO/yT/wAG0+o+Gvhh8PPiR+0H4ttp0t73XYbSK4jiDySQwIpWJFAyWLPj04ySApI+fP8AgvJ+0nd/tHf8FFf2h/H0sl39k8PeM18B6DG8oaOGHTEWGdVIydr3Fi84B4zOxABr9Cv+CQfwE8XfBj/gnn4BvNe+Hmn3r3GjXGsOIRI0ji6le4i8yNlIaRVdUOANuOM5OfncyqXpzfml8kr/AOR9zlFN0oUo2urNv1bSX3XkfeVx+3ddfDvU4brxr8F9eh8OTbRFqljHHdSR7jhfMghdpAGzxhTjvivon4a/GjwP8RdIg17QL+KWGWJXjZeu0gHp1r8gvFP7VH/BRST4geEdB8G/AO4Nj4ollF/q9x4ols38OqsoVnuY44XWNSmZBHG1wzAbAxc4H15+wZ8SdQ8efFq68C65Z21nq2n6Ba3Gv6aFaOUPNJLHFI6ptC7xAzDIDOPnI5y3hz9rTcXZJM9nFYHBYqnN2d43u15f1ufY3xD+Pnwy+GOgXGvePPFFpptjEpMs93KEVR+PU56AcmvnrXP2wv2Yf2k4734b+DvGTTT3EEn2SWSyljhuNqhhJFK6hJBghlYEg44zzXgX7TnxC+I1vrfiG18FeErLXvEOmeK5NPhlugt1Hptu0SyxtJEzMtspxIokkAYlMhiTsPg37Of/AAUw8d/GTRrSy+On7KOs+FNPuNci0hm1rTI4ZTcbIm8wFLe3eEIXxgx7NysBL5hjjl3j7ScG5LRGNDL8JhGnTu5Pz/r8z5F/aZ+FcPwW/aA+JMGlaZHaxWF+niTT763ik32szMqTldn3FCR8DGN1y5HTA/pU/Zk8VX3jn9nDwD4z1S/kurvVfBumXV5cTZ3yTPaxtIzA8htxbIPIORX89X/BRzwxZfDL9pLwlr+peONQj0XxLpl3o6zi2k8yVmKSWwkymJFPkNtLBt+wnua/aH/gix8XJvjF/wAE7PAeu3kl29zZ2slrcm9kZpFk3ea0eWz8sZl8oDJAEYGeK9nKZKM3F9jxOJqfNThVXf8ANf8AAPqyiiivePjgps2BExLYGOTnGKdWV461WfQvBOsa3axh5bPS7ieNCm4MyRswGO/I6UnsNK7sfxyeOPDOsfGbVItX1uGRNV+IvjHXvEmrOrloJ57hbl4yCDyVV2OABwfmHBr+mb9h/S/Cc37N/hbTbCGNLddCthCmAMR+WoUDBx0x04r8HfCvwgnk/ao8D+F9R024gistamsLuymt2uGguJSluu5VXH+suGGQMAkjOOa/aL9gfxnBdfDpNEsIGWDSJ59OgV3BPl20726t8pwf9V1BweoJ618Lia9Sd3J9dj9Oo04SpRpw00v87n0hqHwu8KLYzTx6FakyBgVbcV6ntnFcR8Efh94a8J/GXUvFFpp1k2oakkQ1a+jt1SSVY8iGJmA3MqKzbQThd5x1Nd6+vRSWPlyXGdyY2da+dvCnxp8a/C741apZ6x4FudQ0aWW4me/iYsyuZCYlC4yy7MjKklSoBXBBrk9rT9tC52YTD4mphK0etrdjvtO+FPw+1X4ja/ev4Zs1utcu0l1qRFCzXLRIscMhbqdqDbg/gRznqLj9lP4eS6kviG+0GK4kQfu0nRGHrySCSBk8Z715H+y38U/GHxj+K+s/EDW/Bl3odrapcWxgnA+YNKPIyRkM+xGZgCdvmAd6+hdY8UqIEj83GFPIPUd/xxXRSqrUyx9GvGvCMOyufkR/wcp2Wn/D+1+EPxAjbEXh/wCIlq10o+68BimLqcAnG1emM4LCv0E/4IT6dc+GP2cvEngyTUIbuC18UyX1hdQuxE9reg3dtId3IzbSwce3vX55/wDBeAr+0B8XvB/wDisIrhI9N1fxFds+cILW0MEeSASp33IbP+z1Bwa+0f8Ag2d8SXOv/sKxWmt6TLBqmlx2dlc3Eow1zCiyiFjn5jtGUDdCqqB90k+zllRvERi+zPE4hpQWWcyet1f9P1P0cooor6U+ECodRtIL+wmsblS0c0TJIAcEqRg81NXLfHLxrefDX4KeMPiLp1ss1xoHhfUNRghY4EjwW8kqqT2yVA/GlJ2TY4q8kj+ePwbNZ67+0vp/j6N7ZLl/EttfTyTAfaGljKMNzlsFWG2UKpBcLKDuGBX0d/wR2/avXxr49+MHwo1fVLcXfhD4k3os7KE8R6bdnzrfawOGzKt3yB0APcV4Z4Qs7fxL8ZR4r8Pie4sbDVrG7sDBH5yGVdF1MKr8fe8ySJQTjjIBG0KPkX/gkb471vwn/wAFJfEtx8OdTvbyGLwjtu4pUZGv0iazjl3Bs4YMWdScElcZAc18bKmqsJvsr/iv8z9Fw8/Y1ad38Ukvwf6o/fP4l/tC3Xwx8N33if8A4Ru81PyJ1SK2sIw7hMAtJtJAwBknnPHGTxXg7ftxeLtO1lteufgXr7aczqzyRWkk8mxyB/y7pKue2Nxz27V3+gfFLTfHXh+K60+5t5JJGRJbadlU5YgAYbrnpip9H/ZK1vVrn+1PAuqT6TCzLIYLaQlAwJORnODnPQivnYqcny31Pv8AL6mW0m5YuN1bvoUfh5/wUY+Henaxa+Eta+EPibw2uoXxEJbwxfeS7My5Zma3QqfmDFmG3HOcDj3WPx7Fepey3EhNtCS0LHqy7c4z9c/pXij/AAs1j4P663iHxIbvWdUu5WUTahMLjykb5X2jjG4ZGTk84zj5a8p/bX/bas/2dPg1rXiCztvtmq29jKmmaVbn5p7jYxVflBIUBSzMAdqKxwcYPdRfNJJs8jM4YZ1ZPCq0X53Pj79pP44S/En/AIKm/FfSvC4a6PhT4Hz2bAMAhvJJUm8vf6FJ4FIHO4EYJFfoX/wbW6pBafs/61ok0CRXOo29rqB2u37xhPdxvgE4AVDbHA5HmgH+Gvx+/Yn8JeOfHnhjxn+0N4qaH+2tfu0+3i4sWieea4vllcuFYPISsDyFQQoDKoIUbB+mH/BCX4rx+Dvjl4J+Dt3E8VxrvgfU5LmBogvlzSG3utnTAEf2WQKo5/enuDXu4afssfC3p+h8Xm1N1cBNdVr913+Gx+wlFFFfVHwoV8/f8FT/ANoTw1+zJ/wT8+K3xS8RqkzJ4NvbHTbJpQrXd3cwtBDEuSM/M+4gc7VY9q9o8f8AxB8H/C7wbqPxA8ea9b6Zo+k2rXGoX9y+EhjHc+voAOSSAASa/D7/AIK/ftv61/wUAv7L4c6dYy6Z8MtMu2ul0y9Zkk1KOPeGnucK3lM7qUjK7xCsNwW6uK87MsZDC4d21k9Ej1MpwUsXi4t/AndvyXT1PkX9iX4/XOn+IPDPhm48UrMTqng231C2jjK3a3BiNlMS+cuc3EisuGbKMACFda89/wCCNfh/T9N/4K+eKNDsFmbTPK1q3tJZ4wm5FvoSuBhQD93gAYz0FaX7P/wX06+8daB8TtP8Tahb32r+P9J1CwgtFZY7iBbmbyLk+UMK00iNMFDDynKE43A1B/wT8gj+H3/BWLS7jTdPjjjvvEWspvgkyPImCyRoSfvBfJbkd2PoRXzdGrGlCcH9pf8AB/4B95PBxxFVTp/Yd7fg/wBW/kfsL8QfghqPgPxWmreE0ZIJn861KJjynzlk46qTzj/61dlovxg8f+GrCOxvtKu4vLIZxCNwc/hzjpXr11oMHivw3HIIy7hFdD2rPHhDTrmzFveWgLj5cBcH9K8+NO8rnd9aagoy1sfOPxl+MXxM8cW/2Cw0+5tVD4adgBI+egUL3JI6+lfJX7e3wig8FfAqW++IV3Pc3uuTr/aexiz2mmJ+/uljA5Zvs8chIBBdvXCrX6P23wztW1T7dNbqLe3csgCD5m9q+Dv+CuGpz65YzWUFtIsVgsYtLwD5LScSeek7g4O3dbiMkE584qRgkjSMbSuS6zktNjyv9nzwfJ8LvgXoGh3OkzRynULzW5bIWhLpAHXT7RUdQAYS8jyrJnhX5I4A9H/YC1+T4e/t/fCzxXe2a2i2+t3umNcy3IRJEkvLq3lIz0wkkbEEZJd8MAdtc/8AtK6/YeDfgvr2jWniKWaHS9ci0KznPLpZizgmQMD8nCQzEEA4x2ya4HxR4iNp4+8N+MtPgktzYWkWvXMEYCyJ5ksUEuFAAOVjlbB5ySMkjNbzqShJW+zZ/ieX7L2sJJ/auvwP6RQQwyKWvHf2a/2z/gp8etA0LRIfiToNv42vtFiu7/wfLqkMeoKQpEkiWxfzGhLI5WQAqVHXOQPXzPGDgsPzr7enUjVgpx2Z+dVKc6M3Cas0fzOeDv8Agqf+2B+07qPhv9mvxj8Z9c8dfE/WoItQ8ea/fWscOm+GY5BGcW9nFGlvHPErwQKqwrH9pPmymQhNnYftU3NhceGV+Gvhcf2bpixx2viO8022eQzIVCG0hOQA2VhhBIG+XZG7A3DZ+d/+COngPVLL4b+K/wBoa80y3uvEHiG7kGn6ldqFRpizxQ27FCHVHnLswXAO1CcbAa96k8Maf4suJ9KvdYk1DTdK1KGOa+ktURtSuoMec5kRhsYTTJufbEIwu9iyBDXzWP8AfrvuvzPt8vj7PDxe19V6dP8AM5/4fWOpad4x0WHwMuni9guP+EvuoZmG23s7KEmytz0dt8dtaRqxIZt8pYMRXnX/AAS1+HniHxV+3XfeMdT0GS1it7pI/sskRDQSK+CCc9Au4BiTkL2OBXrnhrwREmq362HiNjNe6aNT1zxBeW+9ZpRcRpb2kUTqGZCPMCRkIyrEsjhBOY1+z/8Agln+w/pEWiT/ALQZxc33ixo9Ya+DmRXS6RbyJEY/wKk6hQMADjGenn1KUvZp9dvyf6HsYavCm53e6PvHwBpJXRoWdd+YlXgcNU974Qma5L2rIEYndvXkda0fBWk6lo8Z06W0RII4wI/L4II7YxgAADvW/Hp18zhY4/lIOD3xXNySvdHLUxHLPc4++8GeTpj+VbrIyRs0plHGO/8AWvyZ/wCCumvan4Qm1SezvwWl00vbxS4ERZZo5pJCxIAMdslzKBkFmjUA7sbv2ui8Ni+0S5s2Kr5sLIHXkjI5P1r8Xv8Ag4Xt/Dvw8+J3wltWW4tb3WPEk91BcR3LRor2kUeHcod2zfOg4z82PlJIrphQnLYjB4ynWnJPoeLfHvS38W/CDUPLvLd7efxHp2pTRW06sYz/AGOI5lJU4J/fSRljxkE8ZUjZ+BGn6TaQxrpyveRaXpFhb6w+ow+ZFDaOs6mUlzydk0khyCflDc5AfL/ZpOgfFT4c+Dm0qJbR544H1LTRZLts7ySCfdauhGC0TMiLvG5lMZwC2B6fp2qeE9M+N7aVLYMtrqujw3GnLcRuYkeONYmJjQEiVvITAbClY2CklwtZy93EyT9DoXNLDpo+WP8AgsZ4B0zWvgZ4f+IltrUkXizwhqAlsNSs51jeQPcTxXMRdMnfG1tatEAQFAlwSXAr40sf+CvH/BT/AE+yhsLT/gox8b4ooIljiiT4kanhFUYCj/SegAxX19+034ytPGXh3xf8HvGXiZLaO51qcWd1cXAimtbqDZNFcuxBODP5kkjNgBHXBLOob8zfEug6z4f8R6hoN0sttLY3stvJbNcZMTI5UpkHBwRjI44r6HKsVCdJwT2PCzrBYinKNWK3P00/4JQfFO30D/gn1rMHh/S7i71y08YmwtYhM8fzTRykspTLBFWVZCy4YNGMKeCfofxDpmn+ENETQrS0s7lbSzgl+xxsVjup3dYIoYmY5EUjGGEiJg3lRMoVkcoCiuOu/wDapR6c3/BOvB/7lCXXlX5I+Zfjj8TNQ0Xw/wCOfHvigL/ZyeFNUsPCEsTI6XNvLd2sPmLGOIyjLpt0pU/8tXGcldv7x/8ABGdoPHP/AATp+F/isae8T3HhHS0YyKVLtDYW9uWweeTEepJoororQi4JHLiqs4YRyT1v/X5H1T/YVlDE6tCN+M5xjvSxaSXTEaBcZxgUUVyezjex4zr1OW9y9aWbqCqrgbe/ev57f+Dyb4jSeGvj78Efh/4fvpIryz8Javql2q55Wa5hjibjgkG2kIPVSoIIPNFFd2BpxdVJ+ZEa9WHM4u235mX+wr8Q7D4z/BbWrx9RtYNQ8S6dBrtvcxRKCmozRL9pVFGMpFPZYVWPCj5mw4zB+0d4n8T6V8PPCHx41rU5LL7H4pWLUIFaTzfJEgWS3xgMwK7xg7cbRtwVGSiuGvQprFuy/qx9fgZzlQjd/wBXPkPw7ZzeKP21LTTvHeoxywfEPTpG1bTr+A+Rbzb5Fto2VOEMMkMbBiSATtPevftL+HHhK00y3tNY+HHh+8u4oES6u7vU1WWeQKAzuPLOGJySMnBJ5NFFcMZONOD62/I96vShKdn5fkf/2Q==',
                    'filename': 'image.jpg'
                },
                {
                    'type': 'url',
                    'data': 'https://www.tutorialspoint.com/3d_figures_and_volumes/images/logo.png',
                    'filename': 'logo.png'
                },
                {
                    'type': 'local',
                    'data': 'C:/Users/silvio.angelo/Downloads/ANEXO_TESTE.pdf',
                    'filename': 'ANEXO_TESTE.pdf'
                },
                {
                    'type': 'pipefy',
                    'data': 'https://pipefy-prd-us-east-1.s3.amazonaws.com/uploads/dbfd2e82-4ac3-4333-9634-e5e7a0e61582/ANEXO_TESTE_2.pdf',
                    'filename': 'ANEXO_TESTE_2.pdf'
                }
            ]
        }
        '''

        file_path = self.tmp
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        for attachment in data['attachment']:
            type_att = attachment['type']
            data_att = attachment['data']
            filename_att = attachment['filename']
            upload_aws = False

            if type_att == 'base64':
                upload_aws = True
                if not type(data_att) == 'binary':
                    data_att = data_att.encode('utf-8')

                with open(file_path + filename_att, 'wb') as file_to_save:
                    decoded_data = base64.decodebytes(data_att)
                    file_to_save.write(decoded_data)

            elif type_att == 'url':
                upload_aws = True
                r = self.session_request.get(data_att, allow_redirects=True, verify=self.verify_ssl, timeout=self.timeoutConexao)
                open(file_path + filename_att, 'wb').write(r.content)
                decoded_data = open(file_path + filename_att, 'rb').read()

            elif type_att == 'local':
                upload_aws = True
                decoded_data = open(data_att, 'rb').read()

            elif type_att == 'pipefy':
                attachment['url_aws'] = data_att
                url_aws = data_att

            else:
                attachment['url_aws'] = ''

            if upload_aws:
                response = self.createPresignedUrl(data['organization_id'], filename_att)
                url_aws = response['url']
                self.uploadFileToAws(url_aws, decoded_data)

            attachment['url_aws'] = url_aws

            if url_aws.find('/orgs/') > 0:
                start = url_aws.find('/orgs/')
            else:
                start = url_aws.find('/uploads/')

            if url_aws.find('?') > 0:
                end = url_aws.find('?')
            else:
                end = len(url_aws)

            attachment['url_pipefy'] = unquote(url_aws[start:end])

        attachments_url_pipefy = [attachment['url_pipefy'] for attachment in data['attachment']]

        self.updateTableRecordField(data['table_record_id'], data['field_id'], attachments_url_pipefy)

    def exportPipeReportGenerateAsync(self, pipe_id='', pipe_report_id='', campos_export_report=[],
                                      response_fields=None, headers={}):
        """
            Description: Export the Excel File.
        """

        # Pega todos os campos do relatorio para extrair
        if len(campos_export_report) == 0 and pipe_report_id not in ['', None]:

            response_pipe = self.pipe(pipe_id, response_fields='name reports{id name fields}')

            pipe_name = response_pipe.get('name')
            if pipe_name in ['', None]:
                msg = f'Pipe {pipe_id} não encontrado'
                raise PipefyException(msg)

            report_name_list = [report for report in response_pipe.get('reports') if report['id'] == pipe_report_id]

            report_name = ''
            if len(report_name_list) > 0:
                campos_export_report = report_name_list[0].get('fields')

        elif len(campos_export_report) == 0:
            # Pega todos os campos do Pipe para extrair
            response_pipe = self.pipe(pipe_id)
            logging.info(f'response_pipe:{response_pipe}')
            campos_export_report = [
                "card_id",
                "title",
                "current_phase",
                "labels",
                "due_date",
                "created_by",
                "assignees",
                "finished_at",
                "created_at",
                "updated_at",
                "last_comment",
                "last_comment_at",
                "expired_at",
                "overdue"
            ]

            list_start_form_index_name = [field['index_name'] for field in response_pipe['start_form_fields']]
            campos_export_report.extend(list_start_form_index_name)

            for phase in response_pipe['phases']:
                list_phase_index_name = [field['index_name'] for field in phase['fields']]
                campos_export_report.extend(list_phase_index_name)

        logging.info(f'campos_export_report:{campos_export_report}')

        response_fields = response_fields or 'id state'
        query = '''
                    mutation {
                      exportPipeReport(
                        input: {
                          pipeReportId: %(pipeReportId)s
                          pipeId: %(pipeId)s
                          columns: %(columns)s
                        }
                      ) {
                        pipeReportExport{
                            %(response_fields)s
                        }
                      }
                    }
                ''' % {
            'pipeReportId': json.dumps(pipe_report_id),
            'pipeId': json.dumps(pipe_id),
            'columns': json.dumps(campos_export_report),
            'response_fields': response_fields,
        }

        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            return response.get('data', {}).get('exportPipeReport', {}).get('pipeReportExport', {})

    def exportPipeReportStatus(self, id, response_fields=None, return_attachments_url_pipefy=False, pipe_id=None, headers={}):
        response_fields = response_fields or 'fileURL state'

        query = '{ pipeReportExport (id: %(id)s) { %(response_fields)s } }' % {
            'id': json.dumps(id),
            'response_fields': response_fields,
        }

        response = self.request(query, headers)

        if response.get('error'):
            return {'error': response.get('error')}
        elif response.get('errors'):
            return {'errors': response.get('errors')}
        else:
            response_tmp = response.get('data', {}).get('pipeReportExport', {})

            if response_tmp.get('state') not in ['done']:
                return response_tmp

            elif return_attachments_url_pipefy in [False]:
                    return response_tmp
            else:
                file_url = response_tmp.get('fileURL')
                filename, file_extension = os.path.splitext(os.path.basename(file_url))

                if pipe_id not in [None]:
                    response_pipe = self.pipe(pipe_id)
                    pipe_name = response_pipe['name'].replace('/', '_')
                    filename = f'{pipe_id}_{pipe_name}'

                if '?' in file_extension:
                    file_extension = file_extension.split('?')[0]

                data = {
                    'organization_id': 129719,
                    'card_id': 99999999,
                    'field_id': 'anexo',
                    'attachment': [
                        {
                            'type': 'url',
                            'data': file_url,
                            'filename': f'{filename}{file_extension}'
                        }
                    ]
                }

                response = {
                    'fileURL': self.updateAttachmentFilesToCard(data, return_attachments_url_pipefy=return_attachments_url_pipefy),
                    'state': 'done'
                }

                return response
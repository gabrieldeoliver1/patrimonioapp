import json
import csv
import os
import uuid
from datetime import datetime
import logging

logger = logging.getLogger(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
USERS_FILE = os.path.join(BASE_DIR, 'users.json')
BENS_JSON_FILE = os.path.join(BASE_DIR, 'bens.json')
BENS_CSV_FILE = os.path.join(BASE_DIR, 'patrimonio.xlsx - Sheet1.csv')
SETORES_FILE = os.path.join(BASE_DIR, 'setores.json')
HISTORICO_FILE = os.path.join(BASE_DIR, 'historico_bens.json')
NOTIFICACOES_FILE = os.path.join(BASE_DIR, 'notificacoes.json')

def load_json_data(file_path, default_data=None):
    if default_data is None:
        default_data = [] 
    
    if not os.path.exists(file_path):
        logger.warning(f"Arquivo JSON não encontrado: {file_path}. Retornando dados padrão.")
        return default_data

    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if file_path == USERS_FILE and default_data == []:
                 return data if isinstance(data, dict) else {}
            return data
    except (IOError, json.JSONDecodeError) as e:
        logger.error(f"Erro ao carregar o arquivo JSON {file_path}: {e}")
        if file_path == USERS_FILE and default_data == []:
            return {}
        return default_data

def save_json_data(file_path, data):
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=4, ensure_ascii=False)
        logger.info(f"Dados salvos com sucesso em {file_path}")
        return True
    except IOError as e:
        logger.error(f"Erro de I/O ao salvar dados em {file_path}: {e}")
        return False
    except TypeError as e:
        logger.error(f"Erro de tipo ao serializar dados para JSON em {file_path}: {e}")
        return False

def get_users():
    return load_json_data(USERS_FILE, default_data={})

def save_users(users_data):
    return save_json_data(USERS_FILE, users_data)

def find_user_by_username(username):
    users = get_users()
    return users.get(username)

def _load_bens_from_csv():
    bens_data_csv = []
    if not os.path.exists(BENS_CSV_FILE):
        logger.warning(f"Arquivo CSV de bens não encontrado: {BENS_CSV_FILE}")
        return bens_data_csv

    try:
        with open(BENS_CSV_FILE, mode='r', encoding='utf-8-sig') as csvfile:
            reader = csv.DictReader(csvfile)
            for row in reader:
                bem = {
                    "id": row.get("ID", str(uuid.uuid4())).strip(),
                    "nome": row.get("Nome do Item", "").strip(),
                    "descricao": row.get("Descricao", "").strip(),
                    "numero_patrimonio": row.get("Numero Patrimonio", "").strip(),
                    "setor_atual": row.get("Setor Atual", "").strip(), 
                    "data_aquisicao": row.get("Data Aquisicao", "").strip(),
                    "status": row.get("Status", "Ótimo").strip(), # Default para o novo padrão de status
                    "observacoes": row.get("Observacoes", "").strip()
                }
                bens_data_csv.append(bem)
        logger.info(f"Bens carregados do CSV: {len(bens_data_csv)} itens.")
    except Exception as e:
        logger.error(f"Erro ao carregar bens do arquivo CSV {BENS_CSV_FILE}: {e}")
    return bens_data_csv

def get_bens():
    bens_data = load_json_data(BENS_JSON_FILE, default_data=[])

    if not bens_data and os.path.exists(BENS_CSV_FILE):
        logger.info(f"Arquivo {BENS_JSON_FILE} vazio ou não encontrado. Tentando carregar de {BENS_CSV_FILE}.")
        bens_data_from_csv = _load_bens_from_csv()
        if bens_data_from_csv:
            if save_json_data(BENS_JSON_FILE, bens_data_from_csv):
                logger.info(f"Dados de bens carregados do CSV e salvos em {BENS_JSON_FILE}.")
                return bens_data_from_csv
            else:
                logger.error(f"Falha ao salvar bens carregados do CSV em {BENS_JSON_FILE}.")
                return [] 
        else:
            logger.warning(f"Nenhum dado de bem carregado do CSV. {BENS_JSON_FILE} permanece/será criado vazio.")
            save_json_data(BENS_JSON_FILE, []) 
            return []
    return bens_data

def save_bens(bens_data):
    return save_json_data(BENS_JSON_FILE, bens_data)

def find_bem_by_id(bem_id):
    bens = get_bens()
    for bem in bens:
        if isinstance(bem, dict) and bem.get('id') == bem_id:
            return bem
    return None

def get_next_id():
    return str(uuid.uuid4())

def get_setores():
    return load_json_data(SETORES_FILE, default_data=[])

def save_setores(setores_data):
    return save_json_data(SETORES_FILE, setores_data)

def find_setor_by_id(setor_id):
    setores = get_setores()
    for setor in setores:
        if isinstance(setor, dict) and setor.get('id') == setor_id:
            return setor
    return None

def get_historico():
    return load_json_data(HISTORICO_FILE, default_data=[])

def save_historico(historico_data):
    return save_json_data(HISTORICO_FILE, historico_data)

def add_historico_entry(bem_id, tipo_acao, detalhes, usuario_responsavel):
    historico = get_historico()
    nova_entrada = {
        "id": get_next_id(),
        "bem_id": bem_id,
        "data_hora": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "tipo_acao": tipo_acao,
        "detalhes": detalhes,
        "usuario_responsavel": usuario_responsavel
    }
    historico.append(nova_entrada)
    return save_historico(historico)

def get_notificacoes():
    return load_json_data(NOTIFICACOES_FILE, default_data=[])

def save_notificacoes(notificacoes_data):
    return save_json_data(NOTIFICACOES_FILE, notificacoes_data)

def find_notificacao_by_id(not_id):
    notificacoes = get_notificacoes()
    for notificacao in notificacoes:
        if isinstance(notificacao, dict) and notificacao.get('id') == not_id:
            return notificacao
    return None

def add_notificacao(mensagem, tipo="info", destinatario_id=None):
    notificacoes = get_notificacoes()
    nova_notificacao = {
        "id": get_next_id(),
        "mensagem": mensagem,
        "data_criacao": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "lida": False,
        "tipo": tipo,
        "destinatario_id": destinatario_id
    }
    notificacoes.insert(0, nova_notificacao) 
    return save_notificacoes(notificacoes)

def initialize_data_files():
    files_to_initialize = {
        USERS_FILE: {}, 
        BENS_JSON_FILE: [], 
        SETORES_FILE: [],
        HISTORICO_FILE: [],
        NOTIFICACOES_FILE: []
    }
    for file_path, default_content in files_to_initialize.items():
        if not os.path.exists(file_path):
            logger.info(f"Arquivo {file_path} não encontrado. Criando com conteúdo padrão.")
            save_json_data(file_path, default_content)
    
    get_bens()
    logger.info("Verificação e inicialização dos arquivos de dados concluída.")


from flask import Flask, render_template, request, redirect, url_for, session, flash, abort, Response
from functools import wraps
import os
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from collections import Counter
from fpdf import FPDF
from fpdf.enums import XPos, YPos

import data_manager as dm

app = Flask(__name__)
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'fallback_chave_secreta_padrao_para_desenvolvimento_123!@#')

if not app.debug:
    file_handler = logging.FileHandler('app_prod.log', encoding='utf-8')
    file_handler.setLevel(logging.WARNING)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    file_handler.setFormatter(formatter)
    app.logger.addHandler(file_handler)
else:
    app.logger.setLevel(logging.INFO)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Por favor, faça o login para aceder a esta página.', 'warning')
            return redirect(url_for('login'))
        user_data_from_db = dm.find_user_by_username(session['user_id'])
        if not user_data_from_db:
            session.clear()
            flash('Sessão inválida ou utilizador não encontrado. Por favor, faça o login novamente.', 'danger')
            return redirect(url_for('login'))
        session['user_role'] = user_data_from_db.get('role', 'user')
        session['user_nome_completo'] = user_data_from_db.get('nome_completo', session['user_id'])
        user_setor_data = user_data_from_db.get('setores_ids', user_data_from_db.get('setor_id'))
        if session['user_role'] == 'admin':
            session['user_setores_ids'] = []
        elif isinstance(user_setor_data, list):
            session['user_setores_ids'] = [sid for sid in user_setor_data if sid]
        elif isinstance(user_setor_data, str) and user_setor_data:
            session['user_setores_ids'] = [user_setor_data]
        else:
            session['user_setores_ids'] = []
            if session['user_role'] in ['user', 'gestor']:
                 app.logger.warning(f"Utilizador '{session['user_id']}' (role: {session['user_role']}) não possui setores_ids definidos ou válidos.")
        if session['user_role'] in ['user', 'gestor'] and session.get('user_setores_ids'):
            session['user_setor_id'] = session['user_setores_ids'][0]
        else:
            if session['user_role'] == 'admin': session.pop('user_setor_id', None)
            elif not session.get('user_setores_ids'): session.pop('user_setor_id', None)
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    @wraps(f)
    @login_required
    def decorated_function(*args, **kwargs):
        if session.get('user_role') != 'admin':
            flash('Não tem permissão para aceder a esta página.', 'danger')
            return render_template('403.html'), 403
        return f(*args, **kwargs)
    return decorated_function

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for('dashboard'))
    if request.method == 'POST':
        username = request.form.get('username', '').strip(); password = request.form.get('password', '')
        if not username or not password: flash('Nome de utilizador e senha são obrigatórios.', 'warning'); return render_template('login.html')
        user_data = dm.find_user_by_username(username)
        if user_data and check_password_hash(user_data.get('senha', ''), password):
            session['user_id'] = username; flash(f"Login bem-sucedido! Bem-vindo.", 'success'); app.logger.info(f"Utilizador '{username}' logado com sucesso.")
            return redirect(url_for('dashboard'))
        else: flash('Nome de utilizador ou senha inválidos.', 'danger'); app.logger.warning(f"Falha de login para o utilizador '{username}'.")
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    user_id = session.get('user_id', 'Desconhecido'); session.clear(); flash('Sessão terminada com sucesso.', 'info'); app.logger.info(f"Utilizador '{user_id}' deslogado.")
    return redirect(url_for('login'))

@app.route('/')
@login_required
def dashboard():
    todos_bens_raw = dm.get_bens(); todos_bens = [b for b in todos_bens_raw if isinstance(b, dict)]; setores_lista_completa = dm.get_setores(); user_role = session.get('user_role'); user_setores_ids_sessao = session.get('user_setores_ids', []); bens_para_dashboard = []; nome_setor_display = "Visão Geral"; current_selected_ids_for_template = []; setores_para_filtro_gestor_template = []; setores_filtrados_ids = []
    
    if user_role == 'admin':
        admin_choice_setor_ids_param = request.args.getlist('setor_id')
        select_all_admin_param = request.args.get('select_all_setores_admin') == 'true'
        if select_all_admin_param or not admin_choice_setor_ids_param:
            setores_filtrados_ids = [s['id'] for s in setores_lista_completa if isinstance(s,dict) and 'id' in s]
            nome_setor_display = "Todos os Setores da Empresa"
            current_selected_ids_for_template = ['todos']
        else:
            valid_admin_choice_ids = [sid for sid in admin_choice_setor_ids_param if dm.find_setor_by_id(sid)]
            if valid_admin_choice_ids:
                setores_filtrados_ids = valid_admin_choice_ids
                nomes_setores_filtrados = [dm.find_setor_by_id(sid).get('nome', f"ID {sid}") for sid in valid_admin_choice_ids]
                if len(nomes_setores_filtrados) == 1:
                    nome_setor_display = nomes_setores_filtrados[0]
                elif len(nomes_setores_filtrados) <= 3:
                    nome_setor_display = ", ".join(nomes_setores_filtrados)
                else:
                    nome_setor_display = f"{len(nomes_setores_filtrados)} Setor(es) Selecionado(s)"
            else: # Corresponde a 'if valid_admin_choice_ids:'
                nome_setor_display = "Todos os Setores (Filtro(s) Inválido(s) Aplicado(s))"
                setores_filtrados_ids = [s['id'] for s in setores_lista_completa if isinstance(s,dict) and 'id' in s]
            current_selected_ids_for_template = valid_admin_choice_ids if valid_admin_choice_ids else ['todos']
    elif user_role == 'gestor':
        if not user_setores_ids_sessao:
            nome_setor_display = "Nenhum Setor Atribuído"; current_selected_ids_for_template = ['nenhum']
        else:
            setores_para_filtro_gestor_template = [s for s in setores_lista_completa if isinstance(s, dict) and s.get('id') in user_setores_ids_sessao]
            if len(user_setores_ids_sessao) == 1 and not request.args.getlist('setor_id_gestor'):
                setor_id_unico_gestor = user_setores_ids_sessao[0]; setores_filtrados_ids = [setor_id_unico_gestor]; setor_obj = dm.find_setor_by_id(setor_id_unico_gestor); nome_setor_display = setor_obj.get('nome', 'Setor não definido') if setor_obj else 'Setor Inválido'; current_selected_ids_for_template = [setor_id_unico_gestor]
            else:
                gestor_choice_setor_ids_param = request.args.getlist('setor_id_gestor'); select_all_gestor_param = request.args.get('select_all_setores_gestor') == 'true'
                if select_all_gestor_param or (not gestor_choice_setor_ids_param and len(user_setores_ids_sessao) > 1) :
                    setores_filtrados_ids = user_setores_ids_sessao; nome_setor_display = "Meus Setores (Visão Agregada)"; current_selected_ids_for_template = ['todos_do_gestor']
                else:
                    valid_gestor_choice_ids = [sid for sid in gestor_choice_setor_ids_param if sid in user_setores_ids_sessao]
                    if valid_gestor_choice_ids:
                        setores_filtrados_ids = valid_gestor_choice_ids; nomes_setores_filtrados_gestor = [dm.find_setor_by_id(sid).get('nome', f"ID {sid}") for sid in valid_gestor_choice_ids]
                        if len(nomes_setores_filtrados_gestor) == 1: nome_setor_display = nomes_setores_filtrados_gestor[0]
                        elif len(nomes_setores_filtrados_gestor) <= 3 : nome_setor_display = ", ".join(nomes_setores_filtrados_gestor)
                        else: nome_setor_display = f"{len(nomes_setores_filtrados_gestor)} Setor(es) Selecionado(s)"
                    else:
                        setores_filtrados_ids = user_setores_ids_sessao; nome_setor_display = "Meus Setores (Filtro Inválido ou Vazio)"
                    current_selected_ids_for_template = valid_gestor_choice_ids if valid_gestor_choice_ids else ['todos_do_gestor']
    elif user_role == 'user':
        user_setor_id_unico_sessao = session.get('user_setor_id')
        if user_setor_id_unico_sessao:
            setor_obj = dm.find_setor_by_id(user_setor_id_unico_sessao)
            if setor_obj: nome_setor_display = setor_obj.get('nome', 'Setor não definido'); setores_filtrados_ids = [user_setor_id_unico_sessao]; current_selected_ids_for_template = [user_setor_id_unico_sessao]
            else: nome_setor_display = "Setor Atribuído Inválido"; setores_filtrados_ids = []; current_selected_ids_for_template = ['nenhum']
        else: nome_setor_display = "Nenhum Setor Atribuído"; setores_filtrados_ids = []; current_selected_ids_for_template = ['nenhum']
    
    if setores_filtrados_ids : bens_para_dashboard = [b for b in todos_bens if b.get('setor_atual') in setores_filtrados_ids]
    elif user_role == 'admin' and 'todos' in current_selected_ids_for_template: bens_para_dashboard = todos_bens
    
    total_bens_filtrados = len(bens_para_dashboard); title_suffix_display = f" ({nome_setor_display})" if nome_setor_display and nome_setor_display not in ["Todos os Setores da Empresa", "Meus Setores (Visão Agregada)", "Visão Geral", "Nenhum Setor Atribuído", "Setor Atribuído Inválido"] else ""
    bens_que_entraram=0; bens_que_sairam=0; daily_activity_data={}; ultimas_alteracoes_setor_raw_data=[]; historico_completo = dm.get_historico(); data_30_dias_atras = datetime.now() - timedelta(days=30); data_7_dias_atras = datetime.now() - timedelta(days=7); ids_bens_no_dashboard_atual = [b['id'] for b in bens_para_dashboard if isinstance(b, dict) and 'id' in b]
    
    # MODIFICAÇÃO: Ajustando a coleta de dados de atividade diária para o admin para incluir todo o histórico se a visão for ampla
    # Isso garante que o gráfico de atividade diária para o admin mostre dados mesmo que os bens filtrados sejam poucos ou não tenham atividade recente.
    # A filtragem por 'ids_bens_no_dashboard_atual' é mantida para os casos de usuário/gestor ou admin com filtro de setor específico.
    if user_role == 'admin' and ('todos' in current_selected_ids_for_template or not current_selected_ids_for_template):
        # Se o admin está vendo todos os setores ou nenhum filtro específico, pega todo o histórico
        for entrada_hist in historico_completo:
            if not isinstance(entrada_hist, dict): app.logger.warning(f"Item de histórico malformado (não é dict): {entrada_hist}"); continue
            try:
                data_acao_str = entrada_hist.get('data_hora', '');
                if not data_acao_str: continue
                data_acao_obj = datetime.strptime(data_acao_str, "%Y-%m-%d %H:%M:%S.%f") if '.' in data_acao_str else datetime.strptime(data_acao_str, "%Y-%m-%d %H:%M:%S")
                if data_acao_obj >= data_30_dias_atras:
                    if entrada_hist.get('tipo_acao') == 'Cadastro': bens_que_entraram += 1
                    elif entrada_hist.get('tipo_acao') == 'Exclusão': bens_que_sairam +=1
                if data_acao_obj >= data_30_dias_atras: # Coleta para os últimos 30 dias
                    data_str_formatada = data_acao_obj.strftime("%Y-%m-%d"); daily_activity_data[data_str_formatada] = daily_activity_data.get(data_str_formatada, 0) + 1
            except ValueError as e_date_parse: app.logger.warning(f"Data inválida no histórico: '{entrada_hist.get('data_hora')}', Erro: {e_date_parse}"); continue
        ultimas_alteracoes_setor_raw_data = historico_completo # Para o admin, as últimas alterações podem ser de todo o histórico
    else: # Lógica original para outros perfis ou admin com filtro de setor específico
        for entrada_hist in historico_completo:
            if not isinstance(entrada_hist, dict): app.logger.warning(f"Item de histórico malformado (não é dict): {entrada_hist}"); continue
            bem_id_hist = entrada_hist.get('bem_id')
            if bem_id_hist in ids_bens_no_dashboard_atual:
                ultimas_alteracoes_setor_raw_data.append(entrada_hist)
                try:
                    data_acao_str = entrada_hist.get('data_hora', '');
                    if not data_acao_str: continue
                    data_acao_obj = datetime.strptime(data_acao_str, "%Y-%m-%d %H:%M:%S.%f") if '.' in data_acao_str else datetime.strptime(data_acao_str, "%Y-%m-%d %H:%M:%S")
                    if data_acao_obj >= data_30_dias_atras:
                        if entrada_hist.get('tipo_acao') == 'Cadastro': bens_que_entraram += 1
                        elif entrada_hist.get('tipo_acao') == 'Exclusão': bens_que_sairam +=1
                    if data_acao_obj >= data_30_dias_atras: # Coleta para os últimos 30 dias
                        data_str_formatada = data_acao_obj.strftime("%Y-%m-%d"); daily_activity_data[data_str_formatada] = daily_activity_data.get(data_str_formatada, 0) + 1
                except ValueError as e_date_parse: app.logger.warning(f"Data inválida no histórico: '{entrada_hist.get('data_hora')}', Erro: {e_date_parse}"); continue

    ordered_daily_activity_data_final = dict(sorted(daily_activity_data.items())); ultimas_alteracoes_para_template_final = sorted(ultimas_alteracoes_setor_raw_data, key=lambda x: x.get('data_hora', ''), reverse=True)[:5]; bens_map_nomes_completo = {b['id']: b.get('nome', 'N/A') for b in todos_bens if isinstance(b, dict)}; users_map_nomes_completo = {uname: udata.get('nome_completo', uname) for uname, udata in dm.get_users().items()}
    for alt_item in ultimas_alteracoes_para_template_final:
        if isinstance(alt_item, dict): alt_item['nome_bem_alterado'] = bens_map_nomes_completo.get(alt_item.get('bem_id'), 'Bem Desconhecido'); alt_item['nome_usuario_responsavel'] = users_map_nomes_completo.get(alt_item.get('usuario_responsavel'), 'Usuário Desconhecido'); data_hora_str_alt = alt_item.get('data_hora', '');
        try: dt_obj_alt = datetime.strptime(data_hora_str_alt, "%Y-%m-%d %H:%M:%S.%f") if '.' in data_hora_str_alt else datetime.strptime(data_hora_str_alt, "%Y-%m-%d %H:%M:%S"); alt_item['data_hora_formatada'] = dt_obj_alt.strftime("%d/%m/%Y %H:%M")
        except ValueError: alt_item['data_hora_formatada'] = data_hora_str_alt
    chart_data_setor_final = None; chart_data_status_final = None; setores_map_completo = {s['id']: s['nome'] for s in setores_lista_completa if isinstance(s, dict) and 'id' in s and 'nome' in s}
    if user_role == 'admin':
        bens_por_setor_contador = Counter(); bens_para_grafico_setor = bens_para_dashboard
        if 'todos' in current_selected_ids_for_template: bens_para_grafico_setor = todos_bens
        for bem_item in bens_para_grafico_setor:
            if isinstance(bem_item, dict): setor_id_do_bem = bem_item.get('setor_atual'); nome_setor_do_bem = setores_map_completo.get(setor_id_do_bem, 'Setor Desconhecido/Nenhum'); bens_por_setor_contador[nome_setor_do_bem] += 1
        if bens_por_setor_contador: chart_data_setor_final = { "labels": list(bens_por_setor_contador.keys()), "data": list(bens_por_setor_contador.values()) }
        elif total_bens_filtrados == 0 and 'todos' not in current_selected_ids_for_template and 'nenhum' not in current_selected_ids_for_template: chart_data_setor_final = { "labels": [nome_setor_display if nome_setor_display else "Setor(es) Selecionado(s)"], "data": [0] }
        else: chart_data_setor_final = { "labels": ["Sem dados para exibir no gráfico de setores"], "data": [0] }
        # Calculando dados para bens por status para o admin (seção comum abaixo)
        bens_por_status_contador = Counter()
        for bem_item in bens_para_dashboard:
            if isinstance(bem_item, dict): status_bem = bem_item.get('status', 'Condição Desconhecida'); bens_por_status_contador[status_bem] += 1
        if bens_por_status_contador:
            labels_status = list(bens_por_status_contador.keys())
            data_status = list(bens_por_status_contador.values())
        else:
            labels_status = ["Sem bens para exibir condição"]
            data_status = [0]
        chart_data_status_final = { "labels": labels_status, "data": data_status }

    if user_role == 'gestor' or user_role == 'user':
        bens_por_status_contador = Counter()
        for bem_item in bens_para_dashboard:
            if isinstance(bem_item, dict): status_bem = bem_item.get('status', 'Condição Desconhecida'); bens_por_status_contador[status_bem] += 1
        if bens_por_status_contador:
            labels_status = list(bens_por_status_contador.keys())
            data_status = list(bens_por_status_contador.values())
        else:
            label_padrao_status = "Sem bens para exibir condição" 
            if 'nenhum' in current_selected_ids_for_template: label_padrao_status = "Utilizador sem setor atribuído"
            elif total_bens_filtrados == 0 : label_padrao_status = "Nenhum bem neste(s) setor(es)"
            labels_status = [label_padrao_status]
            data_status = [0]
        chart_data_status_final = { "labels": labels_status, "data": data_status }
    app.logger.info(f"Dashboard - Renderizando para user_role='{user_role}', nome_setor_display='{nome_setor_display}'")
    if user_role == 'admin':
        total_setores_geral_calculado = len([s for s in setores_lista_completa if isinstance(s, dict)]); notificacoes_ativas_admin = []
        if dm: notificacoes_todas = dm.get_notificacoes(); notificacoes_ativas_admin = sorted( [n for n in notificacoes_todas if isinstance(n, dict) and not n.get('lida')], key=lambda x: x.get('data_criacao', ''), reverse=True )
        else: app.logger.error("data_manager (dm) não está disponível para buscar notificações.")
        app.logger.info(f"DEBUG: ordered_daily_activity_data_final para admin: {ordered_daily_activity_data_final}") # Linha de depuração adicionada
        return render_template('dashboard_admin.html', total_bens=total_bens_filtrados, total_setores_geral=total_setores_geral_calculado, notificacoes_dashboard=notificacoes_ativas_admin, chart_data_setor=chart_data_setor_final if chart_data_setor_final else {}, chart_condicao_data=chart_data_status_final if chart_data_status_final else {}, daily_activity_data=ordered_daily_activity_data_final if ordered_daily_activity_data_final else {}, ultimas_alteracoes_setor=ultimas_alteracoes_para_template_final, title_suffix=title_suffix_display, nome_setor_selecionado_display=nome_setor_display, current_selected_ids_for_template=current_selected_ids_for_template, setores_para_filtro_admin=setores_lista_completa)
    elif user_role == 'gestor' or user_role == 'user':
        return render_template('dashboard_user.html', total_bens=total_bens_filtrados, chart_data_status=chart_data_status_final if chart_data_status_final else {}, daily_activity_data=ordered_daily_activity_data_final if ordered_daily_activity_data_final else {}, bens_que_entraram=bens_que_entraram, bens_que_sairam=bens_que_sairam, ultimas_alteracoes_setor=ultimas_alteracoes_para_template_final, title_suffix=title_suffix_display, nome_setor_selecionado_display=nome_setor_display, current_selected_ids_for_template=current_selected_ids_for_template, setores_para_filtro_gestor=setores_para_filtro_gestor_template)
    else: app.logger.error(f"Perfil de usuário desconhecido '{user_role}' encontrado na rota do dashboard."); flash("Perfil de usuário desconhecido. Contacte o suporte.", "danger"); return redirect(url_for('logout'))

class PDF(FPDF):
    title = "Relatório"; gerador = "Sistema"
    def header(self):
        font_name = 'Arial'; font_path_local = "DejaVuSans.ttf"
        if os.path.exists(font_path_local):
            try: self.add_font('DejaVu', '', font_path_local); font_name = 'DejaVu'; app.logger.info(f"Fonte '{font_path_local}' carregada para PDF.")
            except Exception as e_font_load: app.logger.error(f"Erro ao carregar fonte TTF '{font_path_local}' para PDF: {e_font_load}. Usando Arial.")
        else: app.logger.warning(f"Arquivo de fonte '{font_path_local}' não encontrado. Usando Arial para PDF. Caracteres PT-BR podem ter problemas.")
        current_font_size = 14 if font_name == 'DejaVu' else 12; self.set_font(font_name, 'B', current_font_size)
        title_text = self.title; page_width = self.w - 2 * self.l_margin; self.set_x(self.l_margin)
        self.cell(page_width, 10, title_text, border=0, align='C', new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_font(font_name, '', 8); info_text = f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')} por: {self.gerador}"
        self.cell(page_width, 7, info_text, border=0, align='R', new_x=XPos.LMARGIN, new_y=YPos.NEXT); self.ln(5)
    def footer(self):
        self.set_y(-15); font_name = self.font_family if self.font_family == 'DejaVu' else 'Arial'
        self.set_font(font_name, 'I', 8); self.set_text_color(128); self.cell(0, 10, f'Página {self.page_no()}/{{nb}}', align='C')
    def fancy_table(self, header_titles, data_rows, column_widths_list):
        font_name = self.font_family if self.font_family == 'DejaVu' else 'Arial'
        self.set_fill_color(52, 152, 219); self.set_text_color(255, 255, 255); self.set_draw_color(100, 100, 100); self.set_line_width(0.2); self.set_font(font_name, 'B', 9)
        for i, header_text in enumerate(header_titles): self.cell(column_widths_list[i], 7, header_text, border=1, align='C', fill=True)
        self.ln()
        self.set_fill_color(236, 240, 241); self.set_text_color(0, 0, 0); self.set_font(font_name, '', 8)
        alternate_fill = False
        for row_data in data_rows:
            y_before_row = self.get_y(); max_row_height = 6
            for i, cell_item in enumerate(row_data):
                self.set_xy(self.l_margin + sum(column_widths_list[:i]), y_before_row)
                cell_text_str = str(cell_item)
                self.multi_cell(column_widths_list[i], max_row_height, cell_text_str, border='LR', align='L', fill=alternate_fill, new_x=XPos.RIGHT, new_y=YPos.TOP, max_line_height=self.font_size * 1.25)
            self.set_xy(self.l_margin, y_before_row + max_row_height); self.ln(0)
            alternate_fill = not alternate_fill
        self.cell(sum(column_widths_list), 0, '', 'T')

@app.route('/relatorio/bens_pdf')
@login_required
def relatorio_bens_pdf():
    app.logger.info("Rota /relatorio/bens_pdf acessada para gerar PDF com FPDF2")
    filtro_setor_ids_param = request.args.getlist('setor_id')
    try:
        todos_bens = dm.get_bens(); setores_lista = dm.get_setores(); setores_map = {s['id']: s['nome'] for s in setores_lista if isinstance(s, dict) and 'id' in s and 'nome' in s}; user_role = session.get('user_role'); user_setores_ids_sessao = session.get('user_setores_ids', []); bens_para_relatorio = []; titulo_para_pdf = "Relatório de Bens"
        if user_role == 'admin':
            if 'todos' in filtro_setor_ids_param or not filtro_setor_ids_param: bens_para_relatorio = todos_bens; titulo_para_pdf = "Relatório Geral de Bens (Todos os Setores)"
            else: setores_efetivos_ids = [sid for sid in filtro_setor_ids_param if dm.find_setor_by_id(sid)]; bens_para_relatorio = [b for b in todos_bens if isinstance(b,dict) and b.get('setor_atual') in setores_efetivos_ids]; nomes_setores = [setores_map.get(sid, f"ID {sid}") for sid in setores_efetivos_ids]; titulo_para_pdf = f"Relatório de Bens - Setor(es): {', '.join(nomes_setores) if nomes_setores else 'Selecionados'}"
        elif user_role == 'gestor':
            if not user_setores_ids_sessao: flash('Gestor não associado a setores.', 'warning'); return redirect(url_for('dashboard'))
            if 'todos_do_gestor' in filtro_setor_ids_param or not filtro_setor_ids_param: setores_efetivos_ids = user_setores_ids_sessao; titulo_para_pdf = "Relatório de Bens - Meus Setores (Visão Agregada)"
            else: setores_efetivos_ids = [sid for sid in filtro_setor_ids_param if sid in user_setores_ids_sessao]; nomes_setores = [setores_map.get(sid, f"ID {sid}") for sid in setores_efetivos_ids]; titulo_para_pdf = f"Relatório de Bens - Setor(es): {', '.join(nomes_setores) if nomes_setores else 'Meus Setores Selecionados'}"
            bens_para_relatorio = [b for b in todos_bens if isinstance(b,dict) and b.get('setor_atual') in setores_efetivos_ids]
        elif user_role == 'user':
            user_setor_id_principal = session.get('user_setor_id')
            if not user_setor_id_principal: flash('Utilizador não associado a um setor.', 'warning'); return redirect(url_for('dashboard'))
            bens_para_relatorio = [b for b in todos_bens if isinstance(b,dict) and b.get('setor_atual') == user_setor_id_principal]; setor_obj_user = dm.find_setor_by_id(user_setor_id_principal); titulo_para_pdf = f"Relatório de Bens - Setor: {setor_obj_user.get('nome', 'N/A') if setor_obj_user else 'N/A'}"
        pdf = PDF(orientation='L', unit='mm', format='A4'); pdf.title = titulo_para_pdf; pdf.gerador = session.get('user_nome_completo', 'Sistema'); pdf.set_author("Sistema de Gestão de Patrimônio"); pdf.alias_nb_pages(); pdf.add_page()
        header_cols = ["Nome", "Patrimônio", "Setor", "Status", "Aquisição", "Descrição", "Obs."]; col_widths_pdf = [55, 25, 40, 25, 22, 65, 45]
        table_data = []
        for bem in bens_para_relatorio:
            if isinstance(bem, dict): nome_setor_pdf = setores_map.get(bem.get('setor_atual'), 'N/A'); row_pdf = [ bem.get('nome', ''), bem.get('numero_patrimonio', ''), nome_setor_pdf, bem.get('status', ''), bem.get('data_aquisicao', ''), bem.get('descricao', ''), bem.get('observacoes', '') ]; table_data.append(row_pdf)
        if table_data: pdf.fancy_table(header_cols, table_data, col_widths_pdf)
        else: current_font = pdf.font_family if hasattr(pdf, 'font_family') and pdf.font_family else 'Arial'; pdf.set_font(current_font, '', 12); pdf.cell(0, 10, "Nenhum bem encontrado para os filtros aplicados.", new_x=XPos.LMARGIN, new_y=YPos.NEXT, align='C')
        pdf_output_bytes = bytes(pdf.output())
        return Response(pdf_output_bytes, mimetype='application/pdf', headers={'Content-Disposition': 'inline;filename=relatorio_bens.pdf'})
    except Exception as e_fpdf_route:
        app.logger.error(f"Erro na rota /relatorio/bens_pdf com FPDF2: {e_fpdf_route}", exc_info=True)
        flash(f'Ocorreu um erro crítico ao gerar o relatório PDF. Verifique os logs do servidor.', 'danger')
        return redirect(request.referrer or url_for('dashboard'))

@app.route('/bens')
@login_required
def listar_bens():
    todos_bens = dm.get_bens(); setores_raw = dm.get_setores(); setores_map = { setor['id']: setor['nome'] for setor in setores_raw if isinstance(setor, dict) and 'id' in setor and 'nome' in setor }; bens_para_listar_final = []; user_role = session.get('user_role'); filtro_setor_admin_param = request.args.getlist('setor_id_filter')
    if user_role == 'admin':
        if filtro_setor_admin_param and 'todos' not in filtro_setor_admin_param: bens_para_listar_final = [b for b in todos_bens if isinstance(b, dict) and b.get('setor_atual') in filtro_setor_admin_param]
        else: bens_para_listar_final = todos_bens
    elif user_role == 'gestor':
        user_setores_ids_atuais = session.get('user_setores_ids', [])
        if user_setores_ids_atuais: bens_para_listar_final = [b for b in todos_bens if isinstance(b, dict) and b.get('setor_atual') in user_setores_ids_atuais]
        else: flash('Gestor não associado a setores. Contacte o administrador.', 'warning'); bens_para_listar_final = []
    elif user_role == 'user':
        user_setor_id_principal_atual = session.get('user_setor_id')
        if user_setor_id_principal_atual: bens_para_listar_final = [b for b in todos_bens if isinstance(b, dict) and b.get('setor_atual') == user_setor_id_principal_atual]
        else: flash('Utilizador não associado a um setor. Contacte o administrador.', 'warning'); bens_para_listar_final = []
    bens_processados_final = []
    for bem_item_lista in bens_para_listar_final:
        if isinstance(bem_item_lista, dict): bem_copia_lista = bem_item_lista.copy(); bem_copia_lista['nome_setor_atual'] = setores_map.get(bem_item_lista.get('setor_atual'), 'Setor não definido'); bens_processados_final.append(bem_copia_lista)
        else: app.logger.warning(f"Item de bem malformado encontrado ao listar bens: {bem_item_lista}")
    return render_template('bens.html', bens=bens_processados_final, setores_para_filtro=setores_raw if user_role == 'admin' else [], selected_filter_ids=filtro_setor_admin_param if user_role == 'admin' else [])

@app.route('/bens/cadastrar', methods=['GET', 'POST'])
@admin_required
def cadastrar_bem():
    setores = dm.get_setores()
    if request.method == 'POST':
        try:
            novo_bem = { "id": dm.get_next_id(), "nome": request.form['nome'].strip(), "descricao": request.form.get('descricao', '').strip(), "numero_patrimonio": request.form['numero_patrimonio'].strip(), "setor_atual": request.form['setor_atual'], "data_aquisicao": request.form['data_aquisicao'], "status": request.form.get('status', 'Ótimo').strip(), "observacoes": request.form.get('observacoes', '').strip() }
            if not novo_bem['nome'] or not novo_bem['numero_patrimonio'] or not novo_bem['setor_atual']: flash("Nome, Número de Património e Setor são obrigatórios.", "danger")
            elif dm.find_bem_by_patrimonio(novo_bem['numero_patrimonio']): flash(f"Número de patrimônio '{novo_bem['numero_patrimonio']}' já existe.", "danger")
            else:
                bens = dm.get_bens(); bens.append(novo_bem)
                if dm.save_bens(bens):
                    dm.add_historico_entry(novo_bem['id'], "Cadastro", f"Bem '{novo_bem['nome']}' cadastrado.", session['user_id'])
                    dm.add_notificacao(f"Novo bem '{novo_bem['nome']}' (Pat: {novo_bem['numero_patrimonio']}) cadastrado por {session.get('user_nome_completo', session.get('user_id'))}.", tipo="info")
                    flash('Bem cadastrado com sucesso!', 'success'); app.logger.info(f"Bem '{novo_bem['id']}' ('{novo_bem['nome']}') cadastrado pelo utilizador '{session['user_id']}'.")
                    return redirect(url_for('listar_bens'))
                else: flash('Erro ao salvar o bem. Tente novamente.', 'danger')
        except Exception as e: app.logger.error(f"Erro ao cadastrar bem: {e}", exc_info=True); flash(f"Ocorreu um erro inesperado ao cadastrar o bem: {e}", "danger")
        return render_template('cadastrar_bem.html', setores=setores, bem_form=request.form)
    return render_template('cadastrar_bem.html', setores=setores, bem_form={})

@app.route('/bens/editar/<bem_id>', methods=['GET', 'POST'])
@admin_required
def editar_bem(bem_id):
    bem_original = dm.find_bem_by_id(bem_id)
    if not bem_original: flash('Bem não encontrado.', 'danger'); app.logger.warning(f"Tentativa de editar bem inexistente com ID: {bem_id}"); return redirect(url_for('listar_bens'))
    if request.method == 'POST':
        try:
            bem_atualizado = bem_original.copy(); bem_atualizado['nome'] = request.form['nome'].strip(); bem_atualizado['descricao'] = request.form.get('descricao', '').strip(); novo_numero_patrimonio = request.form['numero_patrimonio'].strip(); bem_atualizado['setor_atual'] = request.form['setor_atual']; bem_atualizado['data_aquisicao'] = request.form['data_aquisicao']; bem_atualizado['status'] = request.form.get('status', bem_original.get('status', 'Ótimo')).strip(); bem_atualizado['observacoes'] = request.form.get('observacoes', bem_original.get('observacoes', '')).strip()
            if not bem_atualizado['nome'] or not novo_numero_patrimonio or not bem_atualizado['setor_atual']: flash("Nome, Número de Património e Setor são obrigatórios.", "danger")
            elif novo_numero_patrimonio != bem_original.get('numero_patrimonio') and dm.find_bem_by_patrimonio(novo_numero_patrimonio): flash(f"Número de patrimônio '{novo_numero_patrimonio}' já existe em outro bem.", "danger")
            else:
                bem_atualizado['numero_patrimonio'] = novo_numero_patrimonio; bens = dm.get_bens(); atualizado_na_lista = False
                for i, b in enumerate(bens):
                    if b.get('id') == bem_id: bens[i] = bem_atualizado; atualizado_na_lista = True; break
                if atualizado_na_lista and dm.save_bens(bens):
                    mudancas = []; [mudancas.append(f"'{key}' de '{bem_original.get(key, 'N/A')}' para '{value}'") for key, value in bem_atualizado.items() if key != 'id' and bem_original.get(key) != value]
                    detalhes_historico = f"Bem '{bem_atualizado['nome']}' (ID: {bem_id}) editado. " + (f"Mudanças: {'; '.join(mudancas)}." if mudancas else "Nenhuma alteração de valor detectada.")
                    dm.add_historico_entry(bem_id, "Edição", detalhes_historico, session['user_id'])
                    dm.add_notificacao(f"Bem '{bem_atualizado['nome']}' (Pat: {bem_atualizado['numero_patrimonio']}) atualizado por {session.get('user_nome_completo', session.get('user_id'))}.", tipo="info")
                    flash('Bem atualizado com sucesso!', 'success'); app.logger.info(f"Bem '{bem_id}' ('{bem_atualizado['nome']}') atualizado pelo utilizador '{session['user_id']}'.")
                    return redirect(url_for('listar_bens'))
                else: flash('Erro ao salvar as alterações do bem. Tente novamente.', 'danger')
        except Exception as e: app.logger.error(f"Erro ao editar bem {bem_id}: {e}", exc_info=True); flash(f"Ocorreu um erro inesperado ao editar o bem: {e}", "danger")
        setores = dm.get_setores(); dados_para_template = request.form.to_dict() if request.method == 'POST' else bem_original; dados_para_template['id'] = bem_id
        return render_template('editar_bem.html', bem=dados_para_template, setores=setores)
    setores = dm.get_setores()
    return render_template('editar_bem.html', bem=bem_original, setores=setores)

@app.route('/bens/excluir/<bem_id>', methods=['POST'])
@admin_required
def excluir_bem(bem_id):
    bens_atuais = dm.get_bens(); bem_para_excluir_obj = dm.find_bem_by_id(bem_id)
    if not bem_para_excluir_obj: flash('Bem não encontrado para exclusão.', 'warning'); app.logger.warning(f"Tentativa de excluir bem inexistente com ID: {bem_id} por '{session['user_id']}'."); return redirect(url_for('listar_bens'))
    nome_do_bem_excluido = bem_para_excluir_obj.get('nome', f"ID {bem_id}"); numero_pat_bem_excluido = bem_para_excluir_obj.get('numero_patrimonio', 'N/P')
    bens_apos_exclusao = [b_item for b_item in bens_atuais if b_item.get('id') != bem_id]
    if len(bens_atuais) == len(bens_apos_exclusao) and bem_para_excluir_obj : flash('Erro crítico: Bem encontrado mas não pôde ser removido da lista de dados.', 'danger'); app.logger.error(f"Falha ao remover bem {bem_id} da lista, embora tenha sido encontrado.")
    elif dm.save_bens(bens_apos_exclusao):
        dm.add_notificacao(f"Bem '{nome_do_bem_excluido}' (Pat: {numero_pat_bem_excluido}) excluído por {session.get('user_nome_completo', session.get('user_id'))}.", tipo="aviso")
        dm.add_historico_entry(bem_id, "Exclusão", f"Bem '{nome_do_bem_excluido}' (Pat: {numero_pat_bem_excluido}, ID: {bem_id}) excluído.", session['user_id'])
        flash(f"Bem '{nome_do_bem_excluido}' excluído com sucesso!", 'success'); app.logger.info(f"Bem '{bem_id}' ('{nome_do_bem_excluido}') excluído pelo utilizador '{session['user_id']}'.")
    else: flash('Erro ao salvar as alterações após excluir o bem. Tente novamente.', 'danger')
    return redirect(url_for('listar_bens'))

@app.route('/bens/transferir/<bem_id>', methods=['GET', 'POST'])
@admin_required
def transferir_bem(bem_id):
    bem_obj_transferir = dm.find_bem_by_id(bem_id)
    if not bem_obj_transferir: flash('Bem não encontrado.', 'danger'); app.logger.warning(f"Tentativa de transferir bem inexistente com ID: {bem_id}"); return redirect(url_for('listar_bens'))
    if request.method == 'POST':
        try:
            setor_id_origem = bem_obj_transferir.get('setor_atual'); setor_id_destino_form = request.form.get('novo_setor'); observacoes_da_transferencia = request.form.get('observacoes_transferencia', '').strip()
            if not setor_id_destino_form: flash("Setor de destino não selecionado.", "warning")
            elif setor_id_origem == setor_id_destino_form: flash('O bem já está neste setor. Nenhuma transferência realizada.', 'info')
            else:
                setor_obj_origem = dm.find_setor_by_id(setor_id_origem) if setor_id_origem else None; setor_obj_destino = dm.find_setor_by_id(setor_id_destino_form)
                if not setor_obj_destino: flash('Setor de destino inválido.', 'danger')
                else:
                    nome_bem_transferido = bem_obj_transferir.get('nome', 'N/A'); nome_setor_origem_display = setor_obj_origem['nome'] if setor_obj_origem else "Setor Desconhecido/Nenhum"; nome_setor_destino_display = setor_obj_destino['nome']
                    bem_obj_transferir['setor_atual'] = setor_id_destino_form; lista_bens_atual = dm.get_bens(); transferencia_salva = False
                    for i, b_loop_item in enumerate(lista_bens_atual):
                        if b_loop_item.get('id') == bem_id: lista_bens_atual[i] = bem_obj_transferir; transferencia_salva = True; break
                    if transferencia_salva and dm.save_bens(lista_bens_atual):
                        detalhes_para_historico = f"Bem '{nome_bem_transferido}' transferido de '{nome_setor_origem_display}' para '{nome_setor_destino_display}'. Observações: {observacoes_da_transferencia if observacoes_da_transferencia else 'Nenhuma'}."
                        dm.add_notificacao(f"Bem '{nome_bem_transferido}' transferido para o setor '{nome_setor_destino_display}' por {session.get('user_nome_completo', session.get('user_id'))}.", tipo="info")
                        dm.add_historico_entry(bem_id, "Transferência", detalhes_para_historico, session['user_id'])
                        flash(f"Bem '{nome_bem_transferido}' transferido para '{nome_setor_destino_display}' com sucesso!", 'success'); app.logger.info(f"Bem '{bem_id}' ('{nome_bem_transferido}') transferido de '{setor_id_origem}' para '{setor_id_destino_form}' pelo utilizador '{session['user_id']}'.")
                        return redirect(url_for('listar_bens'))
                    else: flash('Erro ao salvar a transferência do bem. Tente novamente.', 'danger')
        except Exception as e_transf_bem: app.logger.error(f"Erro ao transferir bem {bem_id}: {e_transf_bem}", exc_info=True); flash(f"Ocorreu um erro inesperado ao transferir o bem: {e_transf_bem}", "danger")
    setores_disponiveis_transf = dm.get_setores()
    return render_template('transferir_bem.html', bem=bem_obj_transferir, setores=setores_disponiveis_transf)

@app.route('/usuarios')
@admin_required
def listar_usuarios():
    users_dict = dm.get_users(); setores_map = {s['id']: s['nome'] for s in dm.get_setores() if isinstance(s, dict)}; lista_usuarios = []
    for username, details in users_dict.items():
        if isinstance(details, dict):
            user_display = details.copy(); user_display['username'] = username
            setor_info = details.get('setores_ids', details.get('setor_id'))
            if isinstance(setor_info, list): user_display['nomes_setores'] = ", ".join([setores_map.get(sid, f"ID Inv: {sid}") for sid in setor_info if sid]) if setor_info else "Nenhum"
            elif isinstance(setor_info, str) and setor_info: user_display['nomes_setores'] = setores_map.get(setor_info, f"ID Inv: {setor_info}")
            else: user_display['nomes_setores'] = "Nenhum (Admin ou não definido)" if user_display.get('role') == 'admin' else "Nenhum"
            lista_usuarios.append(user_display)
        else: app.logger.warning(f"Dados de usuário malformados para {username}")
    return render_template('usuarios.html', usuarios=lista_usuarios)

@app.route('/usuarios/cadastrar', methods=['GET', 'POST'])
@admin_required
def cadastrar_usuario():
    setores = dm.get_setores()
    if request.method == 'POST':
        try:
            username = request.form['username'].strip(); password = request.form['password']; confirm_password = request.form['confirm_password']; role = request.form.get('role', 'user'); nome_completo = request.form.get('nome_completo', '').strip(); email = request.form.get('email', '').strip().lower(); setores_selecionados_ids = request.form.getlist('setores_ids')
            if not username or not password or not confirm_password: flash('Nome de utilizador e senhas são obrigatórios.', 'danger')
            elif password != confirm_password: flash('As senhas não coincidem!', 'danger')
            elif len(password) < 6: flash('A senha deve ter pelo menos 6 caracteres.', 'danger')
            elif role != 'admin' and not setores_selecionados_ids: flash('Pelo menos um setor é obrigatório para Usuários Padrão e Gestores.', 'danger')
            elif dm.find_user_by_username(username): flash('Este nome de utilizador já existe.', 'danger')
            else:
                users = dm.get_users(); hashed_password = generate_password_hash(password)
                users[username] = { "senha": hashed_password, "role": role, "nome_completo": nome_completo, "email": email, "setores_ids": setores_selecionados_ids if role != 'admin' else [], "data_cadastro": datetime.now().strftime("%Y-%m-%d %H:%M:%S") }
                if dm.save_users(users): flash('Utilizador cadastrado com sucesso!', 'success'); app.logger.info(f"Utilizador '{username}' cadastrado pelo administrador '{session['user_id']}'."); return redirect(url_for('listar_usuarios'))
                else: flash('Erro ao salvar o utilizador. Tente novamente.', 'danger')
        except Exception as e: app.logger.error(f"Erro ao cadastrar utilizador: {e}", exc_info=True); flash(f"Ocorreu um erro inesperado ao cadastrar o utilizador: {e}", "danger")
        return render_template('cadastrar_usuario.html', form_data=request.form, setores=setores)
    return render_template('cadastrar_usuario.html', form_data={}, setores=setores)

@app.route('/usuarios/editar/<user_id_edit>', methods=['GET', 'POST'])
@admin_required
def editar_usuario(user_id_edit):
    users = dm.get_users(); usuario_para_editar_data = users.get(user_id_edit); setores = dm.get_setores()
    if not usuario_para_editar_data: flash('Utilizador não encontrado.', 'danger'); app.logger.warning(f"Tentativa de editar utilizador inexistente: {user_id_edit} por '{session['user_id']}'."); return redirect(url_for('listar_usuarios'))
    if request.method == 'POST':
        try:
            usuario_atualizado_temp = usuario_para_editar_data.copy(); role_nova = request.form.get('role', usuario_atualizado_temp.get('role')); usuario_atualizado_temp['role'] = role_nova; usuario_atualizado_temp['nome_completo'] = request.form.get('nome_completo', usuario_atualizado_temp.get('nome_completo', '')).strip(); usuario_atualizado_temp['email'] = request.form.get('email', usuario_atualizado_temp.get('email', '')).strip().lower()
            novos_setores_ids = request.form.getlist('setores_ids')
            if role_nova == 'admin': usuario_atualizado_temp['setores_ids'] = []
            elif not novos_setores_ids: flash('Pelo menos um setor é obrigatório para Usuários Padrão e Gestores.', 'danger'); form_data_com_erro = usuario_para_editar_data.copy(); form_data_com_erro.update(request.form.to_dict()); form_data_com_erro['username_original'] = user_id_edit; return render_template('editar_usuario.html', usuario_para_editar=form_data_com_erro, user_id_edit=user_id_edit, setores=setores)
            else: usuario_atualizado_temp['setores_ids'] = novos_setores_ids
            nova_senha = request.form.get('nova_senha'); confirmar_nova_senha = request.form.get('confirmar_nova_senha'); senha_alterada_msg = ""
            if nova_senha:
                if not confirmar_nova_senha: flash('Por favor, confirme a nova senha.', 'warning')
                elif nova_senha != confirmar_nova_senha: flash('As novas senhas não coincidem. A senha não foi alterada.', 'warning')
                elif len(nova_senha) < 6: flash('A nova senha deve ter pelo menos 6 caracteres. A senha não foi alterada.', 'warning')
                else: usuario_atualizado_temp['senha'] = generate_password_hash(nova_senha); senha_alterada_msg = 'Senha atualizada com sucesso. '
            users[user_id_edit] = usuario_atualizado_temp
            if dm.save_users(users):
                flash(f'{senha_alterada_msg}Dados do utilizador atualizados com sucesso!', 'success'); app.logger.info(f"Dados do utilizador '{user_id_edit}' atualizados pelo administrador '{session['user_id']}'.")
                if user_id_edit == session.get('user_id'): session['user_role'] = usuario_atualizado_temp['role']; session['user_nome_completo'] = usuario_atualizado_temp['nome_completo']
                return redirect(url_for('listar_usuarios'))
            else: flash('Erro ao salvar as alterações do utilizador. Tente novamente.', 'danger')
        except Exception as e: app.logger.error(f"Erro ao editar utilizador {user_id_edit}: {e}", exc_info=True); flash(f"Ocorreu um erro inesperado ao editar o utilizador: {e}", "danger")
        form_data = usuario_para_editar_data.copy(); form_data.update(request.form.to_dict()); form_data['username_original'] = user_id_edit
        return render_template('editar_usuario.html', usuario_para_editar=form_data, user_id_edit=user_id_edit, setores=setores)
    usuario_para_template = usuario_para_editar_data.copy(); usuario_para_template['username_original'] = user_id_edit
    setor_info_template = usuario_para_template.get('setores_ids', usuario_para_template.get('setor_id'))
    if isinstance(setor_info_template, str): usuario_para_template['setores_ids'] = [setor_info_template] if setor_info_template else []
    elif not isinstance(setor_info_template, list): usuario_para_template['setores_ids'] = []
    return render_template('editar_usuario.html', usuario_para_editar=usuario_para_template, user_id_edit=user_id_edit, setores=setores)

@app.route('/usuarios/excluir/<user_id_delete>', methods=['POST'])
@admin_required
def excluir_usuario(user_id_delete):
    if user_id_delete == session.get('user_id'): flash('Não pode excluir a si mesmo.', 'danger'); return redirect(url_for('listar_usuarios'))
    users = dm.get_users()
    if user_id_delete in users:
        del users[user_id_delete]
        if dm.save_users(users): flash('Utilizador excluído com sucesso!', 'success'); app.logger.info(f"Utilizador '{user_id_delete}' excluído pelo administrador '{session['user_id']}'.")
        else: flash('Erro ao salvar as alterações após excluir o utilizador. Tente novamente.', 'danger')
    else: flash('Utilizador não encontrado.', 'warning'); app.logger.warning(f"Tentativa de excluir utilizador inexistente: {user_id_delete} por '{session['user_id']}'.")
    return redirect(url_for('listar_usuarios'))

@app.route('/setores')
@admin_required
def listar_setores():
    setores = dm.get_setores()
    return render_template('setores.html', setores=setores)

@app.route('/setores/cadastrar', methods=['GET', 'POST'])
@admin_required
def cadastrar_setor():
    if request.method == 'POST':
        try:
            nome_setor = request.form['nome_setor'].strip(); descricao_setor = request.form.get('descricao_setor', '').strip()
            if not nome_setor: flash("O nome do setor é obrigatório.", "danger")
            else:
                setores = dm.get_setores()
                if any(s.get('nome','').lower() == nome_setor.lower() for s in setores if isinstance(s, dict)): flash(f'Setor com nome "{nome_setor}" já existe.', 'warning')
                else:
                    next_id_func = getattr(dm, 'get_next_id_setor', getattr(dm, 'get_next_id', lambda: str(int(datetime.now().timestamp() * 1000))))
                    novo_setor = { "id": next_id_func(), "nome": nome_setor, "descricao": descricao_setor, "data_criacao": datetime.now().strftime("%Y-%m-%d %H:%M:%S") }
                    setores.append(novo_setor)
                    if dm.save_setores(setores): flash('Setor cadastrado com sucesso!', 'success'); app.logger.info(f"Setor '{nome_setor}' (ID: {novo_setor['id']}) cadastrado por '{session['user_id']}'."); return redirect(url_for('listar_setores'))
                    else: flash('Erro ao salvar o setor. Tente novamente.', 'danger')
        except Exception as e: app.logger.error(f"Erro ao cadastrar setor: {e}", exc_info=True); flash(f"Ocorreu um erro inesperado ao cadastrar o setor: {e}", "danger")
        return render_template('editar_setor.html', acao="Cadastrar", setor=request.form)
    return render_template('editar_setor.html', acao="Cadastrar", setor={})

@app.route('/setores/editar/<setor_id>', methods=['GET', 'POST'])
@admin_required
def editar_setor(setor_id):
    setor_original = dm.find_setor_by_id(setor_id)
    if not setor_original: flash('Setor não encontrado.', 'danger'); app.logger.warning(f"Tentativa de editar setor inexistente com ID: {setor_id} por '{session['user_id']}'."); return redirect(url_for('listar_setores'))
    if request.method == 'POST':
        try:
            nome_antigo = setor_original.get('nome',''); setor_atualizado = setor_original.copy(); setor_atualizado['nome'] = request.form['nome_setor'].strip(); setor_atualizado['descricao'] = request.form.get('descricao_setor', setor_original.get('descricao', '')).strip()
            if not setor_atualizado['nome']: flash("O nome do setor é obrigatório.", "danger")
            else:
                setores = dm.get_setores()
                if any(s.get('nome','').lower() == setor_atualizado['nome'].lower() and s.get('id') != setor_id for s in setores if isinstance(s, dict)): flash(f'Já existe outro setor com o nome "{setor_atualizado["nome"]}".', 'warning')
                else:
                    atualizado_na_lista = False
                    for i, s_loop in enumerate(setores):
                        if isinstance(s_loop, dict) and s_loop.get('id') == setor_id: setores[i] = setor_atualizado; atualizado_na_lista = True; break
                    if atualizado_na_lista and dm.save_setores(setores): flash('Setor atualizado com sucesso!', 'success'); app.logger.info(f"Setor ID '{setor_id}' ('{nome_antigo}' para '{setor_atualizado['nome']}') atualizado por '{session['user_id']}'."); return redirect(url_for('listar_setores'))
                    else: flash('Erro ao salvar as alterações do setor. Tente novamente.', 'danger')
        except Exception as e: app.logger.error(f"Erro ao editar setor {setor_id}: {e}", exc_info=True); flash(f"Ocorreu um erro inesperado ao editar o setor: {e}", "danger")
        dados_para_template = request.form.to_dict(); dados_para_template['id'] = setor_id
        return render_template('editar_setor.html', acao="Editar", setor=dados_para_template)
    return render_template('editar_setor.html', acao="Editar", setor=setor_original)

@app.route('/setores/excluir/<setor_id>', methods=['POST'])
@admin_required
def excluir_setor(setor_id):
    bens = dm.get_bens();
    if any(isinstance(bem, dict) and bem.get('setor_atual') == setor_id for bem in bens): flash('Este setor não pode ser excluído pois está associado a um ou mais bens. Transfira os bens primeiro.', 'danger'); return redirect(url_for('listar_setores'))
    mapa_users_excluir_setor = dm.get_users()
    for user_data_ex_setor in mapa_users_excluir_setor.values():
        if isinstance(user_data_ex_setor, dict) and user_data_ex_setor.get('role') != 'admin':
            setores_ids_user_ex = user_data_ex_setor.get('setores_ids', user_data_ex_setor.get('setor_id'))
            if isinstance(setores_ids_user_ex, list) and setor_id in setores_ids_user_ex: flash(f"Este setor não pode ser excluído pois está associado ao utilizador '{user_data_ex_setor.get('nome_completo', user_data_ex_setor.get('username'))}'. Remova a associação primeiro.", 'danger'); return redirect(url_for('listar_setores'))
            elif isinstance(setores_ids_user_ex, str) and setor_id == setores_ids_user_ex: flash(f"Este setor não pode ser excluído pois está associado ao utilizador '{user_data_ex_setor.get('nome_completo', user_data_ex_setor.get('username'))}'. Remova a associação primeiro.", 'danger'); return redirect(url_for('listar_setores'))
    setores = dm.get_setores(); setor_a_excluir = dm.find_setor_by_id(setor_id)
    if not setor_a_excluir: flash('Setor não encontrado.', 'warning'); app.logger.warning(f"Tentativa de excluir setor inexistente com ID: {setor_id} por '{session['user_id']}'."); return redirect(url_for('listar_setores'))
    nome_setor_excluido = setor_a_excluir.get('nome', f"ID {setor_id}"); setores_atualizados = [s for s in setores if isinstance(s, dict) and s.get('id') != setor_id]
    if dm.save_setores(setores_atualizados): flash(f'Setor "{nome_setor_excluido}" excluído com sucesso!', 'success'); app.logger.info(f"Setor ID '{setor_id}' ('{nome_setor_excluido}') excluído por '{session['user_id']}'.")
    else: flash('Erro ao salvar as alterações após excluir o setor. Tente novamente.', 'danger')
    return redirect(url_for('listar_setores'))

@app.route('/historico')
@login_required
def visualizar_historico():
    historico_dados_crus = dm.get_historico(); historico_para_template = []
    mapa_bens_hist = {bem_h['id']: bem_h.get('nome', 'Nome Indisponível') for bem_h in dm.get_bens() if isinstance(bem_h, dict)}
    mapa_users_hist = {uname_h: udata_h.get('nome_completo', uname_h) for uname_h, udata_h in dm.get_users().items() if isinstance(udata_h, dict)}
    for entrada_h_item in historico_dados_crus:
        if isinstance(entrada_h_item, dict):
            entrada_copia_h = entrada_h_item.copy(); entrada_copia_h['nome_bem'] = mapa_bens_hist.get(entrada_h_item.get('bem_id'), 'Bem Desconhecido/Excluído'); entrada_copia_h['nome_usuario'] = mapa_users_hist.get(entrada_h_item.get('usuario_responsavel'), entrada_h_item.get('usuario_responsavel', 'Utilizador Desconhecido'))
            data_hora_hist_str = entrada_copia_h.get('data_hora', '')
            try:
                dt_obj_hist = datetime.strptime(data_hora_hist_str, "%Y-%m-%d %H:%M:%S.%f") if '.' in data_hora_hist_str else datetime.strptime(data_hora_hist_str, "%Y-%m-%d %H:%M:%S")
                entrada_copia_h['data_hora_display'] = dt_obj_hist.strftime("%d/%m/%Y %H:%M:%S")
            except ValueError: entrada_copia_h['data_hora_display'] = data_hora_hist_str
            historico_para_template.append(entrada_copia_h)
        else: app.logger.warning(f"Item de histórico malformado (não é dict) encontrado: {entrada_h_item}")
    historico_ordenado_final = sorted(historico_para_template, key=lambda x: x.get('data_hora', ''), reverse=True)
    return render_template('historico.html', historico=historico_ordenado_final)

@app.route('/notificacoes')
@admin_required
def listar_notificacoes():
    notificacoes_todas_list = dm.get_notificacoes()
    notificacoes_validas = [n_item for n_item in notificacoes_todas_list if isinstance(n_item, dict)]
    notificacoes_ordenadas_list = sorted(notificacoes_validas, key=lambda x: x.get('data_criacao', ''), reverse=True)
    for n_disp in notificacoes_ordenadas_list:
        data_criacao_str = n_disp.get('data_criacao', '')
        try:
            dt_obj_notif = datetime.strptime(data_criacao_str, "%Y-%m-%d %H:%M:%S.%f") if '.' in data_criacao_str else datetime.strptime(data_criacao_str, "%Y-%m-%d %H:%M:%S")
            n_disp['data_criacao_display'] = dt_obj_notif.strftime("%d/%m/%Y %H:%M")
        except ValueError: n_disp['data_criacao_display'] = data_criacao_str
    return render_template('notificacoes.html', notificacoes=notificacoes_ordenadas_list[:100])

@app.route('/notificacoes/ler/<notificacao_id_ler>', methods=['POST'])
@admin_required
def marcar_notificacao_lida(notificacao_id_ler):
    lista_notificacoes_marcar = dm.get_notificacoes(); notificacao_foi_marcada = False
    for notificacao_item_marcar in lista_notificacoes_marcar:
        if isinstance(notificacao_item_marcar, dict) and notificacao_item_marcar.get('id') == notificacao_id_ler:
            notificacao_item_marcar['lida'] = True; notificacao_foi_marcada = True; break
    if notificacao_foi_marcada:
        if not dm.save_notificacoes(lista_notificacoes_marcar): flash("Erro ao salvar o estado da notificação.", "danger"); app.logger.error(f"Falha ao salvar notificações após marcar {notificacao_id_ler} como lida.")
    else: flash("Notificação não encontrada ou inválida para marcar como lida.", "warning"); app.logger.warning(f"Tentativa de marcar notificação inexistente/inválida {notificacao_id_ler} como lida.")
    return redirect(request.referrer or url_for('listar_notificacoes'))

@app.errorhandler(400)
def bad_request_error(e): app.logger.warning(f"Erro 400 - Requisição inválida: {request.url} (Erro original: {e})"); return render_template('400.html', error_code=400, error_message="Requisição Inválida", error_details=str(e)), 400
@app.errorhandler(403)
def forbidden_access_error(e): app.logger.warning(f"Erro 403 - Acesso Proibido: {request.url} (Erro original: {e})"); return render_template('403.html', error_code=403, error_message="Acesso Proibido", error_details=str(e)), 403
@app.errorhandler(404)
def page_not_found_error(e): app.logger.warning(f"Erro 404 - Página não encontrada: {request.url} (Erro original: {e})"); return render_template('404.html', error_code=404, error_message="Página Não Encontrada", error_details=str(e)), 404
@app.errorhandler(500)
def internal_server_error(e): app.logger.error(f"Erro 500 - Erro interno do servidor: {request.url} (Erro original: {e})", exc_info=True); return render_template('500.html', error_code=500, error_message="Erro Interno do Servidor", error_details="Ocorreu um erro inesperado."), 500

@app.context_processor
def inject_global_vars():
    user_id_sess = session.get('user_id'); usuario_logado_contexto = None; notificacoes_nao_lidas_contagem = 0
    if user_id_sess:
        dados_usuario_bd_contexto = dm.find_user_by_username(user_id_sess)
        if dados_usuario_bd_contexto:
            role_atual_contexto = dados_usuario_bd_contexto.get('role', 'user'); nome_completo_atual_contexto = dados_usuario_bd_contexto.get('nome_completo', user_id_sess)
            setores_ids_raw_contexto = dados_usuario_bd_contexto.get('setores_ids', dados_usuario_bd_contexto.get('setor_id')); lista_setores_ids_contexto = []; primeiro_setor_id_contexto = None
            if role_atual_contexto == 'admin': lista_setores_ids_contexto = []
            elif isinstance(setores_ids_raw_contexto, list): lista_setores_ids_contexto = [sid_ctx for sid_ctx in setores_ids_raw_contexto if sid_ctx]
            elif isinstance(setores_ids_raw_contexto, str) and setores_ids_raw_contexto: lista_setores_ids_contexto = [setores_ids_raw_contexto]
            if lista_setores_ids_contexto: primeiro_setor_id_contexto = lista_setores_ids_contexto[0]
            usuario_logado_contexto = { 'username': user_id_sess, 'role': role_atual_contexto, 'nome_completo': nome_completo_atual_contexto, 'is_authenticated': True , 'setor_id': primeiro_setor_id_contexto, 'setores_ids': lista_setores_ids_contexto }
            if role_atual_contexto == 'admin':
                notificacoes_bd_contexto = dm.get_notificacoes()
                for n_ctx in notificacoes_bd_contexto:
                    if isinstance(n_ctx, dict) and n_ctx.get('lida') is False: notificacoes_nao_lidas_contagem += 1
                    elif not isinstance(n_ctx, dict): app.logger.warning(f"Item não dicionário encontrado em notificações durante contagem no context_processor: {n_ctx}")
        else: usuario_logado_contexto = { 'is_authenticated': False, 'username': 'Anônimo (Sessão Inválida)', 'nome_completo': 'Visitante', 'role': None, 'setor_id': None, 'setores_ids': [] }; app.logger.warning(f"Usuário '{user_id_sess}' encontrado na sessão mas não na base de dados.")
    else: usuario_logado_contexto = { 'is_authenticated': False, 'username': 'Anônimo', 'nome_completo': 'Visitante', 'role': None, 'setor_id': None, 'setores_ids': [] }
    return dict(current_user=usuario_logado_contexto, num_notificacoes_nao_lidas=notificacoes_nao_lidas_contagem)

if __name__ == '__main__':
    if hasattr(dm, 'initialize_data_files'): dm.initialize_data_files()
    elif hasattr(dm, 'initialize_database'): dm.initialize_database()
    app.logger.info(f"Aplicação Patrimônio iniciando em modo {'DEBUG' if app.debug else 'PRODUÇÃO'}...")
    app.run(debug=True, host='0.0.0.0', port=5000)
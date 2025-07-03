from flask import Flask, request, send_file, render_template
import re
import io
import csv

app = Flask(__name__, static_folder='static', template_folder='templates')

# Parser pour app-avit-backend
def parser_app_avit_backend(lines):
    pattern = re.compile(
        r'(?P<timestamp>\d{2}:\d{2}:\d{2},\d{3})\s+'         # 00:02:00,887
        r'(?P<level>\S+)\s+'                                # INFO
        r'\[(?P<logger>[^\]]+)\]\s+'                      # ma.iam.avit...Authenticator
        r'\((?P<thread>[^)]+)\)\s+'                        # http-...:8443-45
        r'(?P<message>.*)'                                   # le reste du message
    )
    return [m.groupdict() for m in (pattern.match(line) for line in lines) if m]

# Parser pour app-sdr-serveur-java
def parser_app_sdr_serveur_java(lines):
    pattern = re.compile(
        r'(?P<timestamp>\d{2}:\d{2}:\d{2},\d{3}) INFO  '   # 00:08:10,188 INFO  
        r'\[(?P<logger>[^\]]+)\] '                          # ma.iam.pvr.utils.UserServletFilter
        r'\((?P<thread>[^)]+)\) '                            # http-...:443-5
        r'Requette login: (?P<login>\S+) ip: (?P<ip>\S+) url: (?P<url>\S+)'  # champs spécifiques
    )
    return [m.groupdict() for m in (pattern.match(line) for line in lines) if m]

# Parser pour debug (Chrome errors)
def parser_debug(lines):
    pattern = re.compile(
        r'\[(?P<timestamp>\d{4}/\d{6}\.\d{3})\:ERROR:(?P<component>[^\(]+)\(\d+\)\] (?P<message>.+)'
    )
    return [m.groupdict() for m in (pattern.match(line) for line in lines) if m]

# Parser pour nps-log-suivi
def parser_nps_log_suivi(lines):
    pattern = re.compile(
        r'(?P<timestamp>\d{2}:\d{2}:\d{2},\d{3}) INFO  '  # ex. 00:11:07,655 INFO  
        r'\[(?P<logger>[^\]]+)\] '                         # ma.iam.nps.job.quartz.SchedulerJob
        r'\((?P<thread>[^)]+)\) '                           # quartz thread
        r'(?P<message>.+)'                                   # le reste du message
    )
    return [m.groupdict() for m in (pattern.match(line) for line in lines) if m]

# Parser pour sdr-log-suivi
def parser_sdr_log_suivi(lines):
    pattern = re.compile(
        r'(?P<timestamp>\d{2}:\d{2}:\d{2},\d{3}) INFO  '  # ex. 00:01:41,548 INFO  
        r'\[(?P<logger>[^\]]+)\] '                         # service class
        r'\((?P<thread>[^)]+)\) '                           # scheduler_Worker-1
        r'(?P<message>.+)'                                   # le reste du message
    )
    return [m.groupdict() for m in (pattern.match(line) for line in lines) if m]

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/process', methods=['POST'])
def process():
    logtype = request.form.get('logtype')
    file = request.files.get('logfile')
    if not logtype or not file:
        return render_template('index.html', error='Sélectionnez un type et un fichier.')

    # Vérification du nom de fichier
    filename = file.filename or ''
    base = filename.rsplit('.', 1)[0]
    allowed = ['app-avit-backend', 'app-sdr-serveur-java', 'debug', 'nps-log-suivi', 'sdr-log-suivi']
    if base != logtype or filename.rsplit('.', 1)[-1] not in ['log', 'txt']:
        return render_template(
            'index.html',
            error=(f"Nom de fichier invalide. Le nom doit être '{logtype}.log' ou '{logtype}.txt'.")
        )

    # Lecture du contenu
    content = file.read().decode('utf-8', errors='ignore').splitlines()

    # Choix du parser
    if logtype == 'app-avit-backend':
        records = parser_app_avit_backend(content)
    elif logtype == 'app-sdr-serveur-java':
        records = parser_app_sdr_serveur_java(content)
    elif logtype == 'debug':
        records = parser_debug(content)
    elif logtype == 'nps-log-suivi':
        records = parser_nps_log_suivi(content)
    elif logtype == 'sdr-log-suivi':
        records = parser_sdr_log_suivi(content)
    else:
        records = []

    if not records:
        return render_template('index.html', error='Aucune ligne valide trouvée pour ce type de log.')

    # Génération du CSV en mémoire et preview
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=records[0].keys())
    writer.writeheader()
    writer.writerows(records)
    csv_data = output.getvalue().encode('utf-8')

    # Aperçu des 10 premières lignes
    preview = records[:10]
    columns = list(records[0].keys())

    # Génération de data URI pour le lien de téléchargement
    import base64
    b64 = base64.b64encode(csv_data).decode('ascii')
    csv_uri = f"data:text/csv;base64,{b64}"

    return render_template(
        'index.html',
        preview=preview,
        columns=columns,
        csv_uri=csv_uri
    )

if __name__ == '__main__':
    app.run(debug=True)

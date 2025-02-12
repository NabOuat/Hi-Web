from flask import (
    Flask, 
    render_template, 
    request, 
    redirect, 
    url_for, 
    session, 
    jsonify, 
    send_file,
    flash
)
from werkzeug.utils import secure_filename
from dotenv import load_dotenv
from supabase import create_client, Client
from functools import wraps
import logging
import sys
import os
import io
import easyocr
import numpy as np
from PIL import Image
import cv2
from pdf2image import convert_from_path
import re
import uuid
import random
import csv
import pandas as pd
from datetime import datetime, timezone, timedelta
import json
import mimetypes
import bcrypt
from math import ceil
import zipfile
from io import BytesIO, StringIO
import time
import mimetypes
import logging
import mimetypes
import numpy as np
from datetime import datetime
from pdf2image import convert_from_path
import easyocr
from functools import wraps
import time
import zipfile
from io import BytesIO
import bcrypt
from math import ceil
import uuid
import random
import csv
import pandas as pd
import tempfile
import traceback

# Configuration des chemins
base_dir = os.path.dirname(os.path.abspath(__file__))
app = Flask(__name__)

# Load environment variables
load_dotenv()

# Configuration de Poppler
poppler_path = os.getenv('POPPLER_PATH')
if not poppler_path:
    # Fallback sur le chemin par défaut si la variable d'environnement n'est pas définie
    poppler_path = os.path.join(base_dir, 'tools', 'popplerLibrary', 'bin')

if os.path.exists(poppler_path):
    os.environ['PATH'] = f"{poppler_path};{os.environ['PATH']}"
    logger = logging.getLogger(__name__)
    logger.info(f"Poppler ajouté au PATH: {poppler_path}")
else:
    logger = logging.getLogger(__name__)
    logger.warning(f"Poppler non trouvé dans: {poppler_path}")

# Configuration du logging
logging.basicConfig(level=logging.INFO)

app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'hiconvert_secret_key_2024')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max-limit

# Configuration des dossiers
app.config['UPLOAD_FOLDER'] = os.path.join(base_dir, 'uploads')
app.config['OUTPUT_FOLDER'] = os.path.join(base_dir, 'output')

# Créer les dossiers s'ils n'existent pas
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)

print(f"Dossier d'upload: {app.config['UPLOAD_FOLDER']}")
print(f"Dossier de sortie: {app.config['OUTPUT_FOLDER']}")

# Configuration de Supabase
url = os.getenv('SUPABASE_URL')
key = os.getenv('SUPABASE_KEY')
supabase: Client = create_client(url, key)

# Initialize Supabase client
try:
    if not url or not key:
        raise ValueError("Supabase URL or Key not found in environment variables")
    
    logger.info("Supabase client initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Supabase client: {str(e)}")
    raise

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Security middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    return response

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Resource not found'}), 404
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {str(error)}")
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Internal server error'}), 500
    return render_template('500.html'), 500

# Login decorator with improved session security
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Authentication required'}), 401
            return redirect(url_for('login'))
            
        # Vérifier la validité de la session
        if 'last_activity' not in session:
            session['last_activity'] = time.time()
        elif time.time() - session['last_activity'] > 3600:  # 1 heure
            session.clear()
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Session expired'}), 401
            return redirect(url_for('login'))
            
        session['last_activity'] = time.time()
        return f(*args, **kwargs)
    return decorated_function

# Role-based access decorator with improved validation
def role_required(roles):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not isinstance(roles, (list, tuple)):
                raise ValueError("Les rôles doivent être une liste ou un tuple")
                
            user_role = session.get('role')
            if not user_role or user_role not in roles:
                if request.path.startswith('/api/'):
                    return jsonify({'error': 'Accès non autorisé'}), 403
                return render_template('403.html'), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('dashboard_redirect'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Page de connexion"""
    if request.method == 'POST':
        try:
            email = request.form.get('email')
            password = request.form.get('password')
            
            # Vérifier les identifiants
            user = supabase.table('users').select('*').eq('email', email).execute()
            
            if user.data:
                user_data = user.data[0]
                
                # Mettre à jour la dernière connexion
                supabase.table('users')\
                    .update({
                        "last_login": datetime.now(timezone.utc).isoformat()
                    })\
                    .eq('id', user_data['id'])\
                    .execute()
                
                # Stocker l'ID de l'utilisateur dans la session
                session['user_id'] = user_data['id']
                session['role'] = user_data['role']
                session['email'] = user_data['email']
                
                # Enregistrer l'action de connexion
                log_user_action(user_data['id'], 'login')
                
                flash('Connexion réussie !', 'success')
                return redirect(url_for('dashboard_redirect'))
            else:
                flash('Email ou mot de passe incorrect.', 'error')
                
        except Exception as e:
            logger.error(f"Erreur de connexion : {str(e)}")
            flash('Une erreur est survenue lors de la connexion.', 'error')
            
    return render_template('login.html')

@app.route('/dashboard')
@login_required
def dashboard_redirect():
    """Redirection vers le tableau de bord approprié selon le rôle"""
    user_role = session.get('role')
    if user_role == 'superadmin':
        return redirect(url_for('superadmin_dashboard'))
    elif user_role == 'admin':
        return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('user_dashboard'))

@app.route('/superadmin/dashboard')
@login_required
@role_required(['superadmin'])
def superadmin_dashboard():
    try:
        # Get all users and directories
        users = supabase.table('users').select("*").execute()
        directories = supabase.table('directories').select("*").execute()
        return render_template('superadmin_dashboard.html', 
                             users=users.data,
                             directories=directories.data)
    except Exception as e:
        logger.error(f"Error loading superadmin dashboard: {str(e)}")
        flash('Erreur lors du chargement du tableau de bord.', 'error')
        return redirect(url_for('dashboard_redirect'))

@app.route('/admin/dashboard')
@login_required
@role_required(['admin'])
def admin_dashboard():
    """Page du tableau de bord administrateur"""
    try:
        # Récupérer les statistiques globales
        stats = get_admin_stats()
        
        # Récupérer les fichiers récents
        files = supabase.table('files')\
            .select('id, name, status, created_at, processed_at, points, user_id, directory_id')\
            .order('created_at', desc=True)\
            .limit(10)\
            .execute()
            
        # Formater les fichiers pour l'affichage
        recent_files = []
        if hasattr(files, 'data'):
            for file in files.data:
                created_at = datetime.fromisoformat(file['created_at'].replace('Z', '+00:00'))
                processed_at = None
                if file.get('processed_at'):
                    processed_at = datetime.fromisoformat(file['processed_at'].replace('Z', '+00:00'))
                
                recent_files.append({
                    'id': file['id'],
                    'filename': file['name'],
                    'created_at': created_at.strftime('%d/%m/%Y %H:%M'),
                    'processed_at': processed_at.strftime('%d/%m/%Y %H:%M') if processed_at else None,
                    'points': file.get('points', 0),
                    'status': file.get('status', 'processing'),
                    'user_id': file['user_id'],
                    'directory_id': file['directory_id']
                })
        
        # Récupérer les activités récentes
        activities = get_admin_activity_stats()
        
        return render_template('admin_dashboard.html',
                             stats=stats,
                             recent_files=recent_files,
                             activities=activities)
                             
    except Exception as e:
        logger.error(f"Error loading admin dashboard: {str(e)}")
        flash('Erreur lors du chargement du tableau de bord.', 'error')
@app.route('/user/dashboard')
@login_required
def user_dashboard():
    """Page du tableau de bord utilisateur"""
    try:
        user_id = session.get('user_id')
        print(f"Récupération du tableau de bord pour l'utilisateur {user_id}")
        
        # Récupérer les fichiers de l'utilisateur
        try:
            files = supabase.table('files')\
                .select('id, name, status, created_at, processed_at, points')\
                .eq('user_id', user_id)\
                .order('created_at', desc=True)\
                .execute()
                
            print("Fichiers récupérés:", files.data if hasattr(files, 'data') else [])
            
        except Exception as e:
            print(f"Erreur lors de la récupération des fichiers: {e}")
            files = {'data': []}
        
        # Calculer les statistiques
        total_files = len(files.data) if hasattr(files, 'data') else 0
        processed_files = len([f for f in files.data if f.get('status') == 'success']) if hasattr(files, 'data') else 0
        error_files = len([f for f in files.data if f.get('status') == 'error']) if hasattr(files, 'data') else 0
        pending_files = total_files - processed_files - error_files
        
        stats = {
            'total_files': total_files,
            'processed_files': processed_files,
            'error_files': error_files,
            'pending_files': pending_files,
            'success_rate': round((processed_files / total_files * 100) if total_files > 0 else 0, 1)
        }
        
        # Formater les fichiers pour l'affichage
        recent_files = []
        if hasattr(files, 'data'):
            for file in files.data:
                created_at = datetime.fromisoformat(file['created_at'].replace('Z', '+00:00'))
                processed_at = None
                if file.get('processed_at'):
                    processed_at = datetime.fromisoformat(file['processed_at'].replace('Z', '+00:00'))
                
                recent_files.append({
                    'id': file['id'],
                    'filename': file['name'],
                    'created_at': created_at.strftime('%d/%m/%Y %H:%M'),
                    'processed_at': processed_at.strftime('%d/%m/%Y %H:%M') if processed_at else None,
                    'points': file.get('points', 0),
                    'status': file.get('status', 'processing')
                })
        
        # Récupérer l'historique des traitements
        try:
            history = supabase.table('files')\
                .select('id, name, status, created_at, processed_at, points')\
                .eq('user_id', user_id)\
                .not_.is_('processed_at', 'null')\
                .order('processed_at', desc=True)\
                .limit(10)\
                .execute()
                
            processing_history = []
            if hasattr(history, 'data'):
                for file in history.data:
                    created_at = datetime.fromisoformat(file['created_at'].replace('Z', '+00:00'))
                    processed_at = datetime.fromisoformat(file['processed_at'].replace('Z', '+00:00'))
                    processing_time = processed_at - created_at
                    
                    processing_history.append({
                        'id': file['id'],
                        'filename': file['name'],
                        'created_at': created_at.strftime('%d/%m/%Y %H:%M'),
                        'processed_at': processed_at.strftime('%d/%m/%Y %H:%M'),
                        'processing_time': str(processing_time).split('.')[0],  # Format: HH:MM:SS
                        'points': file.get('points', 0),
                        'status': file.get('status', 'success')
                    })
        except Exception as e:
            print(f"Erreur lors de la récupération de l'historique: {e}")
            processing_history = []
        
        return render_template('user_dashboard.html', 
                             recent_files=recent_files,
                             processing_history=processing_history,
                             stats=stats)
        
    except Exception as e:
        print(f"Erreur dans le dashboard: {e}")
        return redirect(url_for('login'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Vous avez été déconnecté.', 'info')
    return redirect(url_for('login'))

@app.route('/api/process', methods=['POST'])
@login_required
def process():
    """Traite un fichier PDF"""
    temp_path = None
    file_id = None
    try:
        logger = logging.getLogger(__name__)
        logger.info("Début du traitement")
        logger.info(f"Headers: {request.headers}")
        logger.info(f"Form data: {request.form}")
        logger.info(f"Files: {request.files}")
        
        if 'file' not in request.files:
            return jsonify({
                'status': 'error',
                'error': 'Aucun fichier reçu'
            }), 400
            
        file = request.files['file']
        if not file or file.filename == '':
            return jsonify({
                'status': 'error',
                'error': 'Nom de fichier invalide'
            }), 400
            
        folder_name = request.form.get('folderName')
        if not folder_name:
            return jsonify({
                'status': 'error',
                'error': 'Nom de dossier manquant'
            }), 400
            
        logger.info(f"Traitement du fichier {file.filename} du dossier {folder_name}")
        
        # Créer un ID unique pour ce fichier
        file_id = str(uuid.uuid4())
        logger.info(f"ID généré: {file_id}")
        
        # Créer un dossier spécifique pour ce fichier
        output_dir = os.path.join(app.config['OUTPUT_FOLDER'], file_id)
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Dossier de sortie créé: {output_dir}")
        
        # Créer un fichier temporaire avec une extension .pdf
        temp_path = os.path.join(output_dir, "input.pdf")
        logger.info(f"Fichier temporaire créé: {temp_path}")
        
        try:
            # Lire le contenu du fichier pour obtenir sa taille
            file_content = file.read()
            file_size = len(file_content)
            
            # Upload le fichier PDF vers Supabase avec retry
            max_retries = 3
            retry_count = 0
            while retry_count < max_retries:
                try:
                    logger.info("Upload du fichier PDF vers Supabase...")
                    upload_pdf_to_supabase(file_id, file_content, session.get('user_id'), folder_name)
                    logger.info("Upload du fichier PDF terminé")
                    break
                except Exception as e:
                    retry_count += 1
                    if retry_count == max_retries:
                        raise
                    logger.warning(f"Tentative {retry_count} échouée: {str(e)}")
                    time.sleep(1)  # Attendre 1 seconde avant de réessayer
            
            # Réinitialiser le curseur du fichier pour pouvoir le sauvegarder
            file.seek(0)
            file.save(temp_path)
            logger.info(f"Fichier sauvegardé: {temp_path}")
            
            # Créer l'entrée dans la base de données
            user_id = session.get('user_id')
            directory_id = request.form.get('directoryId')
            
            file_data = {
                'id': file_id,
                'name': file.filename,
                'status': 'processing',
                'user_id': user_id,
                'directory_id': directory_id,
                'filename': f"{file_id}.csv",
                'created_at': datetime.now(timezone.utc).isoformat(),
                'updated_at': datetime.now(timezone.utc).isoformat(),
                'original_path': temp_path,
                'file_size': file_size,
                'mime_type': file.content_type or 'application/pdf'
            }
            
            logger.info("Insertion dans la base de données: %s", file_data)
            response = supabase.table('files').insert(file_data).execute()
            logger.info("Réponse de la base de données: %s", response.data)
            
            # Traiter le PDF avec timeout
            csv_path, result = process_pdf(temp_path, file_id, output_dir)
            
            if csv_path is None:
                error_data = {
                    'status': 'error',
                    'processed_at': datetime.now(timezone.utc).isoformat()
                }
                logger.error("Erreur de traitement PDF: %s", result)
                supabase.table('files')\
                    .update(error_data)\
                    .eq('id', file_id)\
                    .execute()
                    
                return jsonify({
                    'status': 'error',
                    'error': result
                }), 500
            
            # Mettre à jour le statut en succès
            success_data = {
                'status': 'success',
                'points': len(result),
                'processed_at': datetime.now(timezone.utc).isoformat()
            }
            logger.info("Mise à jour du statut en succès: %s", success_data)
            supabase.table('files')\
                .update(success_data)\
                .eq('id', file_id)\
                .execute()
            
            return jsonify({
                'message': 'Traitement terminé avec succès',
                'points': len(result),
                'file_id': file_id,
                'status': 'success'
            })
            
        except Exception as e:
            logger.error(f"Erreur lors du traitement: {str(e)}")
            logger.error(traceback.format_exc())
            
            if file_id:
                error_data = {
                    'status': 'error',
                    'error_message': str(e),
                    'processed_at': datetime.now(timezone.utc).isoformat()
                }
                try:
                    supabase.table('files')\
                        .update(error_data)\
                        .eq('id', file_id)\
                        .execute()
                except Exception as db_error:
                    logger.error(f"Erreur lors de la mise à jour du statut: {str(db_error)}")
            
            return jsonify({
                'status': 'error',
                'error': str(e)
            }), 500
            
    except Exception as e:
        logger.error(f"Erreur globale: {str(e)}")
        logger.error(traceback.format_exc())
        
        if temp_path and os.path.exists(temp_path):
            try:
                os.remove(temp_path)
                logger.info(f"Fichier temporaire supprimé: {temp_path}")
            except Exception as cleanup_error:
                logger.error(f"Erreur lors de la suppression du fichier temporaire: {str(cleanup_error)}")
        
        return jsonify({
            'status': 'error',
            'error': str(e)
        }), 500

@app.route('/api/files/<file_id>/download', methods=['GET'])
@login_required
def download_file(file_id):
    """Télécharge un fichier depuis Supabase"""
    try:
        # Récupérer les informations du fichier depuis la base de données
        user_id = session.get('user_id')
        logger.info(f"User ID: {user_id}")
        
        response = supabase.table('files')\
            .select('*')\
            .eq('id', file_id)\
            .eq('user_id', user_id)\
            .execute()
            
        logger.info(f"Réponse de la base de données: {response.data}")
            
        if not response.data:
            logger.error(f"Fichier {file_id} non trouvé dans la base de données")
            return jsonify({'error': 'Fichier non trouvé'}), 404
            
        file_info = response.data[0]
        logger.info(f"Informations du fichier: {file_info}")
        
        # Vérifier que le fichier a été traité avec succès
        if file_info.get('status') != 'success':
            logger.error(f"Le fichier {file_id} n'a pas été traité avec succès. Status: {file_info.get('status')}")
            return jsonify({'error': 'Le fichier n\'a pas été traité avec succès'}), 400
            
        # Récupérer le type de fichier demandé (pdf ou csv)
        file_type = request.args.get('type', 'csv')
        logger.info(f"Type de fichier demandé: {file_type}")
        
        try:
            if file_type == 'csv':
                bucket_name = 'csv'
                file_path = f"{user_id}/coordinates/{file_id}/coordinates_{file_id}.csv"
                mime_type = 'text/csv'
                download_name = f"coordinates_{file_id}.csv"
            else:
                bucket_name = 'files'
                file_path = f"{user_id}/uploads/{file_id}.pdf"
                mime_type = 'application/pdf'
                download_name = file_info['name']
                
            logger.info(f"Tentative de téléchargement depuis le bucket {bucket_name}: {file_path}")
            file_data = supabase.storage.from_(bucket_name).download(file_path)
            
            return send_file(
                io.BytesIO(file_data),
                mimetype=mime_type,
                as_attachment=True,
                download_name=download_name
            )
            
        except Exception as e:
            logger.error(f"Erreur lors du téléchargement depuis Supabase: {str(e)}")
            
            # Vérifier si le fichier existe dans le bucket
            try:
                files = supabase.storage.from_(bucket_name).list()
                file_exists = any(f['name'] == file_path for f in files)
                if not file_exists:
                    raise Exception(f"Le fichier {file_path} n'existe pas dans le bucket {bucket_name}")
            except Exception as e:
                logger.error(f"Erreur lors de la vérification du fichier dans le bucket: {str(e)}")
                return jsonify({"error": f"Fichier non trouvé dans le bucket {bucket_name}"}), 404
                
    except Exception as e:
        logger.error(f"Erreur lors du téléchargement: {str(e)}")
        return jsonify({"error": str(e)}), 500

@app.route('/api/files/download-all', methods=['GET'])
@login_required
def download_all_coordinates():
    """Télécharge tous les fichiers CSV dans un fichier ZIP"""
    try:
        # Récupérer tous les fichiers de l'utilisateur
        response = supabase.table('files')\
            .select('*')\
            .eq('uploaded_by', session.get('user_id'))\
            .execute()
            
        if not response.data:
            return jsonify({'error': 'Aucun fichier trouvé'}), 404
            
        # Créer un fichier ZIP en mémoire
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zf:
            # Pour chaque fichier, ajouter son CSV au ZIP s'il existe
            for file_info in response.data:
                try:
                    csv_data = download_csv_from_supabase(
                        file_info['id'], 
                        file_info['uploaded_by'], 
                        file_info['directory_id']
                    )
                    zf.writestr(
                        f"{file_info['filename'].replace('.pdf', '.csv')}", 
                        csv_data
                    )
                except Exception as e:
                    print(f"Erreur lors de l'ajout du fichier {file_info['id']} au ZIP: {str(e)}")
                    continue
                    
        memory_file.seek(0)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name='coordinates.zip'
        )
        
    except Exception as e:
        print(f"Erreur lors de la création du ZIP: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/download-all/<file_id>', methods=['GET'])
@login_required
def download_all_files(file_id):
    """Télécharger les fichiers CSV et PDF dans un ZIP"""
    try:
        print(f"Tentative de téléchargement groupé pour le fichier {file_id}")
        
        # Vérifier l'accès au fichier
        if not check_file_access(file_id):
            print(f"Accès non autorisé pour le fichier {file_id}")
            return jsonify({'error': 'Accès non autorisé'}), 403
            
        # Récupérer les informations du fichier
        file_info = supabase.table('files')\
            .select('*')\
            .eq('id', file_id)\
            .single()\
            .execute()
            
        if not file_info.data:
            print(f"Fichier {file_id} non trouvé dans la base de données")
            return jsonify({'error': 'Fichier non trouvé'}), 404
            
        print(f"Informations du fichier: {file_info.data}")
        
        # Créer un fichier ZIP en mémoire
        memory_file = BytesIO()
        with zipfile.ZipFile(memory_file, 'w') as zf:
            try:
                user_id = file_info.data.get('user_id') or file_info.data.get('uploaded_by')
                directory_id = file_info.data.get('directory_id')
                
                print(f"Téléchargement des fichiers pour user_id: {user_id}, directory_id: {directory_id}")
                
                # Ajouter le PDF
                pdf_data = download_pdf_from_supabase(file_id, user_id, directory_id)
                zf.writestr(file_info.data['name'], pdf_data)
                print(f"PDF ajouté au ZIP, taille: {len(pdf_data)} bytes")
                
                # Ajouter le CSV
                csv_data = download_csv_from_supabase(file_id, user_id, directory_id)
                csv_name = file_info.data['name'].replace('.pdf', '.csv')
                zf.writestr(csv_name, csv_data)
                print(f"CSV ajouté au ZIP, taille: {len(csv_data)} bytes")
                
            except Exception as e:
                print(f"Erreur lors de l'ajout des fichiers au ZIP: {str(e)}")
                return jsonify({'error': 'Fichier non trouvé dans le bucket'}), 404
                
        memory_file.seek(0)
        zip_name = file_info.data['name'].replace('.pdf', '_all.zip')
        print(f"Envoi du ZIP: {zip_name}")
        
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=zip_name
        )
        
    except Exception as e:
        print(f"Erreur lors de la création du ZIP: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Routes pour la navigation
@app.route('/mes-fichiers')
@login_required
def mes_fichiers():
    """Page des fichiers de l'utilisateur"""
    return render_template('mes_fichiers.html')

@app.route('/historique')
@login_required
def historique():
    """Page d'historique des traitements"""
    return render_template('historique.html')

@app.route('/mon-profil')
@login_required
def mon_profil():
    """Page de profil de l'utilisateur"""
    try:
        user_id = session.get('user_id')
        user_data = supabase.table('users')\
            .select('id, email, username, role, preferences')\
            .eq('id', user_id)\
            .single()\
            .execute()

        if not hasattr(user_data, 'data'):
            flash('Erreur lors du chargement du profil.', 'error')
            return redirect(url_for('dashboard_redirect'))

        user = user_data.data
        return render_template('mon_profil.html', user=user)

    except Exception as e:
        logger.error(f"Erreur lors du chargement du profil: {str(e)}")
        flash('Erreur lors du chargement du profil.', 'error')
        return redirect(url_for('dashboard_redirect'))

@app.route('/api/profile', methods=['GET', 'PUT'])
@login_required
def profile():
    """Gestion du profil utilisateur"""
    if request.method == 'GET':
        try:
            user_id = session.get('user_id')
            user_data = supabase.table('users')\
                .select('id, email, username, role, created_at, last_login')\
                .eq('id', user_id)\
                .single()\
                .execute()
                
            if not user_data.data:
                return jsonify({'error': 'Utilisateur non trouvé'}), 404
                
            # Récupérer les statistiques des fichiers
            files = supabase.table('files')\
                .select('id, status')\
                .eq('user_id', user_id)\
                .execute()
                
            total_files = len(files.data)
            successful_files = len([f for f in files.data if f['status'] == 'success'])
            
            stats = {
                'total_files': total_files,
                'successful_files': successful_files,
                'success_rate': round((successful_files / total_files * 100) if total_files > 0 else 0, 1)
            }
            
            return jsonify({
                'user': user_data.data,
                'stats': stats
            })
            
        except Exception as e:
            logger.error(f"Erreur lors de la récupération du profil: {str(e)}")
            return jsonify({'error': 'Erreur lors de la récupération du profil'}), 500
            
    elif request.method == 'PUT':
        try:
            user_id = session.get('user_id')
            data = request.get_json()

            # Vérifier les données requises
            if 'username' not in data:
                return jsonify({'error': 'Le nom d\'utilisateur est requis'}), 400

            # Mettre à jour le profil
            response = supabase.table('users')\
                .update({
                    'username': data['username'],
                    'updated_at': datetime.utcnow().isoformat()
                })\
                .eq('id', user_id)\
                .execute()

            if not hasattr(response, 'data'):
                return jsonify({'error': 'Erreur lors de la mise à jour du profil'}), 500

            return jsonify({'message': 'Profil mis à jour avec succès'})

        except Exception as e:
            logger.error(f"Erreur lors de la mise à jour du profil: {str(e)}")
            return jsonify({'error': str(e)}), 500

@app.route('/api/stats/global', methods=['GET'])
@login_required
@role_required(['admin', 'superadmin'])
def get_global_stats():
    """Récupérer les statistiques globales du système"""
    try:
        # Récupérer les statistiques des utilisateurs et fichiers
        users = supabase.table('users').select("*").execute()
        files = supabase.table('files').select("*").execute()
        
        # Statistiques des utilisateurs
        total_users = len(users.data) if users.data else 0
        user_roles = {}
        for user in users.data or []:
            role = user.get('role', 'user')
            user_roles[role] = user_roles.get(role, 0) + 1
            
        # Statistiques des fichiers
        total_files = len(files.data) if files.data else 0
        file_stats = {
            'total': total_files,
            'processed': 0,
            'pending': 0,
            'error': 0
        }
        
        total_points = 0
        for file in files.data or []:
            status = file.get('status', 'pending')
            file_stats[status] = file_stats.get(status, 0) + 1
            total_points += file.get('points', 0)
            
        # Calculer les taux de succès
        success_rate = (file_stats.get('processed', 0) / total_files * 100) if total_files > 0 else 0
        
        stats = {
            'users': {
                'total': total_users,
                'by_role': user_roles
            },
            'files': {
                'total': total_files,
                'by_status': file_stats,
                'success_rate': success_rate,
                'total_points': total_points
            },
            'timestamp': datetime.now().isoformat()
        }
        
        return jsonify(stats), 200
        
    except Exception as e:
        print(f"Erreur lors de la récupération des statistiques globales: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files', methods=['GET'])
@login_required
def get_files():
    try:
        # Récupérer les paramètres de pagination
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 10, type=int)
        
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Construire la requête de base
        query = supabase.table('files').select('''
            id,
            name,
            status,
            points,
            created_at,
            directory_id,
            directories (
                id,
                name
            )
        ''')
        
        # Filtrer selon les droits d'accès
        if user_role != 'superadmin':
            # Récupérer les répertoires accessibles
            accessible_dirs = supabase.table('user_access')\
                .select('directory_id')\
                .eq('user_id', user_id)\
                .execute()
                
            if not accessible_dirs.data:
                return jsonify({
                    'files': [],
                    'total': 0,
                    'page': page,
                    'per_page': per_page,
                    'total_pages': 0
                }), 200
                
            dir_ids = [d['directory_id'] for d in accessible_dirs.data]
            query = query.in_('directory_id', dir_ids)
        
        # Exécuter la requête
        files = query.execute()
        
        if not files.data:
            return jsonify({
                'files': [],
                'total': 0,
                'page': page,
                'per_page': per_page,
                'total_pages': 0
            }), 200
        
        # Formater les fichiers
        formatted_files = []
        for file in files.data:
            try:
                formatted_file = {
                    'id': file['id'],
                    'name': file['name'],
                    'status': file['status'],
                    'points': file.get('points', 0),
                    'created_at': file['created_at'],
                    'directory_name': file.get('directories', {}).get('name', 'N/A'),
                    'directory_id': file['directory_id']
                }
                formatted_files.append(formatted_file)
            except Exception as e:
                logger.error(f"Erreur lors du formatage du fichier {file.get('id')}: {str(e)}")
                continue
        
        # Calculer la pagination
        total = len(formatted_files)
        total_pages = ceil(total / per_page)
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        paginated_files = formatted_files[start_idx:end_idx]
        
        return jsonify({
            'files': paginated_files,
            'total': total,
            'page': page,
            'per_page': per_page,
            'total_pages': total_pages
        }), 200
        
    except Exception as e:
        error_msg = f"Erreur lors de la récupération des fichiers: {str(e)}"
        logger.error(error_msg)
        return jsonify({'error': error_msg}), 500

@app.route('/api/files/<file_id>/download', methods=['GET'])
@login_required
def download_processed_file(file_id):
    """Télécharger le résultat d'un fichier traité"""
    try:
        print(f"Tentative de téléchargement du fichier {file_id}")
        
        # Récupérer les informations du fichier depuis la base de données
        user_id = session.get('user_id')
        print(f"User ID: {user_id}")
        
        response = supabase.table('files')\
            .select('*')\
            .eq('id', file_id)\
            .eq('user_id', user_id)\
            .execute()
            
        print(f"Réponse de la base de données: {response.data}")
            
        if not response.data:
            print(f"Fichier {file_id} non trouvé dans la base de données")
            return jsonify({'error': 'Fichier non trouvé'}), 404
            
        file_info = response.data[0]
        print(f"Informations du fichier: {file_info}")
        
        # Vérifier que le fichier a été traité avec succès
        if file_info.get('status') != 'success':
            print(f"Le fichier {file_id} n'a pas été traité avec succès. Status: {file_info.get('status')}")
            return jsonify({'error': 'Le fichier n\'a pas été traité avec succès'}), 400
            
        # Construire le chemin du fichier CSV
        output_dir = file_info.get('output_dir')
        if not output_dir:
            print("Dossier de sortie manquant dans la base de données")
            return jsonify({'error': 'Informations du fichier incomplètes'}), 500
            
        csv_path = os.path.join(output_dir, f"{file_id}.csv")
        print(f"Chemin du fichier CSV: {csv_path}")
        
        if not os.path.exists(csv_path):
            print(f"Fichier CSV non trouvé: {csv_path}")
            # Lister les fichiers dans le dossier
            if os.path.exists(output_dir):
                files = os.listdir(output_dir)
                print(f"Fichiers dans le dossier {output_dir}: {files}")
            return jsonify({'error': 'Fichier CSV non trouvé'}), 404
            
        try:
            print(f"Envoi du fichier {csv_path}")
            return send_file(
                csv_path,
                mimetype='text/csv',
                as_attachment=True,
                download_name=f"coordinates_{file_id}.csv"
            )
            
        except Exception as e:
            print(f"Erreur lors de l'envoi du fichier: {str(e)}")
            return jsonify({'error': 'Erreur lors de l\'envoi du fichier'}), 500
            
    except Exception as e:
        print(f"Erreur lors du téléchargement: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users', methods=['GET'])
@login_required
@role_required(['admin', 'superadmin'])
def get_users():
    """Récupérer la liste des utilisateurs"""
    try:
        current_user_role = session.get('role')
        current_user_id = session.get('user_id')

        # Récupérer d'abord les accès utilisateur
        try:
            if current_user_role == 'admin':
                print("Utilisateur est admin, récupération de son accès")
                admin_access = supabase.table('user_access').select('*').eq('user_id', current_user_id).execute()
                print(f"Accès admin: {admin_access.data}")
                
                if not admin_access.data:
                    print("Aucun accès trouvé pour l'admin")
                    return jsonify({'users': [], 'message': 'Admin sans accès configuré'})
                
                directory_id = admin_access.data[0].get('directory_id')
                if not directory_id:
                    print("Admin sans directory_id")
                    return jsonify({'users': [], 'message': 'Admin sans répertoire associé'})
                
                # Récupérer tous les user_access pour ce répertoire
                user_access = supabase.table('user_access')\
                    .select("users(*)")\
                    .eq('directory_id', directory_id)\
                    .execute()
            else:
                print("Utilisateur est superadmin, récupération de tous les accès")
                user_access = supabase.table('user_access')\
                    .select("users(*)")\
                    .execute()
            
            print(f"Accès utilisateurs récupérés: {user_access.data}")
            
            if not user_access.data:
                return jsonify({'users': []})
            
            # Extraire les user_ids
            user_ids = [access['user_id'] for access in user_access.data]
            
            # Récupérer les informations des utilisateurs
            users = supabase.table('users').select('*').in_('id', user_ids).execute()
            print(f"Informations utilisateurs récupérées: {users.data}")
            
            if not users.data:
                return jsonify({'users': []})
            
            # Créer un mapping des accès par user_id
            access_map = {access['user_id']: access for access in user_access.data}
            
            # Récupérer les noms des répertoires
            directory_ids = set(access['directory_id'] for access in user_access.data if access.get('directory_id'))
            directories = {}
            if directory_ids:
                print(f"Récupération des répertoires pour les IDs: {directory_ids}")
                dirs = supabase.table('directories').select('*').in_('id', list(directory_ids)).execute()
                print(f"Répertoires récupérés: {dirs.data}")
                if dirs.data:
                    directories = {d['id']: d['name'] for d in dirs.data}
            
            # Combiner les informations
            result = []
            for user in users.data:
                user_data = dict(user)
                user_data.pop('password_hash', None)  # Ne pas envoyer le hash du mot de passe
                
                # Ajouter les informations d'accès
                access_info = access_map.get(user['id'], {})
                user_data['directory_id'] = access_info.get('directory_id')
                user_data['directory_name'] = directories.get(access_info.get('directory_id'), '-')
                user_data['role'] = access_info.get('role_in_dir', 'user')
                
                result.append(user_data)
            
            print("Fin de get_users avec succès")
            return jsonify({'users': result})
            
        except Exception as e:
            print(f"Erreur lors de la récupération des données: {str(e)}")
            return jsonify({'error': 'Erreur lors de la récupération des données utilisateurs'}), 500
            
    except Exception as e:
        print(f"Erreur générale dans get_users: {str(e)}")
        return jsonify({'error': 'Erreur lors de la récupération des utilisateurs'}), 500

@app.route('/api/users/<user_id>', methods=['GET'])
@login_required
@role_required(['admin', 'superadmin'])
def get_user(user_id):
    """Récupérer les détails d'un utilisateur"""
    try:
        current_user_role = session.get('role')
        current_user_id = session.get('user_id')

        # Récupérer l'utilisateur
        user = supabase.table('users').select('*').eq('id', user_id).execute()
        if not user.data:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404

        user_data = user.data[0]

        # Vérifier les permissions
        if current_user_role == 'admin':
            admin_user = supabase.table('users').select('directory_id').eq('id', current_user_id).execute()
            if not admin_user.data or admin_user.data[0].get('directory_id') != user_data.get('directory_id'):
                return jsonify({'error': 'Permission non accordée'}), 403

        # Récupérer le nom du répertoire si nécessaire
        if user_data.get('directory_id'):
            directory = supabase.table('directories').select('name').eq('id', user_data['directory_id']).execute()
            if directory.data:
                user_data['directory_name'] = directory.data[0]['name']

        # Ne pas envoyer le hash du mot de passe
        user_data.pop('password_hash', None)

        return jsonify({'user': user_data})

    except Exception as e:
        print(f"Erreur lors de la récupération de l'utilisateur: {str(e)}")
        return jsonify({'error': 'Erreur lors de la récupération de l\'utilisateur'}), 500

@app.route('/api/users', methods=['POST'])
@login_required
@role_required(['admin', 'superadmin'])
def create_user():
    """Créer un nouvel utilisateur"""
    try:
        creator_id = session.get('user_id')
        if not creator_id:
            return jsonify({'error': 'Non autorisé'}), 401

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Données manquantes'}), 400

        # Vérifier les données requises
        required_fields = ['email', 'password', 'name', 'role']
        for field in required_fields:
            if not data.get(field):
                return jsonify({'error': f'Le champ {field} est requis'}), 400
            
        email = data['email'].lower().strip()
        password = data['password']
        name = data['name'].strip()
        role = data['role'].lower()

        # Vérifier le format de l'email
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            return jsonify({'error': 'Format d\'email invalide'}), 400

        # Vérifier la longueur du mot de passe
        if len(password) < 8:
            return jsonify({'error': 'Le mot de passe doit contenir au moins 8 caractères'}), 400

        # Vérifier le rôle
        allowed_roles = ['user', 'admin']
        if role not in allowed_roles:
            return jsonify({'error': 'Rôle invalide'}), 400

        try:
            # Vérifier si l'email existe déjà
            existing_user = supabase.table('users')\
                .select('id')\
                .eq('email', email)\
                .execute()

            if existing_user.data:
                return jsonify({'error': 'Cet email est déjà utilisé'}), 409

            # Hasher le mot de passe
            password_hash = bcrypt.hashpw(
                password.encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')

            # Créer l'utilisateur
            new_user = supabase.table('users')\
                .insert({
                    'email': email,
                    'password_hash': password_hash,
                    'name': name,
                    'role': role,
                    'created_by': creator_id,
                    'created_at': datetime.utcnow().isoformat(),
                    'updated_at': datetime.utcnow().isoformat(),
                    'preferences': {},
                    'is_active': True
                })\
                .execute()

            if not new_user.data:
                return jsonify({'error': 'Erreur lors de la création de l\'utilisateur'}), 500

            user_id = new_user.data[0]['id']

            # Enregistrer l'action
            log_user_action(
                creator_id,
                'create_user',
                {'user_id': user_id, 'email': email, 'role': role}
            )

            # Retourner l'utilisateur créé sans le mot de passe
            created_user = new_user.data[0]
            created_user.pop('password_hash', None)

            return jsonify({
                'message': 'Utilisateur créé avec succès',
                'user': created_user
            }), 201

        except Exception as e:
            logger.error(f"Erreur lors de la création dans Supabase: {str(e)}")
            return jsonify({'error': 'Erreur lors de la création de l\'utilisateur'}), 500

    except Exception as e:
        logger.error(f"Erreur lors de la création de l'utilisateur: {str(e)}")
        return jsonify({'error': 'Erreur lors de la création de l\'utilisateur'}), 500

@app.route('/api/users/<user_id>', methods=['PUT'])
@login_required
@role_required(['admin', 'superadmin'])
def update_user(user_id):
    """Mettre à jour un utilisateur"""
    try:
        data = request.json
        current_user_role = session.get('role')
        current_user_id = session.get('user_id')

        # Vérifier si l'utilisateur existe
        user = supabase.table('users').select('*').eq('id', user_id).execute()
        if not user.data:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404

        existing_user = user.data[0]

        # Vérifier les permissions
        if current_user_role == 'admin':
            # Vérifier si l'utilisateur est admin du répertoire
            admin_user = supabase.table('users').select('directory_id').eq('id', current_user_id).execute()
            if not admin_user.data or admin_user.data[0].get('directory_id') != existing_user.get('directory_id'):
                return jsonify({'error': 'Permission non accordée'}), 403

            # L'admin ne peut pas modifier les superadmin ou autres admin
            if existing_user['role'] in ['superadmin', 'admin']:
                return jsonify({'error': 'Permission non accordée'}), 403

            # L'admin ne peut pas changer le rôle des utilisateurs
            if 'role' in data:
                return jsonify({'error': 'Permission non accordée pour modifier le rôle'}), 403

        # Préparer les données de mise à jour
        update_data = {
            'updated_at': datetime.utcnow().isoformat()
        }

        # Mettre à jour l'email si fourni
        if 'email' in data and data['email'] != existing_user['email']:
            email_check = supabase.table('users').select('*').eq('email', data['email']).execute()
            if email_check.data:
                return jsonify({'error': 'Cet email est déjà utilisé'}), 400
            update_data['email'] = data['email']

        # Mettre à jour le mot de passe si fourni
        if 'password' in data and data['password']:
            update_data['password_hash'] = bcrypt.hashpw(
                data['password'].encode('utf-8'),
                bcrypt.gensalt()
            ).decode('utf-8')

        # Mettre à jour le rôle si fourni (superadmin uniquement)
        if 'role' in data and current_user_role == 'superadmin':
            update_data['role'] = data['role']

        # Mettre à jour le statut si fourni
        if 'is_active' in data:
            update_data['is_active'] = data['is_active']

        # Mettre à jour le répertoire si fourni
        if 'directory_id' in data:
            # Vérifier si le répertoire existe
            directory = supabase.table('directories').select('*').eq('id', data['directory_id']).execute()
            if not directory.data:
                return jsonify({'error': 'Répertoire non trouvé'}), 404

            if current_user_role == 'admin':
                # Vérifier si l'admin a accès au nouveau répertoire
                if admin_user.data[0]['directory_id'] != data['directory_id']:
                    return jsonify({'error': 'Permission non accordée pour ce répertoire'}), 403

            update_data['directory_id'] = data['directory_id']

        # Si aucune donnée à mettre à jour
        if len(update_data) == 1:  # Seulement updated_at
            return jsonify({'message': 'Aucune modification nécessaire'})

        # Effectuer la mise à jour
        updated_user = supabase.table('users').update(update_data).eq('id', user_id).execute()
        if not updated_user.data:
            return jsonify({'error': 'Erreur lors de la mise à jour de l\'utilisateur'}), 500

        # Ne pas renvoyer le hash du mot de passe
        result_user = updated_user.data[0]
        result_user.pop('password_hash', None)

        return jsonify({'message': 'Utilisateur mis à jour avec succès', 'user': result_user})
    except Exception as e:
        print(f"Erreur lors de la mise à jour de l'utilisateur: {str(e)}")
        return jsonify({'error': 'Erreur lors de la mise à jour de l\'utilisateur'}), 500

@app.route('/api/directories', methods=['GET'])
@login_required
def get_directories():
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Non autorisé'}), 401
            
        user_role = session.get('role')
        
        try:
            if user_role == 'superadmin':
                # Les superadmins voient tous les répertoires
                directories = supabase.table('directories')\
                    .select('*')\
                    .execute()
            else:
                # Les autres utilisateurs ne voient que leurs répertoires assignés
                directories = supabase.table('user_access')\
                    .select("directories(*)")\
                    .eq('user_id', user_id)\
                    .execute()
            
            if not directories.data:
                return jsonify([]), 200
            
            # Récupérer le nombre d'utilisateurs par répertoire
            directory_list = []
            for dir_data in directories.data:
                dir_info = dir_data.get('directories', dir_data)
                if not dir_info:
                    continue
                    
                try:
                    # Compter les utilisateurs dans ce répertoire
                    users_count = supabase.table('user_access')\
                        .select('id')\
                        .eq('directory_id', dir_info['id'])\
                        .execute()
                    
                    # Compter les fichiers dans ce répertoire
                    files_count = supabase.table('files')\
                        .select('id')\
                        .eq('directory_id', dir_info['id'])\
                        .execute()
                    
                    directory_list.append({
                        'id': dir_info['id'],
                        'name': dir_info['name'],
                        'users_count': len(users_count.data) if users_count.data else 0,
                        'files_count': len(files_count.data) if files_count.data else 0,
                        'created_at': dir_info.get('created_at'),
                        'updated_at': dir_info.get('updated_at'),
                        'role': dir_data.get('role_in_dir') if user_role != 'superadmin' else 'superadmin'
                    })
                except Exception as e:
                    logger.error(f"Erreur lors du comptage pour le répertoire {dir_info['id']}: {str(e)}")
                    continue
                    
            return jsonify(directory_list), 200
            
        except Exception as e:
            logger.error(f"Erreur lors de la requête Supabase: {str(e)}")
            return jsonify({'error': 'Erreur lors de la récupération des données'}), 500
            
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des répertoires: {str(e)}")
        return jsonify({'error': 'Erreur lors du chargement des répertoires'}), 500

@app.route('/api/directories/<directory_id>', methods=['DELETE'])
@login_required
@role_required(['admin', 'superadmin'])
def delete_directory(directory_id):
    try:
        # Vérifier si l'utilisateur a les droits sur ce répertoire
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        if user_role != 'superadmin':
            # Vérifier si l'utilisateur est admin du répertoire
            access = supabase.table('user_access')\
                .select('role_in_dir')\
                .eq('user_id', user_id)\
                .eq('directory_id', directory_id)\
                .single()\
                .execute()
                
            if not access.data or access.data['role_in_dir'] != 'admin':
                return jsonify({'error': 'Accès non autorisé'}), 403
        
        # Supprimer d'abord les accès utilisateurs
        supabase.table('user_access')\
            .delete()\
            .eq('directory_id', directory_id)\
            .execute()
            
        # Supprimer les fichiers associés
        supabase.table('files')\
            .delete()\
            .eq('directory_id', directory_id)\
            .execute()
            
        # Enfin, supprimer le répertoire
        supabase.table('directories')\
            .delete()\
            .eq('id', directory_id)\
            .execute()
            
        return jsonify({'message': 'Répertoire supprimé avec succès'}), 200
    except Exception as e:
        print(f"Erreur lors de la suppression du répertoire: {str(e)}")
        return jsonify({'error': 'Erreur lors de la suppression du répertoire'}), 500

@app.route('/api/directories', methods=['POST'])
@login_required
@role_required(['superadmin'])
def create_directory():
    """Créer un nouveau répertoire (superadmin uniquement)"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Non autorisé'}), 401

        data = request.get_json()
        if not data:
            return jsonify({'error': 'Données manquantes'}), 400

        # Vérifier les données requises
        name = data.get('name')
        if not name or not name.strip():
            return jsonify({'error': 'Le nom du répertoire est requis'}), 400
            
        # Vérifier si le répertoire existe déjà
        existing_dir = supabase.table('directories')\
            .select('id')\
            .eq('name', name.strip())\
            .execute()

        if existing_dir.data:
            return jsonify({'error': 'Un répertoire avec ce nom existe déjà'}), 409

        try:
            # Créer le répertoire
            new_directory = supabase.table('directories')\
                .insert({
                    'name': name.strip(),
                    'created_by': user_id,
                    'created_at': datetime.utcnow().isoformat(),
                    'updated_at': datetime.utcnow().isoformat()
                })\
                .execute()

            if not new_directory.data:
                return jsonify({'error': 'Erreur lors de la création du répertoire'}), 500

            directory_id = new_directory.data[0]['id']

            # Donner l'accès admin au créateur
            supabase.table('user_access')\
                .insert({
                    'user_id': user_id,
                    'directory_id': directory_id,
                    'role_in_dir': 'admin',
                    'created_at': datetime.utcnow().isoformat()
                })\
                .execute()

            # Enregistrer l'action
            log_user_action(
                user_id,
                'create_directory',
                {'directory_id': directory_id, 'name': name}
            )

            return jsonify({
                'message': 'Répertoire créé avec succès',
                'directory': {
                    'id': directory_id,
                    'name': name,
                    'users_count': 1,
                    'files_count': 0,
                    'role': 'admin'
                }
            }), 201

        except Exception as e:
            logger.error(f"Erreur lors de la création dans Supabase: {str(e)}")
            return jsonify({'error': 'Erreur lors de la création du répertoire'}), 500

    except Exception as e:
        logger.error(f"Erreur lors de la création du répertoire: {str(e)}")
        return jsonify({'error': 'Erreur lors de la création du répertoire'}), 500

@app.route('/api/directories/<directory_id>', methods=['PUT'])
@login_required
@role_required(['superadmin'])
def update_directory(directory_id):
    """Mettre à jour un répertoire (superadmin uniquement)"""
    try:
        data = request.json

        # Vérifier si le répertoire existe
        directory = supabase.table('directories').select('*').eq('id', directory_id).execute()
        if not directory.data:
            return jsonify({'error': 'Répertoire non trouvé'}), 404

        # Vérifier si le nouveau nom existe déjà
        if 'name' in data:
            existing_dir = supabase.table('directories').select('*').eq('name', data['name']).neq('id', directory_id).execute()
            if existing_dir.data:
                return jsonify({'error': 'Ce nom de répertoire est déjà utilisé'}), 400

        # Mettre à jour le répertoire
        update_data = {
            'name': data['name'],
            'updated_at': datetime.utcnow().isoformat()
        }

        updated_directory = supabase.table('directories').update(update_data).eq('id', directory_id).execute()
        if not updated_directory.data:
            return jsonify({'error': 'Erreur lors de la mise à jour du répertoire'}), 500

        return jsonify({'message': 'Répertoire mis à jour avec succès', 'directory': updated_directory.data[0]})
    except Exception as e:
        print(f"Erreur lors de la mise à jour du répertoire: {str(e)}")
        return jsonify({'error': 'Erreur lors de la mise à jour du répertoire'}), 500

# API Routes pour les statistiques des répertoires
@app.route('/api/directories/<directory_id>/stats', methods=['GET'])
@login_required
def get_directory_stats(directory_id):
    """Récupérer les statistiques d'un répertoire"""
    try:
        # Vérifier l'accès
        if not check_directory_access(directory_id):
            return jsonify({'error': 'Accès non autorisé'}), 403
            
        # Vérifier si le répertoire existe
        directory = supabase.table('directories')\
            .select('*')\
            .eq('id', directory_id)\
            .single()\
            .execute()
            
        if not directory.data:
            return jsonify({'error': 'Répertoire non trouvé'}), 404
            
        # Récupérer les fichiers du répertoire avec une seule requête optimisée
        files = supabase.table('files')\
            .select('''
                id,
                status,
                created_at,
                updated_at,
                created_by,
                users!inner (
                    email
                )
            ''')\
            .eq('directory_id', directory_id)\
            .execute()
            
        # Calculer les statistiques globales
        total_files = len(files.data)
        processed_files = len([f for f in files.data if f['status'] == 'processed'])
        success_rate = (processed_files / total_files * 100) if total_files > 0 else 0
        
        # Calculer les statistiques par utilisateur
        user_stats = {}
        for file in files.data:
            user_id = file['created_by']
            if user_id not in user_stats:
                user_stats[user_id] = {
                    'email': file['users']['email'],
                    'total_files': 0,
                    'processed_files': 0,
                    'success_rate': 0
                }
            user_stats[user_id]['total_files'] += 1
            if file['status'] == 'processed':
                user_stats[user_id]['processed_files'] += 1
                
        # Calculer les taux de succès par utilisateur
        for stats in user_stats.values():
            stats['success_rate'] = round(
                (stats['processed_files'] / stats['total_files'] * 100)
                if stats['total_files'] > 0 else 0,
                2
            )
        
        # Calculer la dernière activité
        last_activity = None
        if files.data:
            last_activity = max(
                f['updated_at'] if f['updated_at'] else f['created_at']
                for f in files.data
            )
        
        # Récupérer les utilisateurs ayant accès
        users_access = supabase.table('user_access')\
            .select('''
                user_id,
                role_in_dir,
                users (
                    email,
                    role
                )
            ''')\
            .eq('directory_id', directory_id)\
            .execute()
            
        # Préparer la réponse
        stats = {
            'directory': {
                'id': directory_id,
                'name': directory.data['name'],
                'created_at': directory.data['created_at'],
                'updated_at': directory.data.get('updated_at')
            },
            'files': {
                'total': total_files,
                'processed': processed_files,
                'success_rate': round(success_rate, 2),
                'last_activity': last_activity
            },
            'users': {
                'total': len(users_access.data),
                'by_role': {
                    'admin': len([u for u in users_access.data if u['role_in_dir'] == 'admin']),
                    'user': len([u for u in users_access.data if u['role_in_dir'] == 'user'])
                },
                'list': [{
                    'id': user['user_id'],
                    'email': user['users']['email'],
                    'role': user['role_in_dir'],
                    'stats': user_stats.get(user['user_id'], {
                        'total_files': 0,
                        'processed_files': 0,
                        'success_rate': 0
                    })
                } for user in users_access.data]
            },
            'timestamp': datetime.utcnow().isoformat()
        }
        
        # Enregistrer l'action
        log_user_action(
            session['user_id'],
            'view_directory_stats',
            {'directory_id': directory_id}
        )
        
        return jsonify(stats)
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques du répertoire: {str(e)}")
        return jsonify({'error': 'Erreur serveur'}), 500

# Fonction pour vérifier l'accès à un répertoire
def check_directory_access(directory_id):
    """Vérifie si l'utilisateur a accès au répertoire"""
    try:
        user_id = session.get('user_id')
        user_role = session.get('role')
        
        # Les superadmins ont accès à tout
        if user_role == 'superadmin':
            return True
            
        # Vérifier l'accès dans la table user_access
        access = supabase.table('user_access')\
            .select('role_in_dir')\
            .eq('user_id', user_id)\
            .eq('directory_id', directory_id)\
            .single()\
            .execute()
            
        return bool(access.data)
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de l'accès: {str(e)}")
        return False

# Fonction pour vérifier l'accès à un fichier
def check_file_access(file_id):
    """Vérifie si l'utilisateur a accès au fichier"""
    try:
        # Les superadmins ont accès à tout
        if session.get('role') == 'superadmin':
            return True
            
        # Récupérer le répertoire du fichier
        file = supabase.table('files')\
            .select('directory_id, user_id')\
            .eq('id', file_id)\
            .single()\
            .execute()
            
        if not file.data:
            return False
            
        # Le propriétaire du fichier a toujours accès
        if file.data['user_id'] == session.get('user_id'):
            return True
            
        # Vérifier l'accès au répertoire si le fichier est dans un répertoire
        if file.data['directory_id']:
            return check_directory_access(file.data['directory_id'])
            
        # Si pas de répertoire, seul le propriétaire a accès
        return False
        
    except Exception as e:
        logger.error(f"Erreur lors de la vérification de l'accès au fichier: {str(e)}")
        return False

@app.route('/api/files/upload', methods=['POST'])
def upload_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'Aucun fichier fourni'}), 400
            
        file = request.files['file']
        directory_id = request.form.get('directory_id')
        
        if not directory_id:
            return jsonify({'error': 'ID du répertoire requis'}), 400
            
        # Vérifier l'accès au répertoire
        if not check_directory_access(directory_id):
            return jsonify({'error': 'Accès non autorisé à ce répertoire'}), 403
            
        # Générer un nom de fichier unique
        filename = secure_filename(file.filename)
        storage_path = f"{session.get('user_id')}/{directory_id}/{uuid.uuid4()}_{filename}"
        
        # Lire le contenu du fichier et obtenir sa taille
        file_data = file.read()
        file_size = len(file_data)
        
        # Sauvegarder dans Supabase Storage
        supabase.storage.from_('files').upload(storage_path, file_data)
        
        # Créer l'entrée dans la base de données
        file_entry = {
            'filename': filename,
            'file_size': file_size,
            'mime_type': file.content_type,
            'directory_id': directory_id,
            'uploaded_by': session.get('user_id'),
            'created_at': datetime.now(timezone.utc).isoformat(),
            'updated_at': datetime.now(timezone.utc).isoformat(),
            'original_path': storage_path,
            'status': 'uploaded'
        }
        
        result = supabase.table('files').insert(file_entry).execute()
        
        if not result.data:
            raise Exception("Erreur lors de l'insertion en base de données")
            
        # Enregistrer l'action d'upload
        log_user_action(
            user_id=session.get('user_id'),
            action='file_upload',
            details={
                'filename': filename,
                'file_size': file_size,
                'directory_id': directory_id,
                'file_id': result.data[0]['id']
            }
        )
        
        return jsonify({
            'message': 'Fichier uploadé avec succès',
            'file_id': result.data[0]['id']
        }), 200
        
    except Exception as e:
        print(f"Erreur lors de l'upload: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/files/<file_id>/process', methods=['POST'])
@login_required
def process_existing_file(file_id):
    """Process an existing file"""
    try:
        # Récupérer les infos du fichier
        file_data = supabase.table('files')\
            .select('*')\
            .eq('id', file_id)\
            .single()\
            .execute()
            
        if not file_data.data:
            return jsonify({'error': 'Fichier non trouvé'}), 404
            
        file = file_data.data
        
        # Vérifier l'accès
        if not check_directory_access(file['directory_id']):
            return jsonify({'error': 'Accès non autorisé'}), 403
            
        # Mettre à jour le statut
        update_data = {
            'status': 'processing',
            'last_processed': datetime.now(timezone.utc).isoformat()
        }
        
        supabase.table('files')\
            .update(update_data)\
            .eq('id', file_id)\
            .execute()
            
        # Traitement du fichier PDF
        try:
            # Télécharger le fichier depuis Supabase Storage
            file_data = supabase.storage.from_('files').download(file['storage_path'])
            
            # Sauvegarder temporairement le fichier
            temp_path = os.path.join(app.config['UPLOAD_FOLDER'], f"temp_{uuid.uuid4()}.pdf")
            with open(temp_path, 'wb') as f:
                f.write(file_data)
            

            coordinates = process_pdf(temp_path)
            
            if isinstance(coordinates, dict) and 'error' in coordinates:
                raise Exception(coordinates['error'])
            
            # Créer le fichier CSV
            csv_filename = f"{os.path.splitext(file['name'])[0]}.csv"
            csv_path = os.path.join(app.config['OUTPUT_FOLDER'], csv_filename)
            
            # Sauvegarder en CSV
            df = pd.DataFrame(coordinates)
            df.to_csv(csv_path, index=False, sep=';')
            
            # Upload vers Supabase
            try:
                # Sauvegarder le CSV dans le bucket "csv"
                with open(csv_path, 'rb') as csv_file:
                    csv_storage_path = f"{session.get('user_id')}/coordinates/{file_id}/{csv_filename}"
                    supabase.storage.from_('csv').upload(csv_storage_path, csv_file)
                logger.info(f"CSV uploadé vers Supabase bucket 'csv': {csv_storage_path}")
            
            except Exception as e:
                logger.error(f"Erreur lors de l'upload du CSV: {str(e)}")
                raise Exception(f"Erreur lors de l'upload du CSV: {str(e)}")
            
            # Mettre à jour avec succès
            success_data = {
                'status': 'processed',
                'points': len(coordinates),  # Stocker le nombre de points
                'processed_at': datetime.now(timezone.utc).isoformat(),
                'storage_path': csv_storage_path
            }
            print("Mise à jour du statut en succès:", success_data)
            supabase.table('files')\
                .update(success_data)\
                .eq('id', file_id)\
                .execute()
                
            # Enregistrer l'action de traitement réussi
            log_user_action(
                user_id=session.get('user_id'),
                action='file_process',
                details={
                    'file_id': file_id,
                    'points': len(coordinates),
                    'status': 'success'
                }
            )
            
            # Nettoyer les fichiers temporaires
            if os.path.exists(temp_path):
                try:
                    os.unlink(temp_path)
                    print(f"Fichier temporaire supprimé: {temp_path}")
                except Exception as e:
                    print(f"Erreur lors de la suppression du fichier temporaire: {str(e)}")
            if os.path.exists(csv_path):
                os.remove(csv_path)
                
        except Exception as e:
            # En cas d'erreur de traitement
            error_data = {
                'status': 'error',
                'error_message': str(e)
            }
            
            supabase.table('files')\
                .update(error_data)\
                .eq('id', file_id)\
                .execute()
                
            # Enregistrer l'action de traitement échoué
            log_user_action(
                user_id=session.get('user_id'),
                action='file_process',
                details={
                    'file_id': file_id,
                    'status': 'error',
                    'error': str(e)
                }
            )
            
            # Nettoyer les fichiers temporaires en cas d'erreur
            if 'temp_path' in locals() and os.path.exists(temp_path):
                os.remove(temp_path)
            if 'csv_path' in locals() and os.path.exists(csv_path):
                os.remove(csv_path)
                
            raise e
            
        return jsonify({
            'message': 'Fichier traité avec succès',
            'points': len(coordinates),
            'file_id': file_id,  # Renvoyer l'ID du fichier au lieu du chemin du CSV
            'status': 'success'
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur lors du traitement: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/directories/<directory_id>/users/<user_id>', methods=['PUT'])
@login_required
@role_required(['admin', 'superadmin'])
def update_user_access(directory_id, user_id):
    try:
        data = request.get_json()
        new_role = data.get('role_in_dir')
        
        if not new_role:
            return jsonify({'error': 'Nouveau rôle requis'}), 400
            
        # Vérifier si l'utilisateur actuel peut modifier les accès
        if session.get('role') == 'admin':
            # Vérifier si l'utilisateur est admin du répertoire
            admin_access = supabase.table('user_access')\
                .select('role_in_dir')\
                .eq('user_id', session.get('user_id'))\
                .eq('directory_id', directory_id)\
                .single()\
                .execute()
                
            if not admin_access.data or admin_access.data['role_in_dir'] != 'admin':
                return jsonify({'error': 'Accès non autorisé'}), 403
        
        # Mettre à jour le rôle
        supabase.table('user_access')\
            .update({'role_in_dir': new_role})\
            .eq('directory_id', directory_id)\
            .eq('user_id', user_id)\
            .execute()
            
        return jsonify({'message': 'Accès mis à jour avec succès'}), 200
        
    except Exception as e:
        print(f"Erreur lors de la mise à jour de l'accès: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/me', methods=['GET'])
@login_required
def get_current_user():
    try:
        user_id = session.get('user_id')
        
        # Récupérer les informations de l'utilisateur
        user = supabase.table('users')\
            .select("id, email, role, created_at, user_access (directory_id, role_in_dir, directories (name))")\
            .eq('id', user_id)\
            .single()\
            .execute()

        if not user.data:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404
            
        # Formater la réponse
        user_data = {
            'id': user.data['id'],
            'email': user.data['email'],
            'role': user.data['role'],
            'created_at': user.data['created_at'],
            'directories': []
        }
        
        # Ajouter les répertoires accessibles
        if user.data.get('user_access'):
            for access in user.data['user_access']:
                if access.get('directories'):
                    user_data['directories'].append({
                        'id': access['directory_id'],
                        'name': access['directories']['name'],
                        'role': access['role_in_dir']
                    })
        
        return jsonify(user_data), 200
        
    except Exception as e:
        print(f"Erreur lors de la récupération du profil: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/me/stats', methods=['GET'])
@login_required
def get_user_stats():
    try:
        user_id = session.get('user_id')
        
        # Récupérer les statistiques des fichiers
        files = supabase.table('files')\
            .select('status, points')\
            .eq('user_id', user_id)\
            .execute()
            
        # Calculer les statistiques
        total_files = len(files.data)
        successful_files = len([f for f in files.data if f['status'] == 'success'])
        success_rate = (successful_files / total_files * 100) if total_files > 0 else 0
        
        # Récupérer l'historique des actions
        history = supabase.table('activity_log')\
            .select('action, created_at')\
            .eq('user_id', user_id)\
            .order('created_at', desc=True)\
            .limit(10)\
            .execute()
            
        stats = {
            'total_files': total_files,
            'successful_files': successful_files,
            'success_rate': round(success_rate, 2),
            'points': sum(f['points'] or 0 for f in files.data),  # Ajout de "or 0" pour gérer les None
            'recent_actions': history.data if history.data else []
        }
        
        return jsonify(stats), 200
        
    except Exception as e:
        print(f"Erreur lors de la récupération des statistiques: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/me/password', methods=['PUT'])
@login_required
def change_password():
    try:
        data = request.get_json()
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not current_password or not new_password:
            return jsonify({'error': 'Mot de passe actuel et nouveau requis'}), 400
            
        # Vérifier l'ancien mot de passe
        try:
            supabase.auth.sign_in_with_password({
                'email': session.get('email'),
                'password': current_password
            })
        except Exception:
            return jsonify({'error': 'Mot de passe actuel incorrect'}), 401
            
        # Mettre à jour le mot de passe
        supabase.auth.update_user({
            'password': new_password
        })
        
        return jsonify({'message': 'Mot de passe mis à jour avec succès'}), 200
        
    except Exception as e:
        print(f"Erreur lors du changement de mot de passe: {str(e)}")
        return jsonify({'error': str(e)}), 500

# Fonction pour enregistrer une action utilisateur
def log_user_action(user_id, action, details=None):
    try:
        action_data = {
            'user_id': user_id,
            'action': action,
            'details': details,
            'created_at': datetime.now().isoformat()
        }
        
        supabase.table('activity_log').insert(action_data).execute()
    except Exception as e:
        print(f"Erreur lors de l'enregistrement de l'action: {str(e)}")

# Route pour les statistiques de l'utilisateur courant
@app.route('/api/stats/user', methods=['GET'])
@login_required
def get_user_dashboard_stats():
    """Récupérer les statistiques pour le tableau de bord utilisateur"""
    try:
        user_id = session.get('user_id')
        if not user_id:
            return jsonify({'error': 'Non autorisé'}), 401

        # Récupérer tous les fichiers de l'utilisateur
        response = supabase.table('files')\
            .select('id, status')\
            .eq('user_id', user_id)\
            .execute()

        if not hasattr(response, 'data'):
            return jsonify({
                'processed_files': 0,
                'error_files': 0,
                'pending_files': 0,
                'success_rate': 0.0
            })

        files = response.data
        
        # Calculer les statistiques
        processed_files = sum(1 for f in files if f['status'] == 'success')
        error_files = sum(1 for f in files if f['status'] == 'error')
        pending_files = sum(1 for f in files if f['status'] == 'processing')
        
        # Calculer le taux de succès uniquement sur les fichiers terminés
        completed_files = processed_files + error_files
        success_rate = (processed_files / completed_files * 100) if completed_files > 0 else 0.0

        return jsonify({
            'processed_files': processed_files,
            'error_files': error_files,
            'pending_files': pending_files,
            'success_rate': round(success_rate, 1)  # Arrondir à 1 décimale
        }), 200
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des statistiques: {str(e)}")
        return jsonify({
            'processed_files': 0,
            'error_files': 0,
            'pending_files': 0,
            'success_rate': 0.0
        }), 500


@app.route('/api/users/me/avatar', methods=['POST'])
@login_required
def update_avatar():
    """Mettre à jour l'avatar de l'utilisateur"""
    try:
        user_id = session.get('user_id')
        
        if 'avatar' not in request.files:
            return jsonify({'error': 'Aucun fichier envoyé'}), 400
            
        file = request.files['avatar']
        
        if file.filename == '':
            return jsonify({'error': 'Aucun fichier sélectionné'}), 400
            
        if not file.content_type.startswith('image/'):
            return jsonify({'error': 'Le fichier doit être une image'}), 400
            
        # Créer le dossier avatars s'il n'existe pas
        avatar_folder = os.path.join(app.static_folder, 'avatars')
        os.makedirs(avatar_folder, exist_ok=True)
        
        # Générer un nom de fichier unique
        filename = f"avatar_{user_id}_{int(time.time())}{os.path.splitext(file.filename)[1]}"
        filepath = os.path.join(avatar_folder, filename)
        
        # Sauvegarder le fichier
        file.save(filepath)
        
        # Mettre à jour l'URL de l'avatar dans la base de données
        avatar_url = f'/static/avatars/{filename}'
        response = supabase.table('users')\
            .update({
                'avatar_url': avatar_url,
                'updated_at': datetime.now(timezone.utc).isoformat()
            })\
            .eq('id', user_id)\
            .execute()
            
        if not hasattr(response, 'data'):
            # Supprimer le fichier si l'update a échoué
            os.remove(filepath)
            return jsonify({'error': 'Erreur lors de la mise à jour de l\'avatar'}), 500
            
        return jsonify({
            'message': 'Avatar mis à jour avec succès',
            'avatar_url': avatar_url
        })
        
    except Exception as e:
        logger.error(f"Erreur lors de la mise à jour de l'avatar: {str(e)}")
        return jsonify({'error': 'Erreur serveur'}), 500


@app.route('/api/process-folder', methods=['POST'])
@login_required
def process_folder():
    """Traite tous les fichiers plan.pdf dans un dossier"""
    try:
        data = request.get_json()
        if not data or 'folder_path' not in data:
            return jsonify({'error': 'Chemin du dossier non fourni'}), 400
            
        folder_path = data['folder_path']
        file_path = data.get('file_path')
        directory_id = data.get('directory_id')
        
        if not directory_id:
            return jsonify({'error': 'ID du répertoire requis'}), 400
            
        logger.info(f"Traitement du dossier: {folder_path}, fichier: {file_path}")
        
        if not os.path.exists(folder_path):
            return jsonify({'error': 'Dossier non trouvé'}), 404
            
        # Traiter le fichier PDF
        try:
            pdf_path = os.path.join(folder_path, 'plan.pdf')
            
            # Lire le fichier PDF et obtenir sa taille
            with open(pdf_path, 'rb') as f:
                pdf_data = f.read()
                file_size = len(pdf_data)
            
            # Générer un ID unique pour le fichier PDF
            pdf_id = str(uuid.uuid4())
            
            # Créer l'entrée dans la base de données pour le PDF
            pdf_entry = {
                'id': pdf_id,
                'name': os.path.basename(pdf_path),
                'size': file_size,
                'mime_type': 'application/pdf',
                'type': 'pdf',
                'directory_id': directory_id,
                'uploaded_by': session.get('user_id'),
                'created_at': datetime.now(timezone.utc).isoformat(),
                'updated_at': datetime.now(timezone.utc).isoformat(),
                'original_path': pdf_path,
                'status': 'processing'
            }
            
            # Insérer le PDF dans la base de données
            pdf_result = supabase.table('files').insert(pdf_entry).execute()
            
            if not pdf_result.data:
                raise Exception("Erreur lors de l'insertion du PDF en base de données")
                
            # Traiter le PDF et générer le CSV
            csv_filename, points = process_pdf(pdf_path, pdf_id)
            
            if isinstance(csv_filename, dict) and 'error' in csv_filename:
                raise Exception(csv_filename['error'])
                
            # Lire le fichier CSV généré
            csv_path = os.path.join(app.config['OUTPUT_FOLDER'], csv_filename)
            
            # Sauvegarder en CSV
            df = pd.DataFrame(points)
            df.to_csv(csv_path, index=False, sep=';')
            
            # Upload vers Supabase
            try:
                # Sauvegarder le CSV dans le bucket "csv"
                with open(csv_path, 'rb') as csv_file:
                    csv_storage_path = f"{session.get('user_id')}/coordinates/{pdf_id}/{csv_filename}"
                    supabase.storage.from_('csv').upload(csv_storage_path, csv_file)
                logger.info(f"CSV uploadé vers Supabase bucket 'csv': {csv_storage_path}")
            
            except Exception as e:
                logger.error(f"Erreur lors de l'upload du CSV: {str(e)}")
                raise Exception(f"Erreur lors de l'upload du CSV: {str(e)}")
            
            # Mettre à jour avec succès
            success_data = {
                'status': 'processed',
                'points': len(points),  # Stocker le nombre de points
                'processed_at': datetime.now(timezone.utc).isoformat(),
                'storage_path': csv_storage_path
            }
            print("Mise à jour du statut en succès:", success_data)
            supabase.table('files')\
                .update(success_data)\
                .eq('id', pdf_id)\
                .execute()
                
            # Enregistrer l'action de traitement réussi
            log_user_action(
                user_id=session.get('user_id'),
                action='file_process',
                details={
                    'file_id': pdf_id,
                    'points': len(points),
                    'status': 'success'
                }
            )
            
            # Nettoyer les fichiers temporaires
            if os.path.exists(csv_path):
                os.remove(csv_path)
                
        except Exception as e:
            logger.error(f"Erreur lors du traitement de {file_path}: {str(e)}")
            return jsonify({
                'error': f"Erreur lors du traitement: {str(e)}",
                'success': False
            }), 500
        
    except Exception as e:
        logger.error(f"Erreur lors du traitement du dossier: {str(e)}")
        return jsonify({'error': str(e), 'success': False}), 500

def uuid_to_int(uuid_str):
    """Convertit un UUID en entier pour la compatibilité avec bigint"""
    # Enlever les tirets et convertir en entier base 16
    return int(uuid_str.replace('-', ''), 16) % (2**63)  # Pour rester dans les limites de bigint

def process_pdf(file_path, file_id=None, output_dir=None):
    """Traite un fichier PDF et extrait les coordonnées"""
    try:
        logger.info(f"Traitement du fichier PDF: {file_path}")
        logger.info(f"ID du fichier: {file_id}")
        logger.info(f"Dossier de sortie: {output_dir}")
        
        # Vérifier si le fichier existe
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Le fichier {file_path} n'existe pas")
            
        # Convert PDF to images with higher DPI for better OCR
        try:
            images = convert_from_path(file_path, dpi=300)
            logger.info(f"PDF converti en {len(images)} pages")
        except Exception as e:
            logger.error(f"Erreur lors de la conversion du PDF: {str(e)}")
            raise Exception(f"Erreur lors de la conversion du PDF: {str(e)}")
        
        if not images:
            raise Exception("Aucune page trouvée dans le PDF")
        
        reader = easyocr.Reader(['fr'])
        all_numbers = []
        
        for i, image in enumerate(images):
            logger.info(f"Traitement de la page {i+1}/{len(images)}")
            try:
                # Convertir l'image en niveaux de gris pour améliorer l'OCR
                image_np = np.array(image.convert('L'))
                
                # Améliorer le contraste de l'image
                image_np = np.clip((image_np - image_np.min()) * 255.0 / (image_np.max() - image_np.min()), 0, 255).astype(np.uint8)
                
                results = reader.readtext(image_np)
                
                # Extraction des nombres avec plus de flexibilité
                page_numbers = []
                for result in results:
                    text = result[1].replace(' ', '')  # Supprimer les espaces
                    # Rechercher les nombres avec ou sans décimales
                    extracted_numbers = re.findall(r'\b\d{5,}(?:[.,]\d+)?\b', text)
                    
                    for num in extracted_numbers:
                        try:
                            # Remplacer la virgule par un point si présent
                            num = num.replace(',', '.')
                            value = float(num)
                            
                            if value not in page_numbers:  # Éviter les doublons
                                page_numbers.append(value)
                                logger.debug(f"Nombre trouvé: {value}")
                        except ValueError:
                            logger.warning(f"Impossible de convertir en nombre: {num}")
                            continue
                
                # Ajouter les nombres de la page uniquement s'ils forment des paires
                if len(page_numbers) >= 2:
                    all_numbers.extend(page_numbers)
                
            except Exception as e:
                logger.error(f"Erreur lors du traitement de la page {i+1}: {str(e)}")
                continue  # Continuer avec la page suivante en cas d'erreur
        
        logger.info(f"Nombres extraits: {len(all_numbers)}")
        
        if len(all_numbers) == 0:
            raise Exception("Aucune coordonnée trouvée dans le document")
            
        # Créer des paires de coordonnées
        coordinates = []
        for i in range(0, len(all_numbers)-1, 2):
            coordinates.append({
                'X': all_numbers[i],
                'Y': all_numbers[i+1]
            })
        
        logger.info(f"Coordonnées extraites: {len(coordinates)} points")
        
        # Générer un nom unique pour le fichier CSV
        csv_filename = f"coordinates_{file_id}.csv"
        
        # Créer le dossier de sortie s'il n'existe pas
        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            csv_path = os.path.join(output_dir, csv_filename)
        else:
            csv_path = os.path.join(app.config['OUTPUT_FOLDER'], csv_filename)
            os.makedirs(app.config['OUTPUT_FOLDER'], exist_ok=True)
        
        # Sauvegarder en CSV localement
        df = pd.DataFrame(coordinates)
        df.to_csv(csv_path, index=False, sep=';')
        logger.info(f"CSV sauvegardé: {csv_path}")
        
        # Upload vers Supabase
        try:
            # Sauvegarder le CSV dans le bucket "csv"
            with open(csv_path, 'rb') as csv_file:
                csv_storage_path = f"{session.get('user_id')}/coordinates/{file_id}/{csv_filename}"
                supabase.storage.from_('csv').upload(csv_storage_path, csv_file)
            logger.info(f"CSV uploadé vers Supabase bucket 'csv': {csv_storage_path}")
            
            return csv_filename, coordinates
            
        except Exception as e:
            logger.error(f"Erreur lors de l'upload du CSV: {str(e)}")
            raise Exception(f"Erreur lors de l'upload du CSV: {str(e)}")
            
    except Exception as e:
        logger.error(f"Erreur lors du traitement du PDF: {str(e)}")
        return {'error': str(e)}

# Fonction pour initialiser les buckets Supabase
def init_supabase_storage():
    """Initialises les buckets de stockage Supabase"""
    try:
        # Liste des buckets existants
        buckets = supabase.storage.list_buckets()
        bucket_names = [bucket.name for bucket in buckets]
        
        # Créer le bucket 'csv' s'il n'existe pas
        if 'csv' not in bucket_names:
            supabase.storage.create_bucket(
                'csv',
                options={'public': False}
            )
            logger.info("Bucket 'csv' créé avec succès")
        else:
            logger.info("Bucket 'csv' existe déjà")
            
    except Exception as e:
        logger.error(f"Erreur lors de l'initialisation du stockage Supabase: {str(e)}")
        raise e

# Fonctions utilitaires pour le stockage Supabase
def download_csv_from_supabase(file_id, user_id, folder_name):
    """Télécharge un fichier CSV depuis le bucket Supabase"""
    try:
        # Construire le chemin de stockage
        storage_path = f"{user_id}/coordinates/{file_id}/{folder_name}"
        
        # Télécharger depuis le bucket "csv"
        try:
            response = supabase.storage.from_('csv').download(storage_path)
            return response
        except Exception as e:
            logger.error(f"Erreur lors du téléchargement direct: {str(e)}")
            
            # Vérifier si le fichier existe
            files = supabase.storage.from_('csv').list()
            for file in files:
                if file['name'] == storage_path:
                    return supabase.storage.from_('csv').download(storage_path)
            
            raise FileNotFoundError(f"Le fichier {storage_path} n'existe pas dans le bucket csv")
            
    except Exception as e:
        logger.error(f"Erreur lors du téléchargement du CSV depuis Supabase: {str(e)}")
        raise

def upload_csv_to_supabase(file_id, csv_data, user_id, folder_name):
    """Upload un fichier CSV vers le bucket Supabase"""
    try:
        # Construire le chemin du fichier dans le bucket
        file_path = f"{user_id}/coordinates/{file_id}/{folder_name}"
        
        # Vérifier si le fichier existe déjà et le supprimer
        try:
            supabase.storage.from_('csv').remove([file_path])
            logger.info(f"Ancien fichier supprimé: {file_path}")
        except Exception as e:
            logger.info(f"Aucun fichier existant à supprimer: {str(e)}")
        
        # Upload le nouveau fichier
        result = supabase.storage.from_('csv').upload(file_path, csv_data)
        logger.info(f"Fichier CSV uploadé avec succès: {file_path}")
        
        return result
        
    except Exception as e:
        logger.error(f"Erreur lors de l'upload du CSV vers Supabase: {str(e)}")
        raise Exception(f"Erreur lors de l'upload du CSV: {str(e)}")

def upload_pdf_to_supabase(file_id, pdf_data, user_id, folder_name):
    """Upload un fichier PDF vers le bucket Supabase"""
    try:
        # Construire le chemin du fichier dans le bucket
        file_path = f"{user_id}/uploads/{file_id}.pdf"
        
        # Vérifier si le fichier existe déjà et le supprimer
        try:
            supabase.storage.from_('files').remove([file_path])
            logger.info(f"Ancien fichier supprimé: {file_path}")
        except Exception as e:
            logger.info(f"Aucun fichier existant à supprimer: {str(e)}")
        
        # Upload le fichier PDF
        result = supabase.storage.from_('files').upload(file_path, pdf_data)
        logger.info(f"Fichier PDF uploadé avec succès: {file_path}")
        
        return result
        
    except Exception as e:
        logger.error(f"Erreur lors de l'upload du PDF vers Supabase: {str(e)}")
        raise Exception(f"Erreur lors de l'upload du PDF: {str(e)}")

def download_csv_from_supabase(file_id, user_id, folder_name):
    """Télécharge un fichier CSV depuis le bucket Supabase"""
    try:
        # Construire le chemin de stockage
        storage_path = f"{user_id}/coordinates/{file_id}/{folder_name}"
        
        # Télécharger depuis le bucket "csv"
        try:
            response = supabase.storage.from_('csv').download(storage_path)
            return response
        except Exception as e:
            logger.error(f"Erreur lors du téléchargement direct: {str(e)}")
            
            # Vérifier si le fichier existe
            files = supabase.storage.from_('csv').list()
            for file in files:
                if file['name'] == storage_path:
                    return supabase.storage.from_('csv').download(storage_path)
            
            raise FileNotFoundError(f"Le fichier {storage_path} n'existe pas dans le bucket csv")
            
    except Exception as e:
        logger.error(f"Erreur lors du téléchargement du CSV depuis Supabase: {str(e)}")
        raise

def download_pdf_from_supabase(file_id, user_id, folder_name):
    """Télécharge un fichier PDF depuis le bucket Supabase"""
    try:
        # Le chemin du fichier PDF est dans le dossier uploads
        file_path = f"{user_id}/uploads/{file_id}.pdf"
        print(f"Tentative de téléchargement du PDF: {file_path}")
        
        try:
            # Essayer de télécharger directement le fichier depuis le bucket 'files'
            pdf_data = supabase.storage.from_('files').download(file_path)
            print(f"PDF téléchargé avec succès, taille: {len(pdf_data)} bytes")
            return pdf_data
        except Exception as download_error:
            logger.error(f"Erreur lors du téléchargement direct: {str(download_error)}")
            # Si le téléchargement échoue, vérifier si le fichier existe
            existing_files = supabase.storage.from_('files').list(f"{user_id}/uploads")
            print(f"Fichiers existants dans le dossier: {existing_files}")
            if not any(f.get('name') == f"{file_id}.pdf" for f in existing_files):
                raise FileNotFoundError(f"Le fichier {file_path} n'existe pas dans le bucket")
            else:
                # Le fichier existe mais il y a eu une erreur de téléchargement
                raise download_error
            
    except Exception as e:
        logger.error(f"Erreur lors du téléchargement du PDF depuis Supabase: {str(e)}")
        raise e


@app.route('/api/admin/users', methods=['GET'])
@login_required
@role_required(['admin'])
def get_directory_users():
    """Récupère la liste des utilisateurs du répertoire"""
    try:
        # Récupérer l'ID du répertoire de l'admin
        admin_directory = supabase.table('user_access')\
            .select('directory_id')\
            .eq('user_id', session['user_id'])\
            .eq('role_in_dir', 'admin')\
            .single()\
            .execute()
            
        if not admin_directory.data:
            return jsonify({'error': 'Répertoire non trouvé'}), 404
            
        directory_id = admin_directory.data['directory_id']
        
        # Récupérer les utilisateurs du répertoire
        users = supabase.table('user_access')\
            .select('user_id')\
            .eq('directory_id', directory_id)\
            .execute()
            
        user_ids = [user['user_id'] for user in users.data]
        
        # Récupérer les informations des utilisateurs
        users = supabase.table('users').select('*').in_('id', user_ids).execute()
        print(f"Informations utilisateurs récupérées: {users.data}")
        
        # Enrichir les données des utilisateurs
        user_list = []
        for user in users.data:
            # Récupérer les statistiques des fichiers
            files = supabase.table('files')\
                .select('id, file_size')\
                .eq('uploaded_by', user['id'])\
                .execute()
                
            processed_files = len(files.data)
            storage_used = sum(file['file_size'] for file in files.data)
            
            # Récupérer la dernière activité
            last_activity = supabase.table('activity_log')\
                .select('created_at')\
                .eq('user_id', user['id'])\
                .order('created_at', desc=True)\
                .limit(1)\
                .execute()
                
            user_list.append({
                'id': user['id'],
                'email': user['email'],
                'is_active': user['last_login'] is not None and \
                           (datetime.now(timezone.utc) - datetime.fromisoformat(user['last_login'])).days < 30,
                'processed_files': processed_files,
                'storage_used': format_size(storage_used),
                'last_activity': last_activity.data[0]['created_at'] if last_activity.data else None,
                'created_at': user['created_at']
            })
            
        return jsonify(user_list)
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des utilisateurs: {str(e)}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/admin/users/<user_id>', methods=['GET'])
@login_required
@role_required(['admin'])
def get_user_details(user_id):
    """Récupère les détails d'un utilisateur spécifique"""
    try:
        # Vérifier que l'utilisateur appartient au répertoire de l'admin
        admin_directory = supabase.table('user_access')\
            .select('directory_id')\
            .eq('user_id', session['user_id'])\
            .eq('role_in_dir', 'admin')\
            .single()\
            .execute()
            
        if not admin_directory.data:
            return jsonify({'error': 'Répertoire non trouvé'}), 404
            
        directory_id = admin_directory.data['directory_id']
        
        # Vérifier l'accès à l'utilisateur
        user_access = supabase.table('user_access')\
            .select('user_id')\
            .eq('directory_id', directory_id)\
            .eq('user_id', user_id)\
            .single()\
            .execute()
            
        if not user_access.data:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404
            
        # Récupérer les détails de l'utilisateur
        user = supabase.table('users')\
            .select('*')\
            .eq('id', user_id)\
            .single()\
            .execute()

        if not user.data:
            return jsonify({'error': 'Utilisateur non trouvé'}), 404
            
        # Récupérer les statistiques des fichiers
        files = supabase.table('files')\
            .select('id, file_size')\
            .eq('uploaded_by', user_id)\
            .execute()
            
        # Récupérer l'historique d'activité
        activities = supabase.table('activity_log')\
            .select('*')\
            .eq('user_id', user_id)\
            .order('created_at', desc=True)\
            .limit(10)\
            .execute()
            
        return jsonify({
            'user': {
                'id': user.data['id'],
                'email': user.data['email'],
                'is_active': user.data['last_login'] is not None and \
                           (datetime.now(timezone.utc) - datetime.fromisoformat(user.data['last_login'])).days < 30,
                'created_at': user.data['created_at'],
                'last_login': user.data['last_login']
            },
            'stats': {
                'processed_files': len(files.data),
                'storage_used': format_size(sum(file['file_size'] for file in files.data)),
            },
            'activities': activities.data
        })
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération des détails de l'utilisateur: {str(e)}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/users/me/export', methods=['POST'])
@login_required
def export_users():
    """Exporte la liste des utilisateurs au format CSV ou Excel"""
    try:
        format = request.json.get('format', 'csv')
        period = request.json.get('period', 'all')
        
        # Récupérer les utilisateurs
        users = get_directory_users()
        if not isinstance(users.json, list):
            return jsonify({'error': 'Erreur lors de la récupération des utilisateurs'}), 500
            
        # Filtrer par période si nécessaire
        if period != 'all':
            days = 30 if period == 'month' else 7
            cutoff = datetime.now(timezone.utc) - timedelta(days=days)
            users_data = [u for u in users.json if datetime.fromisoformat(u['created_at']) >= cutoff]
        else:
            users_data = users.json
            
        # Préparer les données pour l'export
        export_data = []
        for user in users_data:
            export_data.append({
                'Email': user['email'],
                'Statut': 'Actif' if user['is_active'] else 'Inactif',
                'Fichiers traités': user['processed_files'],
                'Points extraits': user.get('total_points', 0),  # Nouveau
                'Taux de succès': f"{user.get('success_rate', 0):.1f}%",  # Nouveau
                'Espace utilisé': user['storage_used'],
                'Dernière activité': user['last_activity'],
                'Date d\'inscription': user['created_at']
            })
            
        # Créer le fichier d'export
        if format == 'csv':
            output = StringIO()
            writer = csv.DictWriter(output, fieldnames=export_data[0].keys())
            writer.writeheader()
            writer.writerows(export_data)
            
            # Créer le fichier à envoyer
            mem_file = BytesIO()
            mem_file.write(output.getvalue().encode('utf-8-sig'))
            mem_file.seek(0)
            
            return send_file(
                mem_file,
                mimetype='text/csv',
                as_attachment=True,
                download_name=f'users_export_{datetime.now().strftime("%Y%m%d")}.csv'
            )
        else:  # xlsx
            df = pd.DataFrame(export_data)
            
            # Créer le fichier Excel
            output = BytesIO()
            with pd.ExcelWriter(output, engine='xlsxwriter') as writer:
                df.to_excel(writer, index=False, sheet_name='Utilisateurs')
                
            output.seek(0)
            
            return send_file(
                output,
                mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                as_attachment=True,
                download_name=f'users_export_{datetime.now().strftime("%Y%m%d")}.xlsx'
            )
            
    except Exception as e:
        logger.error(f"Erreur lors de l'export des utilisateurs: {str(e)}")
        return jsonify({'error': 'Erreur serveur'}), 500

@app.route('/api/admin/files', methods=['GET'])
@login_required
@role_required(['admin'])
def get_admin_files():
    try:
        # Récupérer l'ID du répertoire de l'admin
        admin_directory = supabase.table('user_access')\
            .select('directory_id')\
            .eq('user_id', session['user_id'])\
            .eq('role_in_dir', 'admin')\
            .single()\
            .execute()
            
        if not admin_directory.data:
            return jsonify({'error': 'Répertoire non trouvé'}), 404
            
        directory_id = admin_directory.data['directory_id']
        
        # Récupérer les utilisateurs du répertoire
        users = supabase.table('user_access')\
            .select('user_id')\
            .eq('directory_id', directory_id)\
            .execute()
            
        user_ids = [user['user_id'] for user in users.data]
        
        # Récupérer les fichiers avec les informations utilisateur
        files = supabase.table('files')\
            .select('*, users:uploaded_by(email)')\
            .in_('uploaded_by', user_ids)\
            .order('created_at', desc=True)\
            .execute()
            
        # Format file sizes and add download URLs for CSV files
        for file in files.data:
            if 'size' in file:
                file['formatted_size'] = format_size(file['size'])
            
            # Add download URL for CSV files
            if file.get('type') == 'csv' and file.get('storage_path'):
                try:
                    signed_url = supabase.storage\
                        .from_('csv')\
                        .create_signed_url(file['storage_path'], 3600)  # URL valide 1 heure
                    
                    if signed_url and 'signedURL' in signed_url:
                        file['download_url'] = signed_url['signedURL']
                    else:
                        print(f"URL signée invalide pour le fichier {file.get('id')}")
                        file['download_url'] = None
                except Exception as e:
                    print(f"Erreur lors de la création de l'URL signée pour le CSV: {str(e)}")
                    file['download_url'] = None
            
        return jsonify(files.data)
        
    except Exception as e:
        print(f"Erreur lors de la récupération des fichiers admin: {str(e)}")
        if 'disconnected' in str(e).lower():
            if reconnect_supabase():
                # Réessayer une fois après la reconnexion
                return get_admin_files()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/activity', methods=['GET'])
@login_required
@role_required(['admin'])
def get_admin_activity():
    """Récupère l'activité des utilisateurs pour le dashboard admin"""
    try:
        # Récupérer l'ID du répertoire de l'admin
        admin_directory = supabase.table('user_access')\
            .select('directory_id')\
            .eq('user_id', session['user_id'])\
            .eq('role_in_dir', 'admin')\
            .single()\
            .execute()
            
        if not admin_directory.data:
            return jsonify({'error': 'Répertoire non trouvé'}), 404
            
        directory_id = admin_directory.data['directory_id']
        
        # Récupérer les utilisateurs du répertoire
        users = supabase.table('user_access')\
            .select('user_id')\
            .eq('directory_id', directory_id)\
            .execute()
            
        user_ids = [user['user_id'] for user in users.data]
        
        # Récupérer l'activité des utilisateurs
        activity = supabase.table('activity_log')\
            .select('*')\
            .in_('user_id', user_ids)\
            .order('created_at', desc=True)\
            .limit(50)\
            .execute()
            
        return jsonify(activity.data)
        
    except Exception as e:
        print(f"Erreur lors de la récupération de l'activité: {str(e)}")
        if 'disconnected' in str(e).lower():
            if reconnect_supabase():
                # Réessayer une fois après la reconnexion
                return get_admin_activity()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/activity-stats', methods=['GET'])
@login_required
@role_required(['admin'])
def get_admin_activity_stats():
    """Récupère les statistiques d'activité pour le dashboard admin"""
    try:
        print("\n=== Début de get_admin_activity_stats ===")
        
        # Récupérer la période demandée (semaine ou mois)
        period = request.args.get('period', 'week')
        days = 30 if period == 'month' else 7
        print(f"Période demandée: {period} ({days} jours)")
        
        # Récupérer l'ID du répertoire de l'admin
        admin_directory = supabase.table('user_access')\
            .select('directory_id')\
            .eq('user_id', session['user_id'])\
            .eq('role_in_dir', 'admin')\
            .single()\
            .execute()
            
        print("Réponse admin_directory:", admin_directory.data)
        
        if not admin_directory.data:
            print("Répertoire admin non trouvé")
            return jsonify({'error': 'Répertoire non trouvé'}), 404
            
        directory_id = admin_directory.data['directory_id']
        print(f"Directory ID: {directory_id}")
        
        # Récupérer les utilisateurs du répertoire
        users = supabase.table('user_access')\
            .select('user_id')\
            .eq('directory_id', directory_id)\
            .execute()
            
        user_ids = [user['user_id'] for user in users.data]
        print(f"Utilisateurs trouvés: {len(user_ids)}")
        print("User IDs:", user_ids)
        
        # Calculer la date de début selon la période
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        
        # Récupérer les activités pour la période
        activities = supabase.table('activity_log')\
            .select('*')\
            .in_('user_id', user_ids)\
            .gte('created_at', start_date.isoformat())\
            .order('created_at')\
            .execute()
            
        if not activities.data:
            # Retourner un jeu de données vide mais correctement formaté
            return jsonify({
                'labels': [],
                'datasets': [
                    {'label': 'Connexions', 'data': [], 'borderColor': '#28a745', 'fill': False},
                    {'label': 'Uploads', 'data': [], 'borderColor': '#007bff', 'fill': False},
                    {'label': 'Traitements', 'data': [], 'borderColor': '#ffc107', 'fill': False}
                ]
            })
        
        # Créer un dictionnaire pour regrouper les activités par date
        daily_stats = {}
        current_date = start_date
        end_date = datetime.now(timezone.utc)
        
        # Initialiser toutes les dates de la période
        while current_date <= end_date:
            date_str = current_date.date().isoformat()
            daily_stats[date_str] = {
                'connections': 0,  # login ou dashboard_access
                'uploads': 0,      # file_process_start
                'processing': 0    # file_process_success
            }
            current_date += timedelta(days=1)
        
        # Compter les activités par type et par date
        for activity in activities.data:
            activity_date = datetime.fromisoformat(activity['created_at']).date().isoformat()
            
            if activity_date in daily_stats:
                action = activity.get('action', '')
                
                if action in ['login', 'dashboard_access']:
                    daily_stats[activity_date]['connections'] += 1
                elif action == 'file_process_start':
                    daily_stats[activity_date]['uploads'] += 1
                elif action == 'file_process_success':
                    daily_stats[activity_date]['processing'] += 1
        
        # Calculer les données pour le graphique
        dates = sorted(daily_stats.keys())
        connections = [daily_stats[date]['connections'] for date in dates]
        uploads = [daily_stats[date]['uploads'] for date in dates]
        processing = [daily_stats[date]['processing'] for date in dates]
        
        # Formater la réponse
        response_data = {
            'labels': dates,
            'datasets': [
                {
                    'label': 'Connexions',
                    'data': connections,
                    'borderColor': '#28a745',
                    'fill': False
                },
                {
                    'label': 'Uploads',
                    'data': uploads,
                    'borderColor': '#007bff',
                    'fill': False
                },
                {
                    'label': 'Traitements',
                    'data': processing,
                    'borderColor': '#ffc107',
                    'fill': False
                }
            ]
        }
        
        return jsonify(response_data)
        
    except Exception as e:
        print(f"Erreur lors de la récupération des statistiques d'activité: {str(e)}")
        if 'disconnected' in str(e).lower():
            if reconnect_supabase():
                # Réessayer une fois après la reconnexion
                return get_admin_activity_stats()
        return jsonify({'error': str(e)}), 500

@app.route('/api/admin/stats', methods=['GET'])
@login_required
@role_required(['admin'])
def get_admin_stats():
    """Récupère les statistiques générales pour le dashboard admin"""
    try:
        # Récupérer tous les utilisateurs
        user_logins = supabase.table('users')\
            .select('id, last_login')\
            .execute()
            
        # Extraire les IDs des utilisateurs
        user_ids = [user['id'] for user in user_logins.data]
        
        total_users = len(user_logins.data)
        active_users = sum(1 for user in user_logins.data if user['last_login'] and \
                         (datetime.now(timezone.utc) - datetime.fromisoformat(user['last_login'])).days < 30)
        
        # Statistiques des fichiers
        file_stats = supabase.table('files')\
            .select('id, file_size, status, created_at, processed_at, points')\
            .in_('user_id', user_ids)\
            .execute()
            
        files = file_stats.data
        
        total_files = len(files)
        total_size = sum(file.get('file_size', 0) or 0 for file in files)  # Ajout de "or 0" pour gérer les None
        processed_files = sum(1 for file in files if file.get('status') == 'success')
        error_files = sum(1 for file in files if file.get('status') == 'error')
        processing_files = sum(1 for file in files if file.get('status') == 'processing')
        total_points = sum(file.get('points', 0) or 0 for file in files)  # Ajout de "or 0" pour gérer les None
        
        # Calculer le taux de succès
        success_rate = (processed_files / total_files * 100) if total_files > 0 else 0
        
        # Statistiques d'activité sur 7 jours
        now = datetime.now(timezone.utc)
        week_ago = now - timedelta(days=7)
        
        daily_stats = []
        for i in range(7):
            day = week_ago + timedelta(days=i)
            next_day = day + timedelta(days=1)
            
            day_files = [f for f in files if f.get('created_at') and \
                        day <= datetime.fromisoformat(f['created_at']) < next_day]
            
            daily_stats.append({
                'date': day.strftime('%Y-%m-%d'),
                'files': len(day_files),
                'processed': sum(1 for f in day_files if f['status'] == 'success')
            })
        
        return jsonify({
            'total_users': total_users,
            'active_users': active_users,
            'total_files': total_files,
            'processed_files': processed_files,
            'error_files': error_files,
            'processing_files': processing_files,
            'success_rate': success_rate,
            'total_size': format_size(total_size),
            'storage_used': total_size,
            'total_points': total_points,
            'files_by_status': {
                'success': processed_files,
                'error': error_files,
                'processing': processing_files
            },
            'daily_stats': daily_stats
        })
        
    except Exception as e:
        print(f"Erreur lors de la récupération des statistiques admin: {str(e)}")
        if 'disconnected' in str(e).lower():
            if reconnect_supabase():
                # Réessayer une fois après la reconnexion
                return get_admin_stats()
        return jsonify({'error': str(e)}), 500

def format_size(size):
    """Convert size in bytes to human readable string."""
    for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
        if size < 1024.0:
            return f"{size:.1f} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"

@app.route('/api/admin/activity-log', methods=['GET'])
@login_required
@role_required(['admin'])
def get_activity_log():
    """Récupère le journal d'activité pour le tableau de bord admin"""
    try:
        # Récupérer les paramètres de filtrage
        search = request.args.get('search', '').lower()
        activity_type = request.args.get('type', '')
        
        # Récupérer le répertoire de l'admin
        admin_directory = supabase.table('user_access')\
            .select('directory_id')\
            .eq('user_id', session['user_id'])\
            .eq('role_in_dir', 'admin')\
            .single()\
            .execute()
            
        if not admin_directory.data:
            return jsonify({'error': 'Répertoire non trouvé'}), 404
            
        directory_id = admin_directory.data['directory_id']
        
        # Récupérer les utilisateurs du répertoire
        users = supabase.table('user_access')\
            .select('user_id')\
            .eq('directory_id', directory_id)\
            .execute()
            
        user_ids = [user['user_id'] for user in users.data]
        
        # Récupérer les informations des utilisateurs
        users_info = supabase.table('users')\
            .select('*')\
            .in_('id', user_ids)\
            .execute()
            
        if not users_info.data:
            return jsonify([]), 200
            
        # Créer un dictionnaire pour mapper les IDs aux emails
        user_emails = {user['id']: user['email'] for user in users_info.data}
        
        # Récupérer les activités
        query = supabase.table('activity_log')\
            .select('*')\
            .in_('user_id', user_ids)
            
        # Filtrer par type d'activité si spécifié
        if activity_type:
            if activity_type == 'login':
                query = query.in_('action', ['login', 'dashboard_access'])
            else:
                query = query.eq('action', activity_type)
                
        # Trier par date décroissante et limiter le nombre de résultats
        activities = query.order('created_at', desc=True)\
            .limit(50)\
            .execute()
            
        if not activities.data:
            return jsonify([]), 200
            
        # Formater les activités
        formatted_activities = []
        for activity in activities.data:
            # Initialiser les détails
            details = activity.get('details', {})
            
            # Traiter les détails s'ils sont une chaîne JSON
            if isinstance(details, str):
                try:
                    details = json.loads(details)
                except json.JSONDecodeError:
                    details = {'message': details}
            elif details is None:
                details = {}
                
            # Créer l'entrée d'activité
            activity_entry = {
                'id': activity['id'],
                'user_email': user_emails.get(activity['user_id'], 'Système'),
                'action': activity['action'],
                'details': details,
                'created_at': activity['created_at']
            }
            
            # Filtrer par recherche si nécessaire
            if search:
                searchable_text = f"{activity_entry['user_email']} {activity_entry['action']} {str(activity_entry['details'])}".lower()
                if search not in searchable_text:
                    continue
                    
            formatted_activities.append(activity_entry)
            
        return jsonify(formatted_activities)
        
    except Exception as e:
        logger.error(f"Erreur lors de la récupération du journal d'activité: {str(e)}")
        if 'disconnected' in str(e).lower():
            if reconnect_supabase():
                return get_activity_log()
        return jsonify({'error': str(e)}), 500


if __name__ == '__main__':
    app.static_folder = 'static'
    app.static_url_path = '/static'

    mimetypes.add_type('application/javascript', '.js')
    
    # Initialiser le stockage Supabase au démarrage
    init_supabase_storage()
    
    # Configuration du port pour Render
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)

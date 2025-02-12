# Hi-Web

Application web pour la gestion et le traitement de fichiers PDF avec extraction de coordonnées.

## Configuration requise

- Python 3.9.12 ou supérieur
- Base de données Supabase
- Dépendances Python listées dans requirements.txt

## Installation locale

1. Cloner le dépôt :
```bash
git clone <votre-repo>
cd Hi-Web
```

2. Créer un environnement virtuel et l'activer :
```bash
python -m venv venv
source venv/bin/activate  # Linux/Mac
venv\Scripts\activate     # Windows
```

3. Installer les dépendances :
```bash
pip install -r requirements.txt
```

4. Configurer les variables d'environnement :
```bash
cp .env.example .env
# Éditer .env avec vos configurations
```

5. Lancer l'application :
```bash
flask run
```

## Déploiement sur Render

1. Créer un compte sur [Render](https://render.com)

2. Connecter votre dépôt GitHub à Render

3. Créer un nouveau Web Service et sélectionner votre dépôt

4. Configurer les variables d'environnement dans Render :
   - SUPABASE_URL
   - SUPABASE_KEY
   - SECRET_KEY
   - FLASK_ENV=production

5. Le déploiement se fera automatiquement à chaque push sur la branche principale

## Variables d'environnement

- `SECRET_KEY` : Clé secrète pour Flask
- `SUPABASE_URL` : URL de votre projet Supabase
- `SUPABASE_KEY` : Clé d'API Supabase
- `PORT` : Port pour le serveur (défaut: 10000)
- `OUTPUT_FOLDER` : Dossier pour les fichiers de sortie
- `UPLOAD_FOLDER` : Dossier pour les fichiers uploadés

## Structure du projet

```
Hi-Web/
├── app.py              # Application principale Flask
├── requirements.txt    # Dépendances Python
├── gunicorn.conf.py   # Configuration du serveur de production
├── render.yaml        # Configuration pour Render
├── static/            # Fichiers statiques
└── templates/         # Templates HTML
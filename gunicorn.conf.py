import os
import multiprocessing

# Server socket
bind = f"0.0.0.0:{int(os.environ.get('PORT', 10000))}"
backlog = 2048

# Worker processes
workers = int(os.environ.get('WEB_CONCURRENCY', 2))  # Réduit pour éviter la surcharge mémoire
worker_class = 'sync'
threads = int(os.environ.get('PYTHON_MAX_THREADS', 1))
worker_connections = 1000

# Timeouts
timeout = 600  # 10 minutes pour les gros fichiers
graceful_timeout = 300
keepalive = 5

# Memory management
max_requests = 100  # Redémarrer les workers plus souvent
max_requests_jitter = 10
worker_tmp_dir = '/dev/shm'  # Utiliser la mémoire pour les fichiers temporaires

# Logging
accesslog = '-'
errorlog = '-'
loglevel = 'info'
capture_output = True
enable_stdio_inheritance = True

# Process naming
proc_name = 'hi-web-gunicorn'

# Reload code on change (development only)
reload = os.environ.get('FLASK_ENV') == 'development'

# Server mechanics
preload_app = True
daemon = False
pidfile = None
umask = 0
user = None
group = None
tmp_upload_dir = None

# SSL configuration
ssl_version = 'TLS'
cert_reqs = 0  # ssl.CERT_NONE

def worker_int(worker):
    """Called when a worker receives SIGINT or SIGTERM."""
    worker.log.info("worker received INT or TERM signal")

def pre_fork(server, worker):
    """Called just before a worker is forked."""
    pass

def post_fork(server, worker):
    """Called just after a worker has been forked."""
    server.log.info("Worker spawned (pid: %s)", worker.pid)

def pre_exec(server):
    """Called just before a new master process is forked."""
    server.log.info("Forked child, re-executing.")

def when_ready(server):
    """Called just after the server is started."""
    server.log.info("Server is ready. Spawning workers")

def worker_abort(worker):
    """Called when a worker received the SIGABRT signal."""
    worker.log.info("worker received SIGABRT signal")

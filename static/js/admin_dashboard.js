// Initialisation des graphiques et des gestionnaires d'événements
document.addEventListener('DOMContentLoaded', function() {
    // Initialiser les graphiques
    initActivityChart();
    initStorageChart();
    
    // Charger les données initiales
    loadAdminStats();
    loadUsers();
    loadFiles();
    loadActivityLog();
    
    // Gestionnaires d'événements pour les filtres
    setupFilters();
    
    // Rafraîchir les données toutes les 5 minutes
    setInterval(loadAdminStats, 300000);
});

// Graphique d'activité
let activityChart = null;
function initActivityChart() {
    const ctx = document.getElementById('activityChart').getContext('2d');
    activityChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: [],
            datasets: []
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                y: {
                    beginAtZero: true,
                    ticks: {
                        precision: 0
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            },
            plugins: {
                title: {
                    display: true,
                    text: 'Activité des 7 derniers jours'
                },
                legend: {
                    position: 'bottom'
                }
            }
        }
    });
    
    // Gestionnaires pour les boutons de période
    const periodButtons = document.getElementById('periodButtons');
    if (periodButtons) {
        periodButtons.querySelectorAll('button').forEach(button => {
            button.addEventListener('click', async function(e) {
                e.preventDefault();
                // Retirer la classe active de tous les boutons
                periodButtons.querySelectorAll('button').forEach(b => b.classList.remove('active'));
                // Ajouter la classe active au bouton cliqué
                this.classList.add('active');
                // Charger les données pour la période sélectionnée
                await loadActivityStats(this.dataset.period);
            });
        });
    }
    
    // Charger les données initiales (7 jours par défaut)
    loadActivityStats('week');
}

// Graphique de statuts des fichiers
let statusChart = null;
function initStorageChart() {
    const ctx = document.getElementById('storageChart').getContext('2d');
    statusChart = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: ['Succès', 'Erreur', 'En cours'],
            datasets: [{
                data: [0, 0, 0],
                backgroundColor: ['#4CAF50', '#f44336', '#2196F3']
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                title: {
                    display: true,
                    text: 'Statuts des fichiers'
                },
                legend: {
                    display: true,
                    position: 'bottom'
                }
            }
        }
    });
}

// Chargement des statistiques
async function loadAdminStats() {
    try {
        const response = await fetch('/api/admin/stats');
        const data = await response.json();
        
        if (response.ok) {
            // Mettre à jour les compteurs
            document.getElementById('total_users').textContent = data.total_users;
            document.getElementById('success_rate').textContent = `${(data.success_rate || 0).toFixed(1)}%`;
            document.getElementById('error_files').textContent = data.files_by_status?.error || '0';
            document.getElementById('total_files').textContent = data.total_files;
            
            // Mettre à jour le graphique de statuts
            if (data.files_by_status && statusChart) {  
                statusChart.data.datasets[0].data = [
                    data.files_by_status.success || 0,
                    data.files_by_status.error || 0,
                    data.files_by_status.processing || 0
                ];
                statusChart.update();
            }
        }
    } catch (error) {
        console.error('Erreur lors du chargement des statistiques:', error);
    }
}

// Chargement des statistiques d'activité
async function loadActivityStats(period = 'week') {
    try {
        console.log('Chargement des statistiques pour la période:', period);
        
        // S'assurer que period est soit 'week' soit 'month'
        if (period !== 'week' && period !== 'month') {
            console.error('Période invalide:', period);
            period = 'week'; // Valeur par défaut
        }
        
        const response = await fetch(`/api/admin/activity-stats?period=${period}`);
        console.log('Réponse du serveur:', response.status);
        
        if (!response.ok) {
            throw new Error(`Erreur HTTP: ${response.status}`);
        }
        
        const data = await response.json();
        console.log('Données reçues:', data);
        
        if (!data.labels || !data.datasets) {
            throw new Error('Format de données invalide');
        }
        
        // Formater les dates pour l'affichage
        const formattedLabels = data.labels.map(date => {
            const d = new Date(date);
            return d.toLocaleDateString('fr-FR', {
                day: '2-digit',
                month: '2-digit'
            });
        });
        
        // Mettre à jour le graphique
        activityChart.data.labels = formattedLabels;
        activityChart.data.datasets = data.datasets.map(dataset => ({
            ...dataset,
            borderWidth: 2,
            tension: 0.4
        }));
        
        // Configuration spécifique selon la période
        const title = period === 'week' ? 'Activité des 7 derniers jours' : 'Activité des 30 derniers jours';
        activityChart.options.plugins.title.text = title;
        
        activityChart.update();
        console.log('Graphique mis à jour avec succès');
    } catch (error) {
        console.error('Erreur lors du chargement des statistiques d\'activité:', error);
        // Réinitialiser le graphique en cas d'erreur
        if (activityChart) {
            activityChart.data.labels = [];
            activityChart.data.datasets = [];
            activityChart.update();
        }
    }
}

// Gestion des utilisateurs
async function loadUsers() {
    try {
        const response = await fetch('/api/admin/users');
        const users = await response.json();
        
        if (response.ok) {
            const tbody = document.querySelector('#users table tbody');
            tbody.innerHTML = '';
            
            users.forEach(user => {
                const tr = document.createElement('tr');
                tr.innerHTML = `
                    <td><input type="checkbox" class="form-check-input user-select" value="${user.id}"></td>
                    <td>${user.email}</td>
                    <td>${user.processed_files}</td>
                    <td>${user.storage_used}</td>
                    <td>${formatDate(user.last_activity)}</td>
                    <td>
                        <div class="btn-group">
                            <button class="btn btn-sm btn-outline-primary" onclick="viewUserDetails('${user.id}')" title="Voir les détails">
                                <i class="bi bi-eye"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-primary" onclick="editUser('${user.id}')" title="Modifier">
                                <i class="bi bi-pencil"></i>
                            </button>
                            <button class="btn btn-sm btn-outline-${user.is_active ? 'danger' : 'success'}" 
                                    onclick="toggleUserStatus('${user.id}')"
                                    title="${user.is_active ? 'Désactiver' : 'Activer'}">
                                <i class="bi bi-${user.is_active ? 'person-x' : 'person-check'}"></i>
                            </button>
                        </div>
                    </td>
                `;
                tbody.appendChild(tr);
            });
        }
    } catch (error) {
        console.error('Erreur lors du chargement des utilisateurs:', error);
    }
}

let allFiles = [];

// Gestion des fichiers
async function loadFiles() {
    try {
        const response = await fetch('/api/admin/files');
        if (!response.ok) {
            throw new Error('Erreur lors du chargement des fichiers');
        }
        const files = await response.json();
        allFiles = files; // Stocker les fichiers pour le filtrage
        displayFiles(files);
    } catch (error) {
        console.error('Erreur lors du chargement des fichiers:', error);
        // Afficher un message d'erreur à l'utilisateur
        const filesContainer = document.querySelector('#files .table tbody');
        if (filesContainer) {
            filesContainer.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-danger">
                        <i class="bi bi-exclamation-triangle me-2"></i>
                        Erreur lors du chargement des fichiers
                    </td>
                </tr>
            `;
        }
    }
}

function displayFiles(files) {
    const tbody = document.querySelector('#files .table tbody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!files || files.length === 0) {
        tbody.innerHTML = `
            <tr>
                <td colspan="6" class="text-center">
                    Aucun fichier trouvé
                </td>
            </tr>
        `;
        return;
    }
    
    files.forEach(file => {
        const tr = document.createElement('tr');
        
        // Déterminer les boutons d'action en fonction du type de fichier
        let actionButtons = '';
        
        if (file.type === 'pdf') {
            actionButtons = `
                <a href="/api/admin/files/${file.id}/download" 
                   class="btn btn-sm btn-outline-primary"
                   title="Télécharger PDF"
                   download>
                    <i class="bi bi-file-pdf"></i>
                </a>
            `;
            
            // Ajouter le bouton CSV si le PDF est complété
            if (file.status === 'completed') {
                actionButtons += `
                    <a href="/api/admin/files/${file.id}/download-csv" 
                       class="btn btn-sm btn-outline-success ms-1"
                       title="Télécharger CSV"
                       download>
                        <i class="bi bi-file-earmark-spreadsheet"></i>
                    </a>
                `;
            }
        } else if (file.type === 'csv') {
            // Pour les fichiers CSV, utiliser l'URL signée si disponible
            if (file.download_url) {
                actionButtons = `
                    <a href="${file.download_url}" 
                       class="btn btn-sm btn-outline-success"
                       title="Télécharger CSV"
                       target="_blank"
                       download>
                        <i class="bi bi-file-earmark-spreadsheet"></i>
                    </a>
                `;
            }
        }
        
        tr.innerHTML = `
            <td>${file.name || 'Sans nom'}</td>
            <td>${file.users?.email || 'Inconnu'}</td>
            <td>
                <span class="badge ${getStatusBadgeClass(file.status)}">
                    ${getStatusLabel(file.status)}
                </span>
            </td>
            <td>${file.formatted_size || '0 B'}</td>
            <td>${formatDate(file.created_at)}</td>
            <td>
                <div class="btn-group">
                    ${actionButtons}
                </div>
            </td>
        `;
        
        tbody.appendChild(tr);
    });
}

// Recherche et filtrage des fichiers
document.getElementById('fileSearch')?.addEventListener('input', (e) => {
    const searchTerm = e.target.value.toLowerCase();
    const typeFilter = document.getElementById('fileTypeFilter').value;
    filterFiles(searchTerm, typeFilter);
});

document.getElementById('fileTypeFilter')?.addEventListener('change', (e) => {
    const searchTerm = document.getElementById('fileSearch').value.toLowerCase();
    const typeFilter = e.target.value;
    filterFiles(searchTerm, typeFilter);
});

function filterFiles(searchTerm, typeFilter) {
    let filteredFiles = allFiles;
    
    if (searchTerm) {
        filteredFiles = filteredFiles.filter(file => 
            (file.name || '').toLowerCase().includes(searchTerm) ||
            (file.users?.email || '').toLowerCase().includes(searchTerm)
        );
    }
    
    if (typeFilter) {
        filteredFiles = filteredFiles.filter(file => 
            file.type === typeFilter
        );
    }
    
    displayFiles(filteredFiles);
}

// Journal d'activité
async function loadActivityLog() {
    try {
        const searchTerm = document.getElementById('activitySearch')?.value || '';
        const activityType = document.getElementById('activityTypeFilter')?.value || '';
        
        const queryParams = new URLSearchParams({
            search: searchTerm,
            type: activityType
        });
        
        const response = await fetch(`/api/admin/activity-log?${queryParams}`);
        const activities = await response.json();
        
        if (response.ok) {
            displayActivities(activities);
        }
    } catch (error) {
        console.error('Erreur lors du chargement du journal d\'activité:', error);
    }
}

function displayActivities(activities) {
    const tbody = document.getElementById('activityTableBody');
    if (!tbody) return;
    
    tbody.innerHTML = '';
    
    if (!activities || activities.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td colspan="4" class="text-center">Aucune activité trouvée</td>';
        tbody.appendChild(tr);
        return;
    }
    
    activities.forEach(activity => {
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${formatDate(activity.created_at)}</td>
            <td>${activity.user_email || 'Système'}</td>
            <td><span class="badge ${getActivityBadgeClass(activity.action)}">${formatActivityType(activity.action)}</span></td>
            <td>${formatActivityDetails(activity.details)}</td>
        `;
        tbody.appendChild(tr);
    });
}

function formatActivityType(type) {
    const types = {
        'login': 'Connexion au système',
        'dashboard_access': 'Accès au tableau de bord',
        'file_process_start': 'Début du traitement de fichier',
        'file_process_success': 'Traitement de fichier réussi',
        'file_process_error': 'Erreur de traitement'
    };
    return types[type] || type;
}

function getActivityBadgeClass(type) {
    const classes = {
        'login': 'bg-success',
        'dashboard_access': 'bg-success',
        'file_process_start': 'bg-primary',
        'file_process_success': 'bg-warning',
        'file_process_error': 'bg-danger'
    };
    return classes[type] || 'bg-secondary';
}

function formatActivityDetails(details) {
    if (!details) return '-';
    if (typeof details === 'string') {
        try {
            details = JSON.parse(details);
        } catch {
            return details || '-';
        }
    }
    
    if (typeof details === 'object') {
        // Pour les activités de fichiers
        if (details.filename) {
            const status = details.status ? ` (${details.status})` : '';
            return `Fichier "${details.filename}"${status}`;
        }
        
        // Pour les erreurs
        if (details.error) {
            return `Erreur : ${details.error}`;
        }
        
        // Pour les messages simples
        if (details.message) {
            return details.message;
        }
        
        // Pour les connexions
        if (details.ip) {
            return `Connexion depuis ${details.ip}`;
        }
        
        // Pour les autres cas
        const entries = Object.entries(details);
        if (entries.length > 0) {
            return entries.map(([key, value]) => `${key}: ${value}`).join(', ');
        }
    }
    
    return '-';
}

// Configuration des filtres
function setupFilters() {
    // Filtres utilisateurs
    const userSearch = document.getElementById('userSearch');
    const statusFilter = document.getElementById('statusFilter');
    
    if (userSearch) {
        userSearch.addEventListener('input', debounce(() => {
            filterUsers(userSearch.value, statusFilter?.value);
        }, 300));
    }
    
    if (statusFilter) {
        statusFilter.addEventListener('change', function() {
            filterUsers(userSearch?.value || '', this.value);
        });
    }
    
    // Filtres fichiers
    const fileSearch = document.getElementById('fileSearch');
    const fileTypeFilter = document.getElementById('fileTypeFilter');
    
    if (fileSearch) {
        fileSearch.addEventListener('input', debounce(() => {
            filterFiles(fileSearch.value, fileTypeFilter?.value);
        }, 300));
    }
    
    if (fileTypeFilter) {
        fileTypeFilter.addEventListener('change', function() {
            filterFiles(fileSearch?.value || '', this.value);
        });
    }
    
    // Filtre de recherche d'activité
    const activitySearch = document.getElementById('activitySearch');
    const activityTypeFilter = document.getElementById('activityTypeFilter');
    
    if (activitySearch) {
        activitySearch.addEventListener('input', debounce(() => loadActivityLog(), 300));
    }
    
    if (activityTypeFilter) {
        activityTypeFilter.addEventListener('change', () => loadActivityLog());
    }
}

// Fonction debounce pour limiter les appels aux fonctions de filtrage
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Fonctions de filtrage
function filterUsers(search, status) {
    const rows = document.querySelectorAll('#users table tbody tr');
    rows.forEach(row => {
        const email = row.cells[1].textContent.toLowerCase();
        const matchSearch = !search || email.includes(search.toLowerCase());
        row.style.display = matchSearch ? '' : 'none';
    });
}

function filterActivities(search, type) {
    const rows = document.querySelectorAll('#activity table tbody tr');
    rows.forEach(row => {
        const activityText = row.cells[3].textContent.toLowerCase();
        const activityType = row.cells[2].textContent.toLowerCase();
        const matchSearch = !search || activityText.includes(search.toLowerCase());
        const matchType = !type || activityType === type.toLowerCase();
        row.style.display = matchSearch && matchType ? '' : 'none';
    });
}

// Export de données
async function exportData() {
    const type = document.getElementById('exportType').value;
    const format = document.getElementById('exportFormat').value;
    const period = document.getElementById('exportPeriod').value;
    
    try {
        const response = await fetch(`/api/admin/${type}/export`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ format, period })
        });
        
        if (response.ok) {
            const blob = await response.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = `${type}_export_${new Date().toISOString().split('T')[0]}.${format}`;
            document.body.appendChild(a);
            a.click();
            window.URL.revokeObjectURL(url);
            a.remove();
        }
    } catch (error) {
        console.error('Erreur lors de l\'export:', error);
        alert('Une erreur est survenue lors de l\'export des données');
    }
}

// Fonctions pour gérer les statuts des fichiers
function getStatusBadgeClass(status) {
    switch (status) {
        case 'completed':
            return 'bg-success';
        case 'failed':
            return 'bg-danger';
        default:
            return 'bg-secondary';
    }
}

function getStatusLabel(status) {
    switch (status) {
        case 'completed':
            return 'Terminé';
        case 'failed':
            return 'Échoué';
        default:
            return 'En cours';
    }
}

function formatDate(dateString) {
    if (!dateString) return 'Jamais';
    const date = new Date(dateString);
    return date.toLocaleString();
}

function formatActivityType(type) {
    const types = {
        'login': 'Connexion',
        'upload': 'Upload',
        'process': 'Traitement'
    };
    return types[type] || type;
}

function formatActivityDetails(details) {
    if (!details) return '';
    try {
        const data = JSON.parse(details);
        return data.message || JSON.stringify(data);
    } catch {
        return details;
    }
}
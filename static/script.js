document.addEventListener('DOMContentLoaded', function() {
    // Récupération des éléments DOM
    const folderInput = document.getElementById('folderInput');
    const fileInput = document.getElementById('fileInput');
    const startButton = document.getElementById('startButton');
    const clearButton = document.getElementById('clearButton');
    const searchInput = document.getElementById('searchInput');
    const columnFilter = document.getElementById('columnFilter');
    const sortButton = document.getElementById('sortButton');
    const resultsTable = document.getElementById('resultsTable');
    
    let results = [];
    let sortDirection = 'none';
    
    // Fonction pour charger les fichiers depuis le serveur
    async function loadFiles() {
        try {
            const response = await fetch('/api/files');
            if (!response.ok) {
                throw new Error(`Erreur HTTP! statut: ${response.status}`);
            }
            const data = await response.json();
            results = data.files || [];
            updateTable();
            updateStatistics();
        } catch (error) {
            console.error('Erreur lors du chargement des fichiers:', error);
        }
    }
    
    // Charger les fichiers au démarrage
    loadFiles();
    
    // File Input Handler
    if (fileInput) {
        fileInput.addEventListener('change', async function(e) {
            const files = Array.from(this.files);
            if (files.length === 0) return;
            
            const formData = new FormData();
            for (let file of files) {
                formData.append('file', file);
            }
            
            try {
                showProcessingStatus(true);
                const response = await fetch('/api/files/upload', {
                    method: 'POST',
                    body: formData
                });
                
                if (!response.ok) {
                    throw new Error(`Erreur HTTP! statut: ${response.status}`);
                }
                
                const data = await response.json();
                console.log('Fichier uploadé:', data);
                
                // Traiter le fichier
                if (data.file_id) {
                    const processResponse = await fetch(`/api/files/${data.file_id}/process`, {
                        method: 'POST'
                    });
                    
                    if (!processResponse.ok) {
                        throw new Error(`Erreur lors du traitement! statut: ${processResponse.status}`);
                    }
                    
                    // Recharger la liste des fichiers
                    await loadFiles();
                }
                
                showProcessingStatus(false);
                this.value = ''; // Réinitialiser l'input
            } catch (error) {
                console.error('Erreur:', error);
                alert('Une erreur est survenue: ' + error.message);
                showProcessingStatus(false);
            }
        });
    }
    
    // Fonction de mise à jour du tableau
    function updateTable() {
        const tbody = resultsTable.querySelector('tbody');
        const searchText = searchInput ? searchInput.value.toLowerCase() : '';
        
        let filteredResults = [...results];
        
        // Appliquer le filtre de recherche
        if (searchText) {
            filteredResults = filteredResults.filter(result => 
                result.filename.toLowerCase().includes(searchText)
            );
        }
        
        // Appliquer le tri
        if (sortDirection !== 'none') {
            filteredResults.sort((a, b) => {
                const aValue = String(a.filename);
                const bValue = String(b.filename);
                return sortDirection === 'asc' 
                    ? aValue.localeCompare(bValue)
                    : bValue.localeCompare(aValue);
            });
        }
        
        tbody.innerHTML = filteredResults.map(result => `
            <tr>
                <td>${result.filename}</td>
                <td>${new Date(result.created_at).toLocaleString()}</td>
                <td>${result.status}</td>
                <td>${result.points || '-'}</td>
                <td>
                    ${result.status === 'processed' 
                        ? `<button class="btn btn-sm btn-primary" onclick="window.location.href='/api/files/${result.id}/download'">
                             <i class="bi bi-download"></i> CSV
                           </button>`
                        : result.status === 'error'
                        ? `<span class="text-danger">${result.error_message || 'Erreur'}</span>`
                        : result.status === 'processing'
                        ? '<span class="spinner-border spinner-border-sm" role="status"></span>'
                        : '-'}
                </td>
            </tr>
        `).join('');
    }
    
    // Fonction de mise à jour des statistiques
    function updateStatistics() {
        const totalFiles = results.length;
        const successfulFiles = results.filter(r => r.status === 'processed').length;
        const totalPoints = results.reduce((sum, r) => sum + (parseInt(r.points) || 0), 0);
        const successRate = totalFiles > 0 ? (successfulFiles / totalFiles * 100).toFixed(1) : 0;
        
        const statsElements = {
            totalFiles: document.getElementById('totalFiles'),
            successfulFiles: document.getElementById('successfulFiles'),
            totalPoints: document.getElementById('totalPoints'),
            successRate: document.getElementById('successRate')
        };
        
        if (statsElements.totalFiles) statsElements.totalFiles.textContent = totalFiles;
        if (statsElements.successfulFiles) statsElements.successfulFiles.textContent = successfulFiles;
        if (statsElements.totalPoints) statsElements.totalPoints.textContent = totalPoints;
        if (statsElements.successRate) statsElements.successRate.textContent = `${successRate}%`;
    }
    
    // Event Listeners pour la recherche
    if (searchInput) {
        searchInput.addEventListener('input', updateTable);
    }
    
    // Event Listener pour le tri
    if (sortButton) {
        sortButton.addEventListener('click', function() {
            const icon = this.querySelector('i');
            if (sortDirection === 'none' || sortDirection === 'desc') {
                sortDirection = 'asc';
                icon.className = 'bi bi-sort-down';
            } else {
                sortDirection = 'desc';
                icon.className = 'bi bi-sort-up';
            }
            updateTable();
        });
    }
    
    // Rafraîchir la liste toutes les 10 secondes si des fichiers sont en cours de traitement
    setInterval(() => {
        if (results.some(r => r.status === 'processing')) {
            loadFiles();
        }
    }, 10000);
});

function showProcessingStatus(show) {
    const status = document.getElementById('processingStatus');
    if (status) {
        status.style.display = show ? 'block' : 'none';
    }
}

// Fonction pour basculer le thème
function toggleTheme() {
    const html = document.documentElement;
    const currentTheme = html.getAttribute('data-bs-theme');
    const newTheme = currentTheme === 'dark' ? 'light' : 'dark';
    html.setAttribute('data-bs-theme', newTheme);
    localStorage.setItem('theme', newTheme);
}

// Charger le thème sauvegardé
const savedTheme = localStorage.getItem('theme');
if (savedTheme) {
    document.documentElement.setAttribute('data-bs-theme', savedTheme);
}

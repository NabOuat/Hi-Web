// Variables globales
const selectedFiles = new Map();
const processedResults = new Map();
let processing = false;

// Initialisation
document.addEventListener('DOMContentLoaded', function() {
    // Charger les statistiques initiales
    loadProfileAndStats();

    // Écouter les changements de fichiers
    const folderInput = document.getElementById('folderInput');
    if (folderInput) {
        folderInput.addEventListener('change', (e) => handleFiles(e.target.files));
    }

    // Écouter les clics sur les boutons
    const startButton = document.getElementById('startButton');
    if (startButton) {
        startButton.addEventListener('click', startProcessing);
    }

    const clearButton = document.getElementById('clearButton');
    if (clearButton) {
        clearButton.addEventListener('click', clearSelection);
    }

    // Écouter les changements de filtres
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
        searchInput.addEventListener('input', updateUI);
    }

    const statusFilter = document.getElementById('statusFilter');
    if (statusFilter) {
        statusFilter.addEventListener('change', updateUI);
    }
});

// Traitement des fichiers
function handleFiles(files) {
    console.log('Traitement des fichiers:', files);
    
    // Réinitialiser si nécessaire
    if (files.length === 0) {
        selectedFiles.clear();
        processedResults.clear();
        updateUI();
        return;
    }

    // Parcourir les fichiers
    Array.from(files).forEach(file => {
        if (file.name.toLowerCase() === 'plan.pdf') {
            const fullPath = file.webkitRelativePath || file.name;
            const folderPath = fullPath.substring(0, fullPath.lastIndexOf('/')) || fullPath;
            
            console.log('Ajout du fichier:', folderPath);
            selectedFiles.set(folderPath, {
                file: file,
                path: fullPath,
                size: file.size,
                startTime: Date.now()
            });
        }
    });
    
    updateUI();
    updateButtons();
}

// Mise à jour de l'interface
function updateUI() {
    const fileList = document.getElementById('fileList');
    if (!fileList) return;

    const searchTerm = document.getElementById('searchInput')?.value.toLowerCase() || '';
    const statusFilter = document.getElementById('statusFilter')?.value || 'all';

    fileList.innerHTML = '';
    let processedCount = 0;
    let errorCount = 0;
    let pendingCount = selectedFiles.size;

    selectedFiles.forEach((fileData, folderPath) => {
        // Appliquer les filtres
        if (searchTerm && !folderPath.toLowerCase().includes(searchTerm)) return;
        
        const result = processedResults.get(folderPath);
        const status = result ? result.status : 'pending';
        
        if (statusFilter !== 'all' && status !== statusFilter) return;

        // Mettre à jour les compteurs
        if (result) {
            if (result.status === 'success') {
                processedCount++;
                pendingCount--;
            } else if (result.status === 'error') {
                errorCount++;
                pendingCount--;
            }
        }

        // Créer la ligne
        const tr = document.createElement('tr');
        tr.innerHTML = `
            <td>${folderPath}</td>
            <td>${result?.points || '-'}</td>
            <td>${result ? formatProcessingTime(fileData.startTime) : '-'}</td>
            <td>
                <span class="badge bg-${getBadgeColor(status)}">
                    ${getStatusText(status)}
                </span>
            </td>
            <td class="text-end">
                ${result?.status === 'success' ? `
                    <div class="action-buttons">
                        <button class="btn btn-primary btn-download me-2" onclick="downloadCSV('${result.fileId}')" title="Télécharger le fichier CSV">
                            <i class="bi bi-download"></i>
                            <span>CSV</span>
                        </button>
                        <button class="btn btn-success btn-download" onclick="downloadBoth('${result.fileId}')" title="Télécharger CSV et PDF">
                            <i class="bi bi-file-earmark-arrow-down"></i>
                            <span>CSV/PDF</span>
                        </button>
                    </div>
                ` : ''}
            </td>
        `;
        fileList.appendChild(tr);
    });

    // Mettre à jour les statistiques
    updateStats(processedCount, errorCount, pendingCount);
}

// Mise à jour des boutons
function updateButtons() {
    const startButton = document.getElementById('startButton');
    const clearButton = document.getElementById('clearButton');
    
    if (startButton) {
        startButton.disabled = selectedFiles.size === 0 || processing;
    }
    
    if (clearButton) {
        clearButton.disabled = selectedFiles.size === 0 || processing;
    }
}

// Lancer le traitement
async function startProcessing() {
    console.log('Démarrage du traitement...');
    const startButton = document.getElementById('startButton');
    const clearButton = document.getElementById('clearButton');
    const modal = new bootstrap.Modal(document.getElementById('processingModal'));
    const progressBar = document.getElementById('progressBar');
    const processingFile = document.getElementById('processingFile');

    if (selectedFiles.size === 0) {
        showMessage('Aucun fichier sélectionné', 'warning');
        return;
    }

    try {
        processing = true;
        startButton.innerHTML = '<i class="bi bi-stop-fill me-1"></i>Arrêter';
        startButton.classList.remove('btn-success');
        startButton.classList.add('btn-danger');
        clearButton.disabled = true;

        modal.show();
        let processed = 0;
        const total = selectedFiles.size;

        for (const [folderPath, data] of selectedFiles) {
            if (!processing) {
                console.log('Traitement annulé');
                break;
            }

            try {
                processingFile.textContent = `Traitement de : ${data.path}`;
                progressBar.style.width = `${(processed / total) * 100}%`;
                progressBar.setAttribute('aria-valuenow', Math.round((processed / total) * 100));

                // Créer un FormData avec le fichier et le nom du dossier
                const formData = new FormData();
                formData.append('file', data.file);
                formData.append('folderName', folderPath.split('/').pop() || folderPath);

                console.log('Envoi de la requête...', data.path);
                const response = await fetch('/api/process', {
                    method: 'POST',
                    body: formData
                });

                const result = await response.json();
                console.log('Résultat reçu:', result);

                if (!response.ok || result.status === 'error') {
                    throw new Error(result.error || `Erreur HTTP: ${response.status}`);
                }

                processedResults.set(folderPath, {
                    status: result.status,
                    points: result.points || 0,
                    time: (Date.now() - data.startTime) / 1000,
                    fileId: result.file_id
                });

                // Mettre à jour les statistiques après chaque fichier traité
                await updateStatsAfterProcessing(result);
                
                showMessage(`Fichier ${data.path} traité avec succès`, 'success');

            } catch (error) {
                console.error(`Erreur lors du traitement de ${data.path}:`, error);
                processedResults.set(folderPath, {
                    status: 'error',
                    error: error.message
                });
                
                // Mettre à jour les statistiques même en cas d'erreur
                await updateStatsAfterProcessing({ status: 'error' });
                
                showMessage(`Erreur lors du traitement de ${data.path}: ${error.message}`, 'danger');
            }

            processed++;
            updateUI();
        }

        if (processing) {
            showMessage('Traitement terminé avec succès', 'success');
        } else {
            showMessage('Traitement annulé', 'info');
        }

    } catch (error) {
        console.error('Erreur globale:', error);
        showMessage('Une erreur est survenue pendant le traitement', 'danger');
    } finally {
        processing = false;
        modal.hide();
        startButton.innerHTML = '<i class="bi bi-play-fill me-1"></i>Lancer le traitement';
        startButton.classList.remove('btn-danger');
        startButton.classList.add('btn-success');
        clearButton.disabled = false;
        
        // Mise à jour finale des statistiques
        await loadProfileAndStats();
        updateUI();
    }
}

// Effacer la sélection
function clearSelection() {
    console.log('Effacement de la sélection...');
    if (processing) {
        showMessage('Impossible d\'effacer pendant le traitement', 'warning');
        return;
    }

    selectedFiles.clear();
    processedResults.clear();
    const folderInput = document.getElementById('folderInput');
    if (folderInput) {
        folderInput.value = '';
    }
    updateUI();
    showMessage('Sélection effacée', 'info');
}

// Fonctions utilitaires
function getBadgeColor(status) {
    switch (status) {
        case 'success': return 'success';
        case 'error': return 'danger';
        default: return 'secondary';
    }
}

function getStatusText(status) {
    switch (status) {
        case 'success': return 'Succès';
        case 'error': return 'Erreur';
        default: return 'En attente';
    }
}

function formatProcessingTime(startTime) {
    const elapsed = Date.now() - startTime;
    if (elapsed < 1000) return '< 1s';
    return `${Math.round(elapsed / 1000)}s`;
}

// Afficher un message
function showMessage(message, type = 'info') {
    // Créer le toast
    const toast = document.createElement('div');
    toast.className = `toast align-items-center text-white bg-${type} border-0`;
    toast.setAttribute('role', 'alert');
    toast.setAttribute('aria-live', 'assertive');
    toast.setAttribute('aria-atomic', 'true');
    
    toast.innerHTML = `
        <div class="d-flex">
            <div class="toast-body">${message}</div>
            <button type="button" class="btn-close btn-close-white me-2 m-auto" data-bs-dismiss="toast" aria-label="Close"></button>
        </div>
    `;
    
    // Ajouter à la page
    const container = document.getElementById('toast-container') || document.body;
    container.appendChild(toast);
    
    // Afficher le toast
    const bsToast = new bootstrap.Toast(toast);
    bsToast.show();
    
    // Supprimer après la fermeture
    toast.addEventListener('hidden.bs.toast', () => {
        toast.remove();
    });
}

// Initialisation des tooltips
function initializeTooltips() {
    const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
    tooltipTriggerList.map(function (tooltipTriggerEl) {
        return new bootstrap.Tooltip(tooltipTriggerEl);
    });
}

// Initialisation de la zone de drop
function initializeDropZone() {
    const dropZone = document.querySelector('.upload-zone');
    const folderInput = document.getElementById('folderInput');

    if (dropZone && folderInput) {
        ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, preventDefaults, false);
        });

        ['dragenter', 'dragover'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.add('border-primary');
                dropZone.classList.add('bg-primary-subtle');
            }, false);
        });

        ['dragleave', 'drop'].forEach(eventName => {
            dropZone.addEventListener(eventName, () => {
                dropZone.classList.remove('border-primary');
                dropZone.classList.remove('bg-primary-subtle');
            }, false);
        });

        dropZone.addEventListener('drop', handleDrop, false);
        folderInput.addEventListener('change', handleFolderSelection);
    }
}

// Initialisation des filtres
function initializeFilters() {
    const searchInput = document.getElementById('searchInput');
    const statusFilter = document.getElementById('statusFilter');

    if (searchInput) {
        searchInput.addEventListener('input', updateFilters);
    }

    if (statusFilter) {
        statusFilter.addEventListener('change', updateFilters);
    }
}

// Mise à jour des filtres
function updateFilters() {
    const searchTerm = document.getElementById('searchInput')?.value.toLowerCase() || '';
    const statusFilter = document.getElementById('statusFilter')?.value || 'all';
    updateTable(searchTerm, statusFilter);
}

// Empêcher le comportement par défaut
function preventDefaults(e) {
    e.preventDefault();
    e.stopPropagation();
}

// Gestion du drop
function handleDrop(e) {
    const items = e.dataTransfer.items;
    if (items) {
        for (let i = 0; i < items.length; i++) {
            const item = items[i];
            if (item.kind === 'file' && item.webkitGetAsEntry) {
                const entry = item.webkitGetAsEntry();
                if (entry.isDirectory) {
                    processDirectory(entry);
                }
            }
        }
    }
}

// Traitement d'un dossier
async function processDirectory(entry) {
    const files = await readDirectoryEntries(entry);
    handleFiles(files);
}

// Lecture récursive des entrées d'un dossier
async function readDirectoryEntries(entry) {
    const files = [];
    const reader = entry.createReader();

    const readEntries = () => {
        return new Promise((resolve, reject) => {
            reader.readEntries(entries => {
                if (!entries.length) {
                    resolve([]);
                } else {
                    Promise.all(entries.map(entry => {
                        if (entry.isFile) {
                            return new Promise(resolve => {
                                entry.file(file => {
                                    file.relativePath = entry.fullPath;
                                    resolve(file);
                                });
                            });
                        } else if (entry.isDirectory) {
                            return readDirectoryEntries(entry);
                        }
                    })).then(resolve);
                }
            }, reject);
        });
    };

    let entries = [];
    let results;
    do {
        results = await readEntries();
        entries = entries.concat(results);
    } while (results.length > 0);

    return entries.flat();
}

// Gestion de la sélection de dossier
function handleFolderSelection(event) {
    const files = Array.from(event.target.files);
    handleFiles(files);
}

// Téléchargement des fichiers
async function downloadFile(fileId, type) {
    try {
        console.log(`Téléchargement du fichier ${fileId} de type ${type}`);
        const response = await fetch(`/api/files/${fileId}/download?type=${type}`, {
            method: 'GET',
            headers: {
                'Accept': type === 'csv' ? 'text/csv' : 'application/pdf',
                'X-Requested-With': 'XMLHttpRequest'
            },
            credentials: 'same-origin'
        });

        if (!response.ok) {
            throw new Error(`Erreur HTTP: ${response.status}`);
        }

        // Récupérer le nom du fichier depuis l'en-tête Content-Disposition
        const contentDisposition = response.headers.get('Content-Disposition');
        const filename = contentDisposition
            ? contentDisposition.split('filename=')[1].replace(/"/g, '')
            : `file.${type}`;

        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = filename;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
        
        console.log(`Téléchargement réussi pour ${filename}`);
    } catch (error) {
        console.error('Erreur lors du téléchargement:', error);
        showMessage(`Erreur lors du téléchargement du fichier ${type.toUpperCase()}: ${error.message}`, 'error');
    }
}

// Fonction pour télécharger les deux fichiers
async function downloadBoth(fileId) {
    try {
        await downloadFile(fileId, 'pdf');
        setTimeout(async () => {
            await downloadFile(fileId, 'csv');
        }, 1000); // Attendre 1 seconde entre les téléchargements
    } catch (error) {
        console.error('Erreur lors du téléchargement:', error);
        showMessage('Erreur lors du téléchargement des fichiers', 'error');
    }
}

// Fonction pour télécharger uniquement le PDF
async function downloadPDF(fileId) {
    await downloadFile(fileId, 'pdf');
}

// Fonction pour télécharger uniquement le CSV
async function downloadCSV(fileId) {
    await downloadFile(fileId, 'csv');
}

// Charger les statistiques utilisateur
async function loadProfileAndStats() {
    try {
        const response = await fetch('/api/stats/user');
        if (!response.ok) {
            throw new Error('Erreur lors du chargement des statistiques');
        }
        
        const stats = await response.json();
        
        // Mettre à jour l'interface avec les statistiques
        document.getElementById('processed_files').textContent = stats.processed_files || 0;
        document.getElementById('error_files').textContent = stats.error_files || 0;
        document.getElementById('pending_files').textContent = stats.pending_files || 0;
        
        // Calculer et afficher le taux de succès
        const successRate = stats.success_rate || 0;
        document.getElementById('success_rate').textContent = `${successRate.toFixed(1)}%`;
        
    } catch (error) {
        console.error('Erreur lors du chargement des statistiques:', error);
        document.getElementById('processed_files').textContent = '0';
        document.getElementById('error_files').textContent = '0';
        document.getElementById('pending_files').textContent = '0';
        document.getElementById('success_rate').textContent = '0.0%';
    }
}

// Mise à jour des statistiques après le traitement d'un fichier
async function updateStatsAfterProcessing(result) {
    try {
        // Recharger les statistiques depuis le serveur
        await loadProfileAndStats();
        
        // Mettre à jour le tableau des fichiers si présent
        if (typeof updateTable === 'function') {
            updateTable();
        }
    } catch (error) {
        console.error('Erreur lors de la mise à jour des statistiques:', error);
    }
}

// Mise à jour du tableau
function updateTable(searchTerm = '', statusFilter = 'all') {
    const resultsTable = document.getElementById('resultsTable');
    if (!resultsTable) return;

    if (selectedFiles.size === 0 && processedResults.size === 0) {
        resultsTable.innerHTML = `
            <tr>
                <td colspan="5" class="text-center py-5">
                    <div class="text-muted">
                        <i class="bi bi-folder2-open display-4 mb-3" aria-hidden="true"></i>
                        <p class="mb-0" role="status">Sélectionnez un dossier pour commencer</p>
                    </div>
                </td>
            </tr>
        `;
        return;
    }

    const allEntries = new Map([...selectedFiles, ...processedResults]);
    
    const filteredEntries = Array.from(allEntries.entries())
        .filter(([path, data]) => {
            const matchesSearch = !searchTerm || path.toLowerCase().includes(searchTerm);
            const matchesStatus = statusFilter === 'all' || 
                                (statusFilter === 'pending' && !processedResults.has(path)) ||
                                (statusFilter === 'success' && processedResults.has(path) && data.status === 'success') ||
                                (statusFilter === 'error' && processedResults.has(path) && data.status === 'error');
            return matchesSearch && matchesStatus;
        });

    resultsTable.innerHTML = filteredEntries.map(([folderPath, data]) => {
        const isProcessed = processedResults.has(folderPath);
        
        if (isProcessed) {
            const result = processedResults.get(folderPath);
            return `
                <tr>
                    <td class="py-3">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-folder-fill text-primary me-2"></i>
                            <span class="text-break">${folderPath}</span>
                        </div>
                    </td>
                    <td class="py-3">${result.points?.toLocaleString() || '-'}</td>
                    <td class="py-3">${result.time ? result.time.toFixed(1) + 's' : '-'}</td>
                    <td class="py-3">
                        <span class="badge rounded-pill bg-${result.status === 'success' ? 'success' : 'danger'} bg-opacity-75">
                            ${result.status === 'success' ? 'Succès' : 'Erreur'}
                        </span>
                        ${result.error ? `
                            <div class="small text-danger mt-1">
                                <i class="bi bi-exclamation-triangle-fill me-1"></i>
                                ${result.error}
                            </div>
                        ` : ''}
                    </td>
                    <td class="py-3">
                        ${result.status === 'success' && result.fileId ? `
                            <div class="action-buttons">
                                <button class="btn btn-primary btn-download" onclick="downloadCSV('${result.fileId}')" title="Télécharger le fichier CSV">
                                    <i class="bi bi-download"></i>
                                    <span>CSV</span>
                                </button>
                                <button class="btn btn-success btn-download" onclick="downloadBoth('${result.fileId}')" title="Télécharger CSV et PDF">
                                    <i class="bi bi-file-earmark-arrow-down"></i>
                                    <span>CSV/PDF</span>
                                </button>
                            </div>
                        ` : '-'}
                    </td>
                </tr>
            `;
        } else {
            return `
                <tr>
                    <td class="py-3">
                        <div class="d-flex align-items-center">
                            <i class="bi bi-folder-fill text-primary me-2"></i>
                            <span class="text-break">${folderPath}</span>
                        </div>
                    </td>
                    <td class="py-3">-</td>
                    <td class="py-3">-</td>
                    <td class="py-3">
                        <span class="badge rounded-pill bg-secondary bg-opacity-75">En attente</span>
                    </td>
                    <td class="py-3">-</td>
                </tr>
            `;
        }
    }).join('');

    // Réinitialiser les tooltips
    initializeTooltips();
}

// Mise à jour des statistiques
function updateStats(processed, errors, pending) {
    const processedElement = document.getElementById('processed_files');
    const errorElement = document.getElementById('error_files');
    const pendingElement = document.getElementById('pending_files');
    const successRateElement = document.getElementById('success_rate');

    if (processedElement) processedElement.textContent = processed;
    if (errorElement) errorElement.textContent = errors;
    if (pendingElement) pendingElement.textContent = pending;

    const total = processed + errors;
    if (successRateElement && total > 0) {
        const rate = (processed / total) * 100;
        successRateElement.textContent = `${rate.toFixed(1)}%`;
    }
}

// Ajout du style CSS pour l'animation du bouton
const style = document.createElement('style');
style.textContent = `
    .pulse {
        animation: pulse-animation 2s infinite;
    }

    @keyframes pulse-animation {
        0% {
            box-shadow: 0 0 0 0 rgba(13, 110, 253, 0.4);
        }
        70% {
            box-shadow: 0 0 0 10px rgba(13, 110, 253, 0);
        }
        100% {
            box-shadow: 0 0 0 0 rgba(13, 110, 253, 0);
        }
    }

    .border-dashed {
        border-style: dashed !important;
    }
`;
document.head.appendChild(style);

/**
 * WireGuard Module - Main View
 * 
 * Complete management UI for WireGuard VPN instances and clients.
 */

import { apiGet, apiPost, apiDelete, apiPatch } from '/static/js/api.js';
import { showToast, confirmDialog, loadingSpinner } from '/static/js/utils.js';
import { checkPermission } from '/static/js/app.js';

let currentInstanceId = null;
let networkInterfaces = [];  // Cache for system network interfaces
let canManage = false;  // Permission cache
let canClients = false;

// Helper function to format bytes to human readable string
function formatBytes(bytes) {
    if (bytes === 0) return '0 B';
    const k = 1024;
    const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

// Helper function to format ISO timestamp to "X ago" format
function formatTimeAgo(isoString) {
    if (!isoString) return 'Mai';
    const date = new Date(isoString);
    const now = new Date();
    const diffMs = now - date;
    const diffSec = Math.floor(diffMs / 1000);

    if (diffSec < 60) return 'Adesso';
    if (diffSec < 3600) return `${Math.floor(diffSec / 60)} min fa`;
    if (diffSec < 86400) return `${Math.floor(diffSec / 3600)} ore fa`;
    if (diffSec < 604800) return `${Math.floor(diffSec / 86400)} giorni fa`;
    return date.toLocaleDateString('it-IT');
}

export async function render(container, params) {
    // Cache permissions
    canManage = checkPermission('wireguard.manage');
    canClients = checkPermission('wireguard.clients');

    if (params && params.length > 0) {
        currentInstanceId = params[0];
        await renderInstanceDetail(container);
    } else {
        await renderInstanceList(container);
    }
}

// ============== INSTANCE LIST ==============

async function renderInstanceList(container) {
    container.innerHTML = `
        <div class="card">
            <div class="card-header d-flex justify-content-between align-items-center">
                <h3 class="card-title"><i class="ti ti-brand-wire me-2"></i>Istanze WireGuard</h3>
                ${canManage ? `
                <button class="btn btn-primary" id="btn-new-instance">
                    <i class="ti ti-plus me-1"></i>Nuova Istanza
                </button>` : ''}
            </div>
            <div class="card-body" id="instances-list">${loadingSpinner()}</div>
        </div>
        
        <!-- New Instance Modal -->
        <div class="modal fade" id="modal-new-instance" tabindex="-1">
            <div class="modal-dialog modal-lg">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Nuova Istanza WireGuard</h5>
                        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="row">
                            <div class="col-md-6 mb-3">
                                <label class="form-label">Nome</label>
                                <input type="text" class="form-control" id="new-instance-name" placeholder="Office VPN">
                            </div>
                            <div class="col-md-3 mb-3">
                                <label class="form-label">Porta UDP</label>
                                <input type="number" class="form-control" id="new-instance-port" value="51820">
                            </div>
                            <div class="col-md-3 mb-3">
                                <label class="form-label">Subnet</label>
                                <input type="text" class="form-control" id="new-instance-subnet" placeholder="10.10.0.0/24">
                            </div>
                        </div>
                        
                        <div class="mb-3">
                            <label class="form-label">Modalità Tunnel</label>
                            <div class="row g-2">
                                <div class="col-6">
                                    <input type="radio" class="btn-check" name="tunnel-mode" id="tunnel-full" value="full" checked>
                                    <label class="btn btn-outline-primary w-100 text-start py-2 d-block" for="tunnel-full">
                                        <i class="ti ti-world me-2"></i><strong>Full Tunnel</strong><br>
                                        <small class="opacity-75">Tutto il traffico passa dalla VPN</small>
                                    </label>
                                </div>
                                <div class="col-6">
                                    <input type="radio" class="btn-check" name="tunnel-mode" id="tunnel-split" value="split">
                                    <label class="btn btn-outline-primary w-100 text-start py-2 d-block" for="tunnel-split">
                                        <i class="ti ti-route me-2"></i><strong>Split Tunnel</strong><br>
                                        <small class="opacity-75">Solo reti specifiche via VPN</small>
                                    </label>
                                </div>
                            </div>
                        </div>
                        
                        <!-- Full Tunnel Options -->
                        <div id="full-tunnel-options">
                            <div class="mb-3">
                                <label class="form-label">Server DNS</label>
                                <input type="text" class="form-control" id="new-instance-dns" 
                                       placeholder="8.8.8.8, 1.1.1.1" value="8.8.8.8, 1.1.1.1">
                                <small class="form-hint">Separati da virgola. Lascia vuoto per usare Google DNS.</small>
                            </div>
                        </div>
                        
                        <!-- Split Tunnel Options -->
                        <div id="split-tunnel-options" style="display: none;">
                            <div class="mb-3">
                                <label class="form-label">Rotte da inoltrare</label>
                                <div id="routes-container">
                                    <div class="route-row mb-2 d-flex gap-2 align-items-center">
                                        <input type="text" class="form-control route-network" placeholder="192.168.1.0/24" style="flex: 2">
                                        <select class="form-select route-interface" style="flex: 1">
                                            <option value="">Interfaccia...</option>
                                        </select>
                                        <button class="btn btn-outline-success btn-add-route" type="button">
                                            <i class="ti ti-plus"></i>
                                        </button>
                                    </div>
                                </div>
                                <small class="form-hint">Subnet → interfaccia di uscita per ogni rotta.</small>
                            </div>
                            <div class="mb-3">
                                <label class="form-label">Server DNS (opzionale)</label>
                                <input type="text" class="form-control" id="new-instance-dns-split" placeholder="Lascia vuoto per usare DNS locali">
                            </div>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-outline-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-create-instance">
                            <i class="ti ti-check me-1"></i>Crea Istanza
                        </button>
                    </div>
                </div>
            </div>
        </div>
    `;

    await loadInstances();
    setupCreateForm();
}

async function setupCreateForm() {
    document.getElementById('btn-new-instance')?.addEventListener('click', async () => {
        await loadNetworkInterfaces();
        populateInterfaceSelects();
        new bootstrap.Modal(document.getElementById('modal-new-instance')).show();
    });

    // Toggle tunnel options
    document.querySelectorAll('input[name="tunnel-mode"]').forEach(radio => {
        radio.addEventListener('change', (e) => {
            const fullOpts = document.getElementById('full-tunnel-options');
            const splitOpts = document.getElementById('split-tunnel-options');
            if (e.target.value === 'full') {
                fullOpts.style.display = 'block';
                splitOpts.style.display = 'none';
            } else {
                fullOpts.style.display = 'none';
                splitOpts.style.display = 'block';
            }
        });
    });

    // Add route button
    document.querySelector('.btn-add-route')?.addEventListener('click', addRouteInput);

    document.getElementById('btn-create-instance')?.addEventListener('click', createInstance);
}

async function loadNetworkInterfaces() {
    try {
        const data = await apiGet('/modules/wireguard/system/interfaces');
        networkInterfaces = data.interfaces || [];
    } catch (err) {
        console.warn('Could not load interfaces:', err);
        networkInterfaces = [{ name: 'eth0', state: 'unknown' }];
    }
}

function populateInterfaceSelects() {
    document.querySelectorAll('.route-interface').forEach(select => {
        const currentVal = select.value;
        select.innerHTML = '<option value="">Auto (default)</option>' +
            networkInterfaces.map(iface =>
                `<option value="${iface.name}" ${iface.state === 'up' ? 'class="fw-bold"' : ''}>
                    ${iface.name} ${iface.state === 'up' ? '●' : ''}
                </option>`
            ).join('');
        if (currentVal) select.value = currentVal;
    });
}

function addRouteInput() {
    const container = document.getElementById('routes-container');
    const div = document.createElement('div');
    div.className = 'route-row mb-2 d-flex gap-2 align-items-center';
    div.innerHTML = `
        <input type="text" class="form-control route-network" placeholder="192.168.1.0/24" style="flex: 2">
        <select class="form-select route-interface" style="flex: 1">
            <option value="">Auto (default)</option>
        </select>
        <button class="btn btn-outline-danger btn-remove-route" type="button">
            <i class="ti ti-minus"></i>
        </button>
    `;
    // Populate interface options
    const select = div.querySelector('.route-interface');
    networkInterfaces.forEach(iface => {
        const opt = document.createElement('option');
        opt.value = iface.name;
        opt.textContent = `${iface.name} ${iface.state === 'up' ? '●' : ''}`;
        select.appendChild(opt);
    });
    div.querySelector('.btn-remove-route').addEventListener('click', () => div.remove());
    container.appendChild(div);
}

async function loadInstances() {
    const listEl = document.getElementById('instances-list');
    try {
        const instances = await apiGet('/modules/wireguard/instances');

        if (instances.length === 0) {
            listEl.innerHTML = `<div class="text-center py-5 text-muted">
                <i class="ti ti-server-off" style="font-size: 3rem;"></i>
                <p class="mt-2">Nessuna istanza configurata</p>
                <small>Clicca "Nuova Istanza" per crearne una</small>
            </div>`;
            return;
        }

        listEl.innerHTML = `<div class="table-responsive"><table class="table table-vcenter card-table">
            <thead><tr>
                <th>Nome</th><th>Interfaccia</th><th>Porta</th><th>Subnet</th>
                <th>Modalità</th><th>Client</th><th>Stato</th><th class="w-1"></th>
            </tr></thead>
            <tbody>${instances.map(i => `<tr>
                <td><a href="#wireguard/${i.id}" class="text-reset"><strong>${i.name}</strong></a></td>
                <td><code>${i.interface}</code></td>
                <td>${i.port}/UDP</td>
                <td><code>${i.subnet}</code></td>
                <td><span class="badge ${i.tunnel_mode === 'full' ? 'bg-blue' : 'bg-purple'}-lt">
                    ${i.tunnel_mode === 'full' ? 'Full' : 'Split'}
                </span></td>
                <td>${i.client_count}</td>
                <td><span class="badge ${i.status === 'running' ? 'bg-success' : 'bg-secondary'}">
                    ${i.status === 'running' ? 'Attivo' : 'Fermo'}
                </span></td>
                <td><div class="btn-group">
                    ${canManage ? (i.status === 'running'
                ? `<button class="btn btn-sm btn-ghost-warning" onclick="stopInstance('${i.id}')" title="Ferma"><i class="ti ti-player-stop"></i></button>`
                : `<button class="btn btn-sm btn-ghost-success" onclick="startInstance('${i.id}')" title="Avvia"><i class="ti ti-player-play"></i></button>`) : ''}
                    <a href="#wireguard/${i.id}" class="btn btn-sm btn-ghost-primary" title="Dettagli"><i class="ti ti-eye"></i></a>
                    ${canManage ? `<button class="btn btn-sm btn-ghost-danger" onclick="deleteInstance('${i.id}')" title="Elimina"><i class="ti ti-trash"></i></button>` : ''}
                </div></td>
            </tr>`).join('')}</tbody>
        </table></div>`;
    } catch (err) {
        listEl.innerHTML = `<div class="alert alert-danger">${err.message}</div>`;
    }
}

async function createInstance() {
    const name = document.getElementById('new-instance-name').value.trim();
    const port = parseInt(document.getElementById('new-instance-port').value);
    const subnet = document.getElementById('new-instance-subnet').value.trim();
    const tunnelMode = document.querySelector('input[name="tunnel-mode"]:checked').value;

    if (!name || !port || !subnet) {
        showToast('Compila tutti i campi obbligatori', 'error');
        return;
    }

    // Collect DNS servers
    let dnsInput = tunnelMode === 'full'
        ? document.getElementById('new-instance-dns').value
        : document.getElementById('new-instance-dns-split').value;

    let dnsServers = dnsInput.split(',').map(s => s.trim()).filter(s => s);
    if (dnsServers.length === 0 && tunnelMode === 'full') {
        dnsServers = ['8.8.8.8', '1.1.1.1'];
    }

    // Collect routes for split tunnel
    let routes = [];
    if (tunnelMode === 'split') {
        document.querySelectorAll('.route-row').forEach(row => {
            const network = row.querySelector('.route-network')?.value.trim();
            const iface = row.querySelector('.route-interface')?.value;
            if (network) {
                routes.push({ network, interface: iface || null });
            }
        });
    }

    try {
        await apiPost('/modules/wireguard/instances', {
            name, port, subnet,
            tunnel_mode: tunnelMode,
            dns_servers: dnsServers,
            routes: routes
        });
        showToast('Istanza creata con successo', 'success');
        bootstrap.Modal.getInstance(document.getElementById('modal-new-instance'))?.hide();
        await loadInstances();
    } catch (err) {
        showToast(err.message, 'error');
    }
}

// ============== INSTANCE DETAIL ==============

async function renderInstanceDetail(container) {
    try {
        const instance = await apiGet(`/modules/wireguard/instances/${currentInstanceId}`);
        const clients = await apiGet(`/modules/wireguard/instances/${currentInstanceId}/clients`);

        container.innerHTML = `
            <div class="mb-3">
                <a href="#wireguard" class="text-muted">
                    <i class="ti ti-arrow-left me-1"></i>Torna alle istanze
                </a>
            </div>
            
            <!-- Instance Info Card -->
            <div class="card mb-3">
                <div class="card-header">
                    <div class="d-flex justify-content-between align-items-center w-100">
                        <div>
                            <h3 class="card-title mb-0">${instance.name}</h3>
                            <small class="text-muted">Interfaccia: ${instance.interface}</small>
                        </div>
                        <div class="btn-group">
                            ${canManage ? `
                            <button class="btn ${instance.status === 'running' ? 'btn-warning' : 'btn-success'}" 
                                    onclick="${instance.status === 'running' ? 'stopInstance' : 'startInstance'}('${instance.id}')">
                                <i class="ti ti-player-${instance.status === 'running' ? 'stop' : 'play'} me-1"></i>
                                ${instance.status === 'running' ? 'Ferma' : 'Avvia'}
                            </button>
                            <button class="btn btn-outline-danger" onclick="deleteInstance('${instance.id}')">
                                <i class="ti ti-trash"></i>
                            </button>` : ''}
                        </div>
                    </div>
                </div>
                <div class="card-body">
                    <div class="row">
                        <div class="col-md-2">
                            <span class="text-muted">Stato</span><br>
                            <span class="badge ${instance.status === 'running' ? 'bg-success' : 'bg-secondary'} fs-6">
                                ${instance.status === 'running' ? 'Attivo' : 'Fermo'}
                            </span>
                        </div>
                        <div class="col-md-2">
                            <span class="text-muted">Porta</span><br>
                            <strong>${instance.port}/UDP</strong>
                        </div>
                        <div class="col-md-2">
                            <span class="text-muted">Subnet</span><br>
                            <code>${instance.subnet}</code>
                        </div>
                        <div class="col-md-2">
                            <span class="text-muted">Modalità</span><br>
                            <span id="display-tunnel-mode" class="badge ${instance.tunnel_mode === 'full' ? 'bg-blue' : 'bg-purple'}-lt">
                                ${instance.tunnel_mode === 'full' ? 'Full Tunnel' : 'Split Tunnel'}
                            </span>
                            ${canManage ? `<button class="btn btn-sm btn-ghost-primary p-0 ms-1" id="btn-edit-routing" title="Modifica instradamento">
                                <i class="ti ti-edit fs-5"></i>
                            </button>` : ''}
                        </div>
                        <div class="col-md-2">
                            <span class="text-muted">DNS</span><br>
                            <small>${instance.dns_servers?.join(', ') || 'N/A'}</small>
                        </div>
                        <div class="col-md-2">
                            <span class="text-muted">Client</span><br>
                            <strong>${instance.client_count}</strong>
                        </div>
                    </div>
                    <hr>
                    <div class="row align-items-center">
                        <div class="col-md-10">
                            <span class="text-muted">Endpoint Pubblico:</span>
                            <code id="display-endpoint">${instance.endpoint || '(auto-detect)'}</code>
                        </div>
                        <div class="col-md-2 text-end">
                            <button class="btn btn-sm btn-outline-primary" id="btn-edit-endpoint">
                                <i class="ti ti-edit me-1"></i>Modifica
                            </button>
                        </div>
                    </div>
                    <div id="display-routes-section">
                    ${instance.tunnel_mode === 'split' && instance.routes?.length ? `
                        <hr>
                        <h4>Rotte Split Tunnel</h4>
                        <div class="d-flex flex-wrap gap-2">
                            ${instance.routes.map(r => `<code class="badge bg-light text-dark">${r.network || r}</code>`).join('')}
                        </div>
                    ` : ''}
                    </div>
                </div>
            </div>
            
            <!-- Tabs for Clients and Firewall -->
            <ul class="nav nav-tabs" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="tab-clients" data-bs-toggle="tab" data-bs-target="#pane-clients" type="button">
                        <i class="ti ti-users me-1"></i>Client (${clients.length})
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="tab-firewall" data-bs-toggle="tab" data-bs-target="#pane-firewall" type="button">
                        <i class="ti ti-shield me-1"></i>Firewall
                    </button>
                </li>
            </ul>
            
            <div class="tab-content">
                <!-- Clients Tab -->
                <div class="tab-pane fade show active" id="pane-clients" role="tabpanel">
                    <div class="card card-body border-top-0 rounded-top-0">
                        <div class="d-flex justify-content-between align-items-center mb-3">
                            <h4 class="mb-0">Client VPN</h4>
                            ${canClients ? `
                            <button class="btn btn-primary" id="btn-new-client">
                                <i class="ti ti-user-plus me-1"></i>Nuovo Client
                            </button>` : ''}
                        </div>
                        ${clients.length === 0 ? `
                            <div class="text-center py-4 text-muted">
                                <i class="ti ti-users-minus" style="font-size: 2rem;"></i>
                                <p class="mt-2">Nessun client configurato</p>
                                <small>Clicca "Nuovo Client" per aggiungerne uno</small>
                            </div>
                        ` : `
                            <div class="table-responsive">
                                <table class="table table-vcenter">
                                    <thead>
                                        <tr>
                                            <th>Stato</th>
                                            <th>Nome</th>
                                            <th>IP Assegnato</th>
                                            <th>Traffico</th>
                                            <th>Ultima Connessione</th>
                                            <th class="w-1">Azioni</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        ${clients.map(c => `
                                            <tr>
                                                <td>
                                                    ${c.is_connected === true
                ? '<span class="status-dot status-dot-animated bg-success" title="Connesso"></span>'
                : '<span class="status-dot bg-secondary" title="Offline"></span>'
            }
                                                </td>
                                                <td><strong>${c.name}</strong></td>
                                                <td><code>${c.allocated_ip}</code></td>
                                                <td>
                                                    ${c.is_connected === true ? `
                                                    <small class="text-muted">
                                                        <i class="ti ti-arrow-down text-success"></i> ${formatBytes(c.rx_bytes || 0)}
                                                        <i class="ti ti-arrow-up text-primary ms-2"></i> ${formatBytes(c.tx_bytes || 0)}
                                                    </small>
                                                    ` : '<small class="text-muted">-</small>'}
                                                </td>
                                                <td>
                                                    ${c.last_seen
                ? `<small class="text-muted">${formatTimeAgo(c.last_seen)}</small>`
                : '<small class="text-muted">Mai connesso</small>'
            }
                                                </td>
                                                <td>
                                                    <div class="btn-group">
                                                        ${canClients ? `
                                                        <button class="btn btn-sm btn-outline-primary" onclick="downloadConfig('${c.name}')" title="Scarica Config">
                                                            <i class="ti ti-download"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-secondary" onclick="showQR('${c.name}')" title="QR Code">
                                                            <i class="ti ti-qrcode"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-success" onclick="openSendEmailModal('${c.name}')" title="Invia via Email">
                                                            <i class="ti ti-mail"></i>
                                                        </button>
                                                        <button class="btn btn-sm btn-outline-danger" onclick="revokeClient('${c.name}')" title="Revoca">
                                                            <i class="ti ti-trash"></i>
                                                        </button>` : ''}
                                                    </div>
                                                </td>
                                            </tr>
                                        `).join('')}
                                    </tbody>
                                </table>
                            </div>
                        `}
                    </div>
                </div>
                
                <!-- Firewall Tab -->
                <div class="tab-pane fade" id="pane-firewall" role="tabpanel">
                    <div class="card card-body border-top-0 rounded-top-0" id="firewall-content">
                        <div class="text-center py-4 text-muted">
                            <i class="ti ti-loader ti-spin" style="font-size: 2rem;"></i>
                            <p class="mt-2">Caricamento...</p>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- New Client Modal -->
        <div class="modal" id="modal-new-client" tabindex="-1">
            <div class="modal-dialog modal-sm">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Nuovo Client</h5>
                        <button class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label" for="new-client-name">Nome del client</label>
                            <input type="text" class="form-control" id="new-client-name" placeholder="es. iPhone-Mario">
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-confirm-new-client">Crea</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Edit Endpoint Modal -->
        <div class="modal" id="modal-edit-endpoint" tabindex="-1">
            <div class="modal-dialog modal-sm">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Modifica Endpoint</h5>
                        <button class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="mb-3">
                            <label class="form-label" for="edit-endpoint-value">Endpoint Pubblico (IP o dominio)</label>
                            <input type="text" class="form-control" id="edit-endpoint-value" placeholder="es. vpn.example.com o 1.2.3.4">
                            <small class="form-hint">Lascia vuoto per usare auto-detect dell'IP pubblico</small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-save-endpoint">Salva</button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Send Email Modal -->
        <div class="modal" id="modal-send-email" tabindex="-1">
            <div class="modal-dialog modal-sm">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Invia Config via Email</h5>
                        <button class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <input type="hidden" id="send-email-client-name">
                        <div class="mb-3">
                            <label class="form-label" for="send-email-address">Email destinatario</label>
                            <input type="email" class="form-control" id="send-email-address" placeholder="utente@example.com">
                            <small class="form-hint">Il destinatario riceverà un link valido 48 ore</small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-success" id="btn-send-email">
                            <i class="ti ti-mail me-1"></i>Invia
                        </button>
                    </div>
                </div>
            </div>
        </div>
        
        <!-- Edit Routing Modal -->
        <div class="modal" id="modal-edit-routing" tabindex="-1">
            <div class="modal-dialog">
                <div class="modal-content">
                    <div class="modal-header">
                        <h5 class="modal-title">Modifica Instradamento</h5>
                        <button class="btn-close" data-bs-dismiss="modal"></button>
                    </div>
                    <div class="modal-body">
                        <div class="alert alert-warning">
                            <i class="ti ti-alert-triangle me-2"></i>
                            <strong>Attenzione:</strong> Dopo la modifica, i client esistenti dovranno riscaricare la configurazione per applicare le nuove rotte.
                        </div>
                        <div class="mb-3">
                            <label class="form-label">Modalità Tunnel</label>
                            <div class="row g-2">
                                <div class="col-6">
                                    <input type="radio" class="btn-check" name="routing-mode" id="routing-full" value="full" ${instance.tunnel_mode === 'full' ? 'checked' : ''}>
                                    <label class="btn btn-outline-primary w-100 text-start py-2 d-block" for="routing-full">
                                        <i class="ti ti-world me-2"></i><strong>Full Tunnel</strong><br>
                                        <small class="opacity-75">Tutto il traffico passa dalla VPN</small>
                                    </label>
                                </div>
                                <div class="col-6">
                                    <input type="radio" class="btn-check" name="routing-mode" id="routing-split" value="split" ${instance.tunnel_mode === 'split' ? 'checked' : ''}>
                                    <label class="btn btn-outline-primary w-100 text-start py-2 d-block" for="routing-split">
                                        <i class="ti ti-route me-2"></i><strong>Split Tunnel</strong><br>
                                        <small class="opacity-75">Solo reti specifiche via VPN</small>
                                    </label>
                                </div>
                            </div>
                        </div>
                        <div id="routing-routes-section" class="${instance.tunnel_mode === 'full' ? 'd-none' : ''}">
                            <label class="form-label">Reti da instradare</label>
                            <div id="routing-routes-list">
                                ${(instance.routes || []).map((r, i) => `
                                    <div class="routing-route-row mb-2 d-flex gap-2 align-items-center">
                                        <input type="text" class="form-control routing-route-input" value="${r.network || r}" placeholder="es. 192.168.1.0/24" style="flex: 2">
                                        <select class="form-select routing-route-interface" style="flex: 1">
                                            <option value="">Auto</option>
                                            ${networkInterfaces.map(iface => `
                                                <option value="${iface.name}" ${(r.interface === iface.name) ? 'selected' : ''}>${iface.name}</option>
                                            `).join('')}
                                        </select>
                                        <button class="btn btn-outline-danger routing-remove-route" type="button"><i class="ti ti-trash"></i></button>
                                    </div>
                                `).join('')}
                            </div>
                            <button class="btn btn-sm btn-outline-primary" id="btn-add-routing-route" type="button">
                                <i class="ti ti-plus me-1"></i>Aggiungi rete
                            </button>
                            <small class="form-hint d-block mt-2">Subnet → interfaccia di uscita. Lascia "Auto" per usare l'interfaccia di default.</small>
                        </div>
                    </div>
                    <div class="modal-footer">
                        <button class="btn btn-secondary" data-bs-dismiss="modal">Annulla</button>
                        <button class="btn btn-primary" id="btn-save-routing">
                            <i class="ti ti-device-floppy me-1"></i>Salva e Applica
                        </button>
                    </div>
                </div>
            </div>
        </div>
        `;

        // New client button - open modal
        document.getElementById('btn-new-client')?.addEventListener('click', () => {
            document.getElementById('new-client-name').value = '';
            new bootstrap.Modal(document.getElementById('modal-new-client')).show();
        });

        // Confirm new client
        document.getElementById('btn-confirm-new-client')?.addEventListener('click', async () => {
            const name = document.getElementById('new-client-name').value.trim();
            if (!name) {
                showToast('Inserisci un nome per il client', 'error');
                return;
            }
            try {
                await apiPost(`/modules/wireguard/instances/${currentInstanceId}/clients`, { name });
                showToast('Client creato con successo', 'success');
                bootstrap.Modal.getInstance(document.getElementById('modal-new-client'))?.hide();
                renderInstanceDetail(container);
            } catch (err) {
                showToast(err.message, 'error');
            }
        });

        // Edit endpoint button
        document.getElementById('btn-edit-endpoint')?.addEventListener('click', () => {
            document.getElementById('edit-endpoint-value').value = instance.endpoint || '';
            new bootstrap.Modal(document.getElementById('modal-edit-endpoint')).show();
        });

        // Save endpoint
        document.getElementById('btn-save-endpoint')?.addEventListener('click', async () => {
            const endpoint = document.getElementById('edit-endpoint-value').value.trim() || null;
            try {
                await apiPatch(`/modules/wireguard/instances/${currentInstanceId}`, { endpoint });
                showToast('Endpoint aggiornato', 'success');
                bootstrap.Modal.getInstance(document.getElementById('modal-edit-endpoint'))?.hide();
                // Update display without full reload
                document.getElementById('display-endpoint').textContent = endpoint || '(auto-detect)';
                instance.endpoint = endpoint;
            } catch (err) {
                showToast(err.message, 'error');
            }
        });

        // Edit routing button
        document.getElementById('btn-edit-routing')?.addEventListener('click', async () => {
            await loadNetworkInterfaces();
            // Repopulate interface selects with current interfaces
            document.querySelectorAll('.routing-route-interface').forEach(select => {
                const currentValue = select.value;
                select.innerHTML = '<option value="">Auto</option>' +
                    networkInterfaces.map(iface =>
                        `<option value="${iface.name}" ${iface.name === currentValue ? 'selected' : ''}>${iface.name}</option>`
                    ).join('');
            });
            new bootstrap.Modal(document.getElementById('modal-edit-routing')).show();
        });

        // Toggle routes section visibility based on mode selection
        document.querySelectorAll('input[name="routing-mode"]').forEach(radio => {
            radio.addEventListener('change', () => {
                const routesSection = document.getElementById('routing-routes-section');
                if (document.getElementById('routing-split').checked) {
                    routesSection.classList.remove('d-none');
                } else {
                    routesSection.classList.add('d-none');
                }
            });
        });

        // Add route button
        document.getElementById('btn-add-routing-route')?.addEventListener('click', () => {
            const list = document.getElementById('routing-routes-list');
            const row = document.createElement('div');
            row.className = 'routing-route-row mb-2 d-flex gap-2 align-items-center';
            row.innerHTML = `
                <input type="text" class="form-control routing-route-input" placeholder="es. 192.168.1.0/24" style="flex: 2">
                <select class="form-select routing-route-interface" style="flex: 1">
                    <option value="">Auto</option>
                    ${networkInterfaces.map(iface => `<option value="${iface.name}">${iface.name}</option>`).join('')}
                </select>
                <button class="btn btn-outline-danger routing-remove-route" type="button"><i class="ti ti-trash"></i></button>
            `;
            list.appendChild(row);
        });

        // Remove route buttons (event delegation)
        document.getElementById('routing-routes-list')?.addEventListener('click', (e) => {
            if (e.target.closest('.routing-remove-route')) {
                e.target.closest('.routing-route-row')?.remove();
            }
        });

        // Save routing
        document.getElementById('btn-save-routing')?.addEventListener('click', async () => {
            const btn = document.getElementById('btn-save-routing');
            const originalHtml = btn.innerHTML;
            btn.disabled = true;
            btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Salvataggio...';

            try {
                const tunnelMode = document.querySelector('input[name="routing-mode"]:checked').value;
                let routes = [];

                if (tunnelMode === 'split') {
                    document.querySelectorAll('.routing-route-row').forEach(row => {
                        const networkInput = row.querySelector('.routing-route-input');
                        const interfaceSelect = row.querySelector('.routing-route-interface');
                        const network = networkInput?.value.trim();
                        if (network) {
                            routes.push({
                                network: network,
                                interface: interfaceSelect?.value || null
                            });
                        }
                    });
                    if (routes.length === 0) {
                        showToast('Split tunnel richiede almeno una rete', 'error');
                        btn.disabled = false;
                        btn.innerHTML = originalHtml;
                        return;
                    }
                }

                const result = await apiPatch(`/modules/wireguard/instances/${currentInstanceId}/routing`, {
                    tunnel_mode: tunnelMode,
                    routes: routes
                });

                bootstrap.Modal.getInstance(document.getElementById('modal-edit-routing'))?.hide();
                showToast(result.message, 'success');

                if (result.warning) {
                    setTimeout(() => showToast(result.warning, 'warning'), 1500);
                }

                // Reload to show updated data
                renderInstanceDetail(container);
            } catch (err) {
                showToast(err.message, 'error');
            } finally {
                btn.disabled = false;
                btn.innerHTML = originalHtml;
            }
        });

        // Load firewall tab when clicked
        document.getElementById('tab-firewall')?.addEventListener('shown.bs.tab', async () => {
            try {
                const firewallModule = await import('./firewall.js');
                await firewallModule.init(document.getElementById('firewall-content'), currentInstanceId);
            } catch (err) {
                document.getElementById('firewall-content').innerHTML = `
                    <div class="alert alert-danger">${err.message}</div>
                `;
            }
        });
    } catch (err) {
        container.innerHTML = `<div class="alert alert-danger">
            <i class="ti ti-alert-circle me-2"></i>${err.message}
        </div>`;
    }
}

// ============== GLOBAL FUNCTIONS ==============

window.startInstance = async (id) => {
    try {
        await apiPost(`/modules/wireguard/instances/${id}/start`);
        showToast('Istanza avviata', 'success');
        location.reload();
    } catch (err) {
        showToast(err.message, 'error');
    }
};

window.stopInstance = async (id) => {
    try {
        await apiPost(`/modules/wireguard/instances/${id}/stop`);
        showToast('Istanza fermata', 'success');
        location.reload();
    } catch (err) {
        showToast(err.message, 'error');
    }
};

window.deleteInstance = async (id) => {
    if (await confirmDialog('Elimina Istanza', 'Eliminare questa istanza e tutti i suoi client?', 'Elimina')) {
        try {
            await apiDelete(`/modules/wireguard/instances/${id}`);
            showToast('Istanza eliminata', 'success');
            location.href = '#wireguard';
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
};

window.downloadConfig = async (name) => {
    try {
        const token = localStorage.getItem('madmin_token');
        const res = await fetch(`/api/modules/wireguard/instances/${currentInstanceId}/clients/${name}/config`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!res.ok) throw new Error('Download fallito: ' + res.statusText);

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `${name}.conf`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        document.body.removeChild(a);
    } catch (err) {
        showToast(err.message, 'error');
    }
};

window.showQR = async (name) => {
    try {
        const token = localStorage.getItem('madmin_token');
        const res = await fetch(`/api/modules/wireguard/instances/${currentInstanceId}/clients/${name}/qr`, {
            headers: { 'Authorization': `Bearer ${token}` }
        });

        if (!res.ok) throw new Error('Caricamento QR fallito: ' + res.statusText);

        const blob = await res.blob();
        const url = window.URL.createObjectURL(blob);

        const modal = document.createElement('div');
        modal.innerHTML = `
            <div class="modal fade" tabindex="-1">
                <div class="modal-dialog modal-sm">
                    <div class="modal-content">
                        <div class="modal-header">
                            <h5 class="modal-title">QR Code - ${name}</h5>
                            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
                        </div>
                        <div class="modal-body text-center p-4">
                            <img src="${url}" class="img-fluid" alt="QR Code">
                            <p class="mt-3 mb-0 text-muted small">Scansiona con l'app WireGuard</p>
                        </div>
                    </div>
                </div>
            </div>
        `;
        document.body.appendChild(modal);
        const bsModal = new bootstrap.Modal(modal.querySelector('.modal'));
        bsModal.show();
        modal.querySelector('.modal').addEventListener('hidden.bs.modal', () => {
            modal.remove();
            window.URL.revokeObjectURL(url);
        });
    } catch (err) {
        showToast(err.message, 'error');
    }
};

window.revokeClient = async (name) => {
    if (await confirmDialog('Revoca Client', `Revocare il client "${name}"? Il client perderà l'accesso alla VPN.`, 'Revoca')) {
        try {
            await apiDelete(`/modules/wireguard/instances/${currentInstanceId}/clients/${name}`);
            showToast('Client revocato', 'success');
            location.reload();
        } catch (err) {
            showToast(err.message, 'error');
        }
    }
};

window.openSendEmailModal = (clientName) => {
    document.getElementById('send-email-client-name').value = clientName;
    document.getElementById('send-email-address').value = '';
    new bootstrap.Modal(document.getElementById('modal-send-email')).show();
};

// Setup send email button handler (called during renderInstanceDetail)
document.addEventListener('click', async (e) => {
    if (e.target.id === 'btn-send-email' || e.target.closest('#btn-send-email')) {
        const clientName = document.getElementById('send-email-client-name').value;
        const email = document.getElementById('send-email-address').value.trim();

        if (!email) {
            showToast('Inserisci un indirizzo email', 'error');
            return;
        }

        const btn = document.getElementById('btn-send-email');
        const originalHtml = btn.innerHTML;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm me-1"></span>Invio...';
        btn.disabled = true;

        try {
            await apiPost(`/modules/wireguard/instances/${currentInstanceId}/clients/${clientName}/send-config`, { email });
            showToast(`Email inviata a ${email}`, 'success');
            bootstrap.Modal.getInstance(document.getElementById('modal-send-email'))?.hide();
        } catch (err) {
            showToast(err.message, 'error');
        } finally {
            btn.innerHTML = originalHtml;
            btn.disabled = false;
        }
    }
});

document.addEventListener('DOMContentLoaded', () => {
    const data = window.AUTHSOME_DATA;
    if (!data) {
        document.body.innerHTML = '<div style="padding: 2rem; color: red;">Error: No data injected into dashboard.</div>';
        return;
    }

    // Render Stats
    const statsHtml = `
        <div class="stat-box">
            <div class="stat-value">${data.stats.connected_providers}</div>
            <div class="stat-label">Active Providers</div>
        </div>
        <div class="stat-box">
            <div class="stat-value">${data.stats.total_connections}</div>
            <div class="stat-label">Connections</div>
        </div>
    `;
    document.getElementById('statsSummary').innerHTML = statsHtml;

    // Render Diagnostics
    const diag = data.diagnostics;
    const diagItems = ['home_exists', 'version_file', 'config_file', 'providers_dir', 'profiles_dir', 'encryption', 'store'];
    
    // We can make diagnostics grid flow nicely 4 columns
    let diagGridHtml = '<div class="diag-grid" style="grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 1rem;">';
    diagItems.forEach(key => {
        const val = diag[key];
        const statusClass = val ? 'diag-ok' : 'diag-fail';
        const statusText = val ? 'OK' : 'FAIL';
        diagGridHtml += `
            <div class="diag-item">
                <span class="diag-label">${key.replace('_', ' ')}</span>
                <span class="${statusClass}">${statusText}</span>
            </div>
        `;
    });
    diagGridHtml += '</div>';
    
    if (diag.issues && diag.issues.length > 0) {
        diagGridHtml += '<div class="issues-list">';
        diag.issues.forEach(issue => {
            diagGridHtml += `<div class="issue-item">${issue}</div>`;
        });
        diagGridHtml += '</div>';
    }
    document.getElementById('diagnosticsCard').innerHTML = diagGridHtml;

    // Split Providers
    const allProviders = data.providers || [];
    const connectedProviders = allProviders.filter(p => p.connections && p.connections.length > 0);
    const availableProviders = allProviders.filter(p => !p.connections || p.connections.length === 0);

    // Render Providers
    function renderProviders(providers, containerId, countId) {
        document.getElementById(countId).textContent = providers.length;
        const container = document.getElementById(containerId);
        
        if (providers.length === 0) {
            container.innerHTML = `<div class="empty-state">No providers available in this category.</div>`;
            return;
        }

        const html = providers.map(p => {
            let connectionsHtml = '<div style="color: var(--text-secondary); font-size: 0.875rem; font-style: italic;">No connections yet</div>';
            
            if (p.connections && p.connections.length > 0) {
                connectionsHtml = p.connections.map(c => {
                    const statusClass = c.status === 'connected' ? 'connected' : (c.status === 'error' ? 'error' : 'disconnected');
                    let scopesHtml = '';
                    if (c.scopes && c.scopes.length > 0) {
                        scopesHtml = `<div class="conn-meta">Scopes: ${c.scopes.join(', ')}</div>`;
                    }
                    let expiresHtml = '';
                    if (c.expires_at) {
                        const date = new Date(c.expires_at * 1000);
                        expiresHtml = `<div class="conn-meta">Expires: ${date.toLocaleString()}</div>`;
                    }
                    
                    return `
                        <div class="connection-item">
                            <div class="conn-header">
                                <span class="conn-name">${c.connection_name}</span>
                                <span class="status ${statusClass}">${c.status}</span>
                            </div>
                            ${scopesHtml}
                            ${expiresHtml}
                        </div>
                    `;
                }).join('');
            }

            const sourceBadge = p.source === 'bundled' 
                ? '<span class="auth-badge" style="margin-left: 0.5rem; background: rgba(59, 130, 246, 0.2); color: #60a5fa;">Bundled</span>'
                : '<span class="auth-badge" style="margin-left: 0.5rem; background: rgba(16, 185, 129, 0.2); color: #34d399;">Custom</span>';

            return `
                <div class="provider-card">
                    <div class="provider-header">
                        <div>
                            <div class="provider-name">${p.display_name}</div>
                            <div class="provider-type">${p.name}</div>
                        </div>
                        <div>
                            <span class="auth-badge">${p.auth_type}</span>
                            ${sourceBadge}
                        </div>
                    </div>
                    <div class="connections-list">
                        ${connectionsHtml}
                    </div>
                </div>
            `;
        }).join('');
        container.innerHTML = html;
    }

    renderProviders(connectedProviders, 'connectedProviders', 'connectedCount');
    renderProviders(availableProviders, 'availableProviders', 'availableCount');
});

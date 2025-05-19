document.addEventListener("DOMContentLoaded", function () {
    // Cache DOM elements
    const elements = {
        login: {
            form: document.getElementById("loginForm"),
            error: document.getElementById("error")
        },
        dashboard: {
            attackLogs: document.getElementById("attackLogs"),
            threatSummary: document.getElementById("threatSummary"),
            protectionStatus: document.getElementById("protection-status"),
            activeAttacks: document.getElementById("active-attacks"),
            traffic: {
                tcp: document.getElementById("tcp-traffic"),
                udp: document.getElementById("udp-traffic"),
                icmp: document.getElementById("icmp-traffic"),
                http: document.getElementById("http-traffic")
            },
            charts: {
                trends: document.getElementById("trafficTrendsChart"),
                types: document.getElementById("attackTypesChart")
            }
        },
        controls: {
            searchBar: document.getElementById("search-bar"),
            logoutBtn: document.getElementById("logout-btn"),
            mitigateBtn: document.getElementById("mitigate-btn"),
            cleanupBtn: document.getElementById("cleanup-btn")
        }
    };

    // State management for attack data
    let state = {
        attacks: [],
        activeAttacks: 0,
        webSocket: null,
        retryCount: 0,
        maxRetries: 5,
        reconnectDelay: 3000,
        charts: {
            trends: null,
            types: null
        },
        trafficData: {
            labels: [],
            tcp: [],
            udp: [],
            icmp: [],
            http: []
        }
    };

    // Debug logging
    const DEBUG = true;
    function log(...args) {
        if (DEBUG) console.log('[CloudGuard]', ...args);
    }

    // Initialize based on current page
    async function initializePage() {
        log('Initializing page...');
        
        if (window.location.pathname.includes('dashboard.html')) {
            try {
                // Check session first
                if (!await checkSession()) {
                    log('Session check failed, redirecting to login');
                    return;
                }

                log('Session valid, setting up dashboard');
                await setupDashboardPage();
            } catch (error) {
                console.error('Dashboard initialization error:', error);
                showNotification('Failed to initialize dashboard', 'error');
            }
        } else if (window.location.pathname.includes('login.html')) {
            log('Setting up login page');
            setupLoginPage();
        }
    }

    async function checkSession() {
        try {
            const response = await fetch('/api/config', {
                credentials: 'include',  // Important: Include credentials
                headers: {
                    'Accept': 'application/json'
                }
            });
            
            if (!response.ok) {
                window.location.href = '/static/login.html';
                return false;
            }
            return true;
        } catch (error) {
            console.error('Session check error:', error);
            window.location.href = '/static/login.html';
            return false;
        }
    }

    function setupLoginPage() {
        const loginForm = document.getElementById("loginForm");
        const errorDiv = document.getElementById("error");

        if (loginForm) {
            loginForm.addEventListener("submit", async function (e) {
                e.preventDefault();
                
                const formData = new FormData(this);
                const username = formData.get("username");
                const password = formData.get("password");

                try {
                    const response = await fetch("/api/login", {
                        method: "POST",
                        headers: {
                            'Content-Type': 'application/x-www-form-urlencoded',
                        },
                        body: `username=${encodeURIComponent(username)}&password=${encodeURIComponent(password)}`,
                        credentials: 'include'
                    });

                    const data = await response.json();
                    
                    if (response.ok) {
                        window.location.href = data.redirect;
                    } else {
                        errorDiv.textContent = data.error || "Login failed";
                        errorDiv.style.display = "block";
                    }
                } catch (error) {
                    console.error("Login error:", error);
                    errorDiv.textContent = "Network error occurred";
                    errorDiv.style.display = "block";
                }
            });
        }
    }

    async function setupDashboardPage() {
        log('Setting up dashboard...');
        
        try {
            // Setup event handlers first
            setupEventHandlers();
            
            // Wait for DOM elements to be ready
            await waitForElements(['trafficTrendsChart', 'attackTypesChart']);
            
            // Initialize charts
            setupCharts();
            
            // Fetch initial data
            await fetchInitialData();
            
            // Setup WebSocket last
            setupWebSocket();
            
            log('Dashboard setup complete');
        } catch (error) {
            console.error('Dashboard setup error:', error);
            showNotification('Failed to initialize dashboard', 'error');
        }
    }

    function waitForElements(ids, maxAttempts = 10) {
        return new Promise((resolve, reject) => {
            let attempts = 0;
            const check = () => {
                const allPresent = ids.every(id => document.getElementById(id));
                if (allPresent) {
                    resolve();
                } else if (++attempts >= maxAttempts) {
                    reject(new Error('Required elements not found'));
                } else {
                    setTimeout(check, 100);
                }
            };
            check();
        });
    }

    // Update chart state and initialization
    function setupCharts() {
        const trendsCtx = document.getElementById('trafficTrendsChart');
        const typesCtx = document.getElementById('attackTypesChart');

        if (!window.Chart) {
            console.error('Chart.js not loaded');
            return;
        }

        // Initialize Traffic Trends chart
        if (trendsCtx) {
            try {
                state.charts.trends = new Chart(trendsCtx.getContext('2d'), {
                    type: 'line',
                    data: {
                        labels: [],
                        datasets: [
                            {
                                label: 'TCP',
                                data: [],
                                borderColor: '#48bb78',
                                tension: 0.4,
                                fill: false
                            },
                            {
                                label: 'UDP',
                                data: [],
                                borderColor: '#ecc94b',
                                tension: 0.4,
                                fill: false
                            },
                            {
                                label: 'ICMP',
                                data: [],
                                borderColor: '#f56565',
                                tension: 0.4,
                                fill: false
                            }
                        ]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        scales: {
                            y: {
                                beginAtZero: true,
                                grid: {
                                    color: 'rgba(255, 255, 255, 0.1)'
                                },
                                ticks: {
                                    color: '#ffffff'
                                }
                            },
                            x: {
                                grid: {
                                    color: 'rgba(255, 255, 255, 0.1)'
                                },
                                ticks: {
                                    color: '#ffffff'
                                }
                            }
                        },
                        plugins: {
                            legend: {
                                labels: {
                                    color: '#ffffff'
                                }
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Failed to initialize trends chart:', error);
            }
        }

        // Initialize Attack Types chart
        if (typesCtx) {
            try {
                state.charts.types = new Chart(typesCtx.getContext('2d'), {
                    type: 'doughnut',
                    data: {
                        labels: [],
                        datasets: [{
                            data: [],
                            backgroundColor: [
                                '#48bb78',
                                '#ecc94b',
                                '#f56565',
                                '#9f7aea'
                            ]
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: false,
                        plugins: {
                            legend: {
                                position: 'right',
                                labels: {
                                    color: '#ffffff'
                                }  // Add missing comma here
                            }
                        }
                    }
                });
            } catch (error) {
                console.error('Failed to initialize types chart:', error);
            }
        }
    }

    function updateTrafficMetrics(stats) {
        if (!stats) return;

        // Map backend stats to frontend display
        const mappings = {
            'tcp-traffic': stats.syn_packets || stats.SYNPackets || 0,
            'udp-traffic': stats.udp_packets || stats.UDPPackets || 0,
            'icmp-traffic': stats.icmp_packets || stats.ICMPPackets || 0,
            'http-traffic': stats.http_packets || stats.HTTPPackets || 0
        };

        Object.entries(mappings).forEach(([elementId, value]) => {
            const element = document.getElementById(elementId);
            if (element) {
                element.textContent = value.toLocaleString();
            }
        });

        // Update traffic trends chart
        if (state.charts.trends) {
            const now = new Date().toLocaleTimeString();
            
            // Update data arrays
            state.trafficData.labels.push(now);
            state.trafficData.tcp.push(mappings['tcp-traffic']);
            state.trafficData.udp.push(mappings['udp-traffic']);
            state.trafficData.icmp.push(mappings['icmp-traffic']);

            // Keep only last 10 points
            if (state.trafficData.labels.length > 10) {
                state.trafficData.labels.shift();
                state.trafficData.tcp.shift();
                state.trafficData.udp.shift();
                state.trafficData.icmp.shift();
            }

            // Update chart
            state.charts.trends.data.labels = state.trafficData.labels;
            state.charts.trends.data.datasets[0].data = state.trafficData.tcp;
            state.charts.trends.data.datasets[1].data = state.trafficData.udp;
            state.charts.trends.data.datasets[2].data = state.trafficData.icmp;
            state.charts.trends.update('none');
        }
    }

    function updateThreatSummary(summary) {
        const summaryTable = document.getElementById('threatSummary');
        if (!summaryTable) return;

        if (!Array.isArray(summary) || summary.length === 0) {
            summaryTable.innerHTML = '<tr><td colspan="5" class="text-center">No threats detected</td></tr>';
            return;
        }

        const html = summary.map(threat => `
            <tr class="hover:bg-gray-800">
                <td>${escapeHtml(threat.protocol)}</td>
                <td>${threat.count}</td>
                <td class="text-${getSeverityColor(threat.severity)}-500">
                    ${escapeHtml(threat.severity)}
                </td>
                <td>${threat.mitigated}</td>
                <td>${formatDate(threat.last_seen)}</td>
            </tr>
        `).join('');

        summaryTable.innerHTML = html;
    }

    function updateAttackTypesChart(data) {
        if (!state.charts || !state.charts.types) {
            console.warn('Attack types chart not initialized');
            return;
        }

        // Initialize distribution if not exists
        if (!state.charts.types.data.distribution) {
            state.charts.types.data.distribution = {
                TCP: 0,
                UDP: 0,
                ICMP: 0,
                HTTP: 0
            };
        }

        // Update distribution based on new data
        if (data && data.protocol) {
            state.charts.types.data.distribution[data.protocol]++;
        }

        // Update chart data
        state.charts.types.data.labels = Object.keys(state.charts.types.data.distribution);
        state.charts.types.data.datasets[0].data = Object.values(state.charts.types.data.distribution);
        state.charts.types.update();
    }

    // Initialize WebSocket connection
    function setupWebSocket() {
        if (state.webSocket?.readyState === WebSocket.OPEN) return;

        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        state.webSocket = new WebSocket(`${protocol}//${window.location.host}/ws`);
        
        state.webSocket.onopen = () => {
            console.log('WebSocket connected');
            state.retryCount = 0;
        };

        state.webSocket.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                console.log('WebSocket message:', data);

                switch(data.type) {
                    case 'stats':
                        updateTrafficMetrics(data.data);
                        break;
                    case 'attack':
                        handleNewAttack(data.data);
                        break;
                    case 'threat_summary':
                        updateThreatSummary(data.data);
                        break;
                }
            } catch (error) {
                console.error('WebSocket message error:', error);
            }
        };

        state.webSocket.onclose = () => {
            console.log('WebSocket disconnected');
            if (state.retryCount < state.maxRetries) {
                setTimeout(setupWebSocket, state.reconnectDelay);
                state.retryCount++;
            }
        };
    }

    async function fetchInitialData() {
        log('Fetching initial data...');
        
        try {
            const [attacksRes, statsRes] = await Promise.all([
                fetch('/api/attacks'),
                fetch('/api/stats')
            ]);

            if (!attacksRes.ok || !statsRes.ok) {
                throw new Error('Failed to fetch initial data');
            }

            const attacks = await attacksRes.json();
            const stats = await statsRes.json();

            log('Initial data loaded:', { attacks, stats });

            // Update state
            state.attacks = attacks.attacks || [];
            
            // Update all displays
            updateAllDisplays();
            
            // Update traffic stats
            if (stats.traffic) {
                handleTrafficUpdate(stats.traffic);
            }

            return true;
        } catch (error) {
            console.error('Error fetching initial data:', error);
            showNotification('Failed to load initial data', 'error');
            return false;
        }
    }

    function updateAllDisplays() {
        log('Updating all displays');
        
        // Update attack logs
        updateAttackLogs();
        
        // Update threat summary
        updateThreatSummary();
        
        // Update protection status
        const activeAttacks = state.attacks.filter(a => !a.mitigated).length;
        if (elements.dashboard.activeAttacks) {
            elements.dashboard.activeAttacks.textContent = activeAttacks;
        }
        
        if (elements.dashboard.protectionStatus) {
            const status = activeAttacks > 0 ? 'Under Attack' : 'Protected';
            const statusClass = activeAttacks > 0 ? 'red' : 'green';
            elements.dashboard.protectionStatus.innerHTML = 
                `<span class="status-dot bg-${statusClass}-500"></span>${status}`;
        }
        
        // Update charts
        updateAttackTypesChart();
    }

    // Handle new attack data
    function handleNewAttack(attack) {
        // Update active attacks counter
        const activeAttacksElement = document.getElementById('active-attacks');
        if (activeAttacksElement) {
            state.activeAttacks++;
            activeAttacksElement.textContent = state.activeAttacks;
        }

        // Update protection status
        const statusElement = document.getElementById('protection-status');
        if (statusElement) {
            const isUnderAttack = state.activeAttacks > 0;
            statusElement.innerHTML = `
                <span class="status-dot bg-${isUnderAttack ? 'red' : 'green'}-500"></span>
                <span>${isUnderAttack ? 'Under Attack' : 'Protected'}</span>
            `;
        }

        // Add to attack logs
        appendAttackLog(attack);
    }

    // Append new attack to the logs table
    function appendNewAttackLog(attack) {
        const logsBody = document.getElementById('attackLogs');
        if (!logsBody) return;

        const row = document.createElement('tr');
        row.className = 'hover:bg-gray-800 transition-colors';
        row.innerHTML = `
            <td>${new Date(attack.timestamp).toLocaleString()}</td>
            <td>${escapeHtml(attack.source_ip)}</td>
            <td>${escapeHtml(attack.destination_ip)}</td>
            <td>${escapeHtml(attack.protocol)}</td>
            <td>${escapeHtml(attack.description)}</td>
            <td class="text-${attack.severity === 'High' ? 'red' : 'yellow'}-500">
                ${escapeHtml(attack.severity)}
            </td>
        `;
        
        logsBody.insertBefore(row, logsBody.firstChild);
        trimTableRows(logsBody, 100); // Keep last 100 entries
    }

    function updateThreatSummary(summary) {
        const summaryTable = document.getElementById('threatSummary');
        if (!summaryTable) return;

        if (!Array.isArray(summary) || summary.length === 0) {
            summaryTable.innerHTML = '<tr><td colspan="5" class="text-center">No threats detected</td></tr>';
            return;
        }

        const html = summary.map(threat => `
            <tr class="hover:bg-gray-800">
                <td>${escapeHtml(threat.protocol)}</td>
                <td>${threat.count}</td>
                <td class="text-${getSeverityColor(threat.severity)}-500">
                    ${escapeHtml(threat.severity)}
                </td>
                <td>${threat.mitigated}</td>
                <td>${formatDate(threat.last_seen)}</td>
            </tr>
        `).join('');

        summaryTable.innerHTML = html;
    }

    function getSeverityColor(severity) {
        switch (severity?.toLowerCase()) {
            case 'high': return 'red';
            case 'medium': return 'yellow';
            case 'low': return 'green';
            default: return 'gray';
        }
    }

    function trimOldLogs(container, maxEntries) {
        while (container.children.length > maxEntries) {
            container.removeChild(container.lastChild);
        }
    }

    function escapeHtml(str) {
        if (!str) return '';
        const div = document.createElement('div');
        div.textContent = str;
        return div.innerHTML;
    }

    function handleTrafficUpdate(stats) {
        log('Updating traffic stats:', stats);
        
        // Update traffic metrics
        Object.entries(elements.dashboard.traffic).forEach(([key, element]) => {
            if (element && stats[`${key}_packets`] !== undefined) {
                element.textContent = stats[`${key}_packets`].toLocaleString();
            }
        });

        // Update traffic trends chart
        updateTrafficChart(stats);
    }

    async function fetchAttacks() {
        try {
            const response = await fetch('/api/attacks');
            if (!response.ok) throw new Error('Failed to fetch attacks');
            const data = await response.json();
            state.attacks = data.attacks;
            updateAllDisplays();
        } catch (error) {
            console.error('Error fetching attacks:', error);
        }
    }

    async function fetchTrafficStats() {
        try {
            const response = await fetch('/api/traffic');
            if (!response.ok) throw new Error('Failed to fetch traffic stats');
            const data = await response.json();
            updateTrafficStats(data.traffic);
        } catch (error) {
            console.error('Error fetching traffic stats:', error);
        }
    }

    async function fetchConfig() {
        try {
            const response = await fetch('/api/config');
            if (!response.ok) throw new Error('Failed to fetch config');
            const config = await response.json();
            // Update UI with config values
            updateConfigDisplay(config);
        } catch (error) {
            console.error('Error fetching config:', error);
        }
    }

    function updateAttackLogs() {
        if (!elements.dashboard.attackLogs) return;
        
        const html = state.attacks.map(attack => `
            <tr class="hover:bg-gray-800">
                <td>${new Date(attack.timestamp).toLocaleString()}</td>
                <td>${escapeHtml(attack.source_ip)}</td>
                <td>${escapeHtml(attack.destination_ip)}</td>
                <td>${escapeHtml(attack.protocol)}</td>
                <td>${escapeHtml(attack.description)}</td>
                <td class="text-${attack.severity === 'High' ? 'red' : 'yellow'}-500">
                    ${escapeHtml(attack.severity)}
                </td>
                <td class="text-${attack.mitigated ? 'green' : 'red'}-500">
                    ${attack.mitigated ? 'Mitigated' : 'Active'}
                </td>
            </tr>
        `).join('');
        
        elements.dashboard.attackLogs.innerHTML = html;
    }

    function updateTrafficStats(stats) {
        Object.entries(elements.dashboard.traffic).forEach(([key, element]) => {
            if (element && stats[`${key}_packets`] !== undefined) {
                element.textContent = stats[`${key}_packets`].toLocaleString();
            }
        });
    }

    function updateTrafficChart(stats) {
        if (!state.charts.trends) {
            log('Traffic trends chart not initialized');
            return;
        }

        const now = new Date().toLocaleTimeString();
        
        // Update data arrays
        state.trafficData.labels.push(now);
        state.trafficData.tcp.push(stats.syn_packets || 0);
        state.trafficData.udp.push(stats.udp_packets || 0);

        // Keep only last 10 points
        if (state.trafficData.labels.length > 10) {
            state.trafficData.labels.shift();
            state.trafficData.tcp.shift();
            state.trafficData.udp.shift();
        }

        // Update chart
        state.charts.trends.data.labels = state.trafficData.labels;
        state.charts.trends.data.datasets[0].data = state.trafficData.tcp;
        state.charts.trends.data.datasets[1].data = state.trafficData.udp;
        state.charts.trends.update('none'); // Use 'none' for smoother updates
    }

    function updateAttackTypesChart(data) {
        if (!state.charts || !state.charts.types) {
            console.warn('Attack types chart not initialized');
            return;
        }

        // Initialize distribution if not exists
        if (!state.charts.types.data.distribution) {
            state.charts.types.data.distribution = {
                TCP: 0,
                UDP: 0,
                ICMP: 0,
                HTTP: 0
            };
        }

        // Update distribution based on new data
        if (data && data.protocol) {
            state.charts.types.data.distribution[data.protocol]++;
        }

        // Update chart data
        state.charts.types.data.labels = Object.keys(state.charts.types.data.distribution);
        state.charts.types.data.datasets[0].data = Object.values(state.charts.types.data.distribution);
        state.charts.types.update();
    }

    function updateProtectionStatus(data) {
        // Update active attacks counter
        const activeAttacks = data.active_attacks || 0;
        if (elements.dashboard.activeAttacks) {
            elements.dashboard.activeAttacks.textContent = activeAttacks;
        }

        // Update protection status indicator
        if (elements.dashboard.protectionStatus) {
            const status = activeAttacks > 0 ? 'Under Attack' : 'Protected';
            const statusClass = activeAttacks > 0 ? 'red' : 'green';
            elements.dashboard.protectionStatus.innerHTML = `
                <span class="status-dot bg-${statusClass}-500"></span>
                <span>${status}</span>
            `;
        }
    }

    function updateTrafficMetrics(stats) {
        if (!stats) return;
        
        const elements = {
            tcp: document.getElementById('tcp-traffic'),
            udp: document.getElementById('udp-traffic'),
            icmp: document.getElementById('icmp-traffic'),
            http: document.getElementById('http-traffic')
        };

        Object.entries(elements).forEach(([key, element]) => {
            if (element && stats[`${key}_packets`] !== undefined) {
                element.textContent = stats[`${key}_packets`].toLocaleString();
            }
        });
    }

    function setupEventHandlers() {
        log('Setting up event handlers...');
        
        // Navigation handlers with proper routing
        document.querySelectorAll('.sidebar li').forEach(item => {
            item.addEventListener('click', () => {
                const page = item.getAttribute('data-page');
                if (page) {
                    // Store current page state if needed
                    localStorage.setItem('lastPage', window.location.pathname);
                    window.location.href = `/static/${page}.html`;
                }
            });
        });

        // Mitigation controls
        elements.controls.mitigateBtn?.addEventListener('click', async () => {
            const button = elements.controls.mitigateBtn;
            button.disabled = true;
            button.textContent = 'Triggering mitigation...';
            
            try {
                const response = await fetch('/api/mitigate', {
                    method: 'POST',
                    credentials: 'include',
                    headers: {
                        'Content-Type': 'application/json'
                    }
                });
                
                if (!response.ok) throw new Error('Mitigation failed');
                
                const result = await response.json();
                showNotification(result.message || 'Mitigation triggered successfully', 'success');
                
                // Refresh data
                await fetchInitialData();
            } catch (error) {
                console.error('Mitigation error:', error);
                showNotification('Failed to trigger mitigation', 'error');
            } finally {
                button.disabled = false;
                button.textContent = 'Trigger Manual Mitigation';
            }
        });

        // Cleanup handler
        elements.controls.cleanupBtn?.addEventListener('click', async () => {
            const button = elements.controls.cleanupBtn;
            button.disabled = true;
            button.textContent = 'Cleaning up...';
            
            try {
                const response = await fetch('/api/cleanup', {
                    method: 'POST',
                    credentials: 'include'
                });
                
                if (!response.ok) throw new Error('Cleanup failed');
                
                const result = await response.json();
                showNotification(result.message || 'Cleanup completed successfully', 'success');
                
                // Refresh data
                await fetchInitialData();
            } catch (error) {
                console.error('Cleanup error:', error);
                showNotification('Failed to cleanup resources', 'error');
            } finally {
                button.disabled = false;
                button.textContent = 'Cleanup Resources';
            }
        });

        // Search functionality
        elements.controls.searchBar?.addEventListener('input', (e) => {
            const searchValue = e.target.value.toLowerCase();
            const rows = document.querySelectorAll('#attackLogs tr');
            
            rows.forEach(row => {
                const text = row.textContent.toLowerCase();
                row.style.display = text.includes(searchValue) ? '' : 'none';
            });
        });
    }

    function setupControls() {
        // Manual mitigation
        elements.controls.mitigateBtn?.addEventListener('click', async () => {
            try {
                const response = await fetch('/api/mitigate', {
                    method: 'POST',
                    credentials: 'include'
                });
                if (!response.ok) throw new Error('Mitigation failed');
                showNotification('Mitigation triggered successfully', 'success');
            } catch (error) {
                console.error('Mitigation error:', error);
                showNotification('Failed to trigger mitigation', 'error');
            }
        });

        // Cleanup
        elements.controls.cleanupBtn?.addEventListener('click', async () => {
            try {
                const response = await fetch('/api/cleanup', {
                    method: 'POST',
                    credentials: 'include'
                });
                if (!response.ok) throw new Error('Cleanup failed');
                showNotification('Cleanup completed successfully', 'success');
            } catch (error) {
                console.error('Cleanup error:', error);
                showNotification('Failed to perform cleanup', 'error');
            }
        });
    }

    async function handleMitigation() {
        try {
            const response = await fetch('/api/mitigate', {
                method: 'POST',
                credentials: 'include'
            });
            
            if (response.ok) {
                showNotification('Mitigation triggered successfully', 'success');
            } else {
                throw new Error('Failed to trigger mitigation');
            }
        } catch (error) {
            console.error('Mitigation error:', error);
            showNotification('Failed to trigger mitigation', 'error');
        }
    }

    async function handleCleanup() {
        try {
            const response = await fetch('/api/cleanup', {
                method: 'POST',
                credentials: 'include'
            });
            
            if (response.ok) {
                showNotification('Cleanup completed successfully', 'success');
            } else {
                throw new Error('Failed to perform cleanup');
            }
        } catch (error) {
            console.error('Cleanup error:', error);
            showNotification('Failed to perform cleanup', 'error');
        }
    }

    function showNotification(message, type = 'info') {
        const notification = document.createElement('div');
        notification.className = `fixed top-4 right-4 p-4 rounded-lg shadow-lg z-50 animate-fade-in ${
            type === 'error' ? 'bg-red-500' : 
            type === 'success' ? 'bg-green-500' : 
            'bg-blue-500'
        } text-white`;
        
        notification.innerHTML = `
            <div class="flex items-center">
                <i class="fas fa-${
                    type === 'error' ? 'exclamation-circle' : 
                    type === 'success' ? 'check-circle' : 
                    'info-circle'
                } mr-2"></i>
                <span>${message}</span>
            </div>
        `;
        
        document.body.appendChild(notification);

        // Fade out
        setTimeout(() => {
            notification.style.opacity = '0';
            notification.style.transform = 'translateY(-20px)';
            notification.style.transition = 'all 0.5s ease';
            setTimeout(() => notification.remove(), 500);
        }, 3000);
    }

    function setupNavigation() {
        document.querySelectorAll('[data-page]').forEach(element => {
            element.addEventListener('click', (e) => {
                e.preventDefault();
                const page = element.getAttribute('data-page');
                if (page) {
                    window.location.href = `/static/${page}.html`;
                }
            });
        });
    }

    function setupLogout() {
        document.getElementById('logoutBtn').addEventListener('click', async () => {
            try {
                const response = await fetch('/api/logout', {
                    method: 'POST',
                    credentials: 'include'
                });
                
                if (response.ok) {
                    window.location.href = '/login';
                } else {
                    console.error('Logout failed:', await response.text());
                }
            } catch (err) {
                console.error('Logout error:', err);
            }
        });
    }

    // Initialize all components
    document.addEventListener('DOMContentLoaded', () => {
        setupCharts();
        setupControls();
        setupNavigation();
        setupWebSocket();
        setupLogout();
    });

    // Initialize the page
    initializePage();

    // Initialize dashboard
    async function initializeDashboard() {
        try {
            setupCharts();
            setupWebSocket();
            
            const [attacksRes, statsRes] = await Promise.all([
                fetch('/api/attacks', { credentials: 'include' }),
                fetch('/api/stats', { credentials: 'include' })
            ]);

            if (!attacksRes.ok || !statsRes.ok) {
                throw new Error('Failed to fetch initial data');
            }

            const [attacks, stats] = await Promise.all([
                attacksRes.json(),
                statsRes.json()
            ]);

            state.attacks = attacks.attacks || [];
            updateAllDisplays();
            updateTrafficMetrics(stats.traffic);

        } catch (error) {
            console.error('Dashboard initialization error:', error);
            // Show error notification
            const errorDiv = document.createElement('div');
            errorDiv.className = 'fixed top-4 right-4 bg-red-500 text-white p-4 rounded-lg shadow-lg';
            errorDiv.textContent = 'Failed to load dashboard data';
            document.body.appendChild(errorDiv);
            setTimeout(() => errorDiv.remove(), 5000);
        }
    }

    // Call on page load
    if (document.getElementById('dashboard')) {
        initializeDashboard();
    }

    function initializeCharts() {
        // Traffic trends chart
        const ctx = document.getElementById('trafficTrends').getContext('2d');
        trafficChart = new Chart(ctx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'TCP',
                    data: [],
                    borderColor: 'rgb(75, 192, 192)',
                    tension: 0.1
                }, {
                    label: 'UDP',
                    data: [],
                    borderColor: 'rgb(255, 99, 132)',
                    tension: 0.1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                scales: {
                    y: {
                        beginAtZero: true
                    }
                }
            }
        });

        // Attack distribution pie chart
        const pieCtx = document.getElementById('attackDistribution').getContext('2d');
        attackChart = new Chart(pieCtx, {
            type: 'pie',
            data: {
                labels: ['TCP SYN Flood', 'UDP Flood', 'HTTP Flood'],
                datasets: [{
                    data: [0, 0, 0],
                    backgroundColor: [
                        'rgb(255, 99, 132)',
                        'rgb(54, 162, 235)',
                        'rgb(255, 205, 86)'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false
            }
        });
    }
});
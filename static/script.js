/**
 * Phishing URL Awareness Checker - Frontend Controller
 * ====================================================
 * Handles UI interactions, API communications, loading animations,
 * benchmark sample selection, and browser-local analysis history.
 */

// Benchmark test samples (used for quick testing chips)
const DEFAULT_BENCHMARKS = [
    {
        label: "Sample 1: Standard HTTPS",
        url: "https://www.example.com/login",
        risk: "low"
    },
    {
        label: "Sample 2: Direct IP + HTTP",
        url: "http://192.0.2.10/account",
        risk: "medium"
    },
    {
        label: "Sample 3: @ Symbol Trick",
        url: "http://example.com@sample.invalid/login",
        risk: "medium"
    },
    {
        label: "Sample 4: Subdomain Chaining",
        url: "https://a.b.c.d.e.example.invalid/path",
        risk: "medium"
    },
    {
        label: "Sample 5: Punycode (IDN)",
        url: "https://xn--example.invalid/",
        risk: "medium"
    },
    {
        label: "Sample 6: Multi-Vector High Risk",
        url: "http://admin@192.0.2.10/verify?redirect=http://attacker.com/session/token/long-string-padding-out-url-over-one-hundred-characters",
        risk: "high"
    }
];

// Storage key for localStorage history
const STORAGE_KEY = "cyberaware_analysis_history_v1";

// DOM Elements
const urlInput = document.getElementById("urlInput");
const clearBtn = document.getElementById("clearBtn");
const analyzeBtn = document.getElementById("analyzeBtn");
const resetBtn = document.getElementById("resetBtn");
const sampleChipsContainer = document.getElementById("sampleChipsContainer");
const loadingScanner = document.getElementById("loadingScanner");
const scannerStepTitle = document.getElementById("scannerStepTitle");
const scannerStepSub = document.getElementById("scannerStepSub");
const progressBar = document.getElementById("progressBar");
const resultSection = document.getElementById("resultSection");

// Result DOM Elements
const assessmentCard = document.getElementById("assessmentCard");
const riskLevelTitle = document.getElementById("riskLevelTitle");
const riskSummaryText = document.getElementById("riskSummaryText");
const riskBadgeScore = document.getElementById("riskBadgeScore");
const metaUrl = document.getElementById("metaUrl");
const metaLength = document.getElementById("metaLength");
const metaProtocol = document.getElementById("metaProtocol");
const metaHostname = document.getElementById("metaHostname");
const disclaimerText = document.getElementById("disclaimerText");
const warningCounter = document.getElementById("warningCounter");
const warningsList = document.getElementById("warningsList");
const noWarningsPlaceholder = document.getElementById("noWarningsPlaceholder");
const recommendationsList = document.getElementById("recommendationsList");
const passedChecksList = document.getElementById("passedChecksList");

// History DOM Elements
const historyTableBody = document.getElementById("historyTableBody");
const historyEmpty = document.getElementById("historyEmpty");
const clearHistoryBtn = document.getElementById("clearHistoryBtn");

// Modal Elements
const guideModal = document.getElementById("guideModal");
const openGuideBtn = document.getElementById("openGuideBtn");
const closeGuideBtn = document.getElementById("closeGuideBtn");

// Inspection scanner steps for smooth visual demonstration
const SCAN_STEPS = [
    { title: "Step 1/6: Parsing URI Syntax & Tokens...", sub: "Decomposing scheme, authority, and host components." },
    { title: "Step 2/6: Checking '@' Symbol Deception...", sub: "Inspecting RFC 3986 user authentication trickery." },
    { title: "Step 3/6: Testing IP Address Classification...", sub: "Verifying if host is a raw IPv4/IPv6 address." },
    { title: "Step 4/6: Analyzing Subdomain Segment Depth...", sub: "Counting dot-separated domain label levels." },
    { title: "Step 5/6: Inspecting Punycode / IDN Homoglyphs...", sub: "Searching for 'xn--' international character prefix." },
    { title: "Step 6/6: Evaluating Transport Protocol...", sub: "Verifying HTTPS encryption vs. plaintext HTTP." }
];

// Initialize on page load
document.addEventListener("DOMContentLoaded", () => {
    initBenchmarkChips();
    initEventListeners();
    renderHistory();
});

/**
 * Populate quick-click benchmark sample chips.
 */
function initBenchmarkChips() {
    sampleChipsContainer.innerHTML = "";
    DEFAULT_BENCHMARKS.forEach(sample => {
        const chip = document.createElement("button");
        chip.type = "button";
        chip.className = "sample-chip";
        chip.innerHTML = `
            <span class="sample-chip-risk ${sample.risk}"></span>
            <span>${escapeHTML(sample.label)}</span>
        `;
        chip.addEventListener("click", () => {
            urlInput.value = sample.url;
            updateClearButtonVisibility();
            urlInput.focus();
            runAnalysis(sample.url);
        });
        sampleChipsContainer.appendChild(chip);
    });
}

/**
 * Attach UI event listeners.
 */
function initEventListeners() {
    // Input text changes
    urlInput.addEventListener("input", updateClearButtonVisibility);

    // Clear input button
    clearBtn.addEventListener("click", () => {
        urlInput.value = "";
        updateClearButtonVisibility();
        urlInput.focus();
    });

    // Reset button (clears form and hides results)
    resetBtn.addEventListener("click", () => {
        urlInput.value = "";
        updateClearButtonVisibility();
        resultSection.style.display = "none";
        loadingScanner.style.display = "none";
        urlInput.focus();
    });

    // Form submit / Analyze button click
    analyzeBtn.addEventListener("click", (e) => {
        e.preventDefault();
        const targetUrl = urlInput.value.trim();
        if (!targetUrl) {
            alert("Please paste or type a URL string before analyzing.");
            urlInput.focus();
            return;
        }
        runAnalysis(targetUrl);
    });

    // Allow pressing Enter in URL input
    urlInput.addEventListener("keydown", (e) => {
        if (e.key === "Enter") {
            e.preventDefault();
            analyzeBtn.click();
        }
    });

    // Clear history
    clearHistoryBtn.addEventListener("click", () => {
        if (confirm("Are you sure you want to clear your local URL analysis history?")) {
            localStorage.removeItem(STORAGE_KEY);
            renderHistory();
        }
    });

    // Detection Guide Modal
    openGuideBtn.addEventListener("click", () => {
        guideModal.style.display = "flex";
    });

    closeGuideBtn.addEventListener("click", () => {
        guideModal.style.display = "none";
    });

    guideModal.addEventListener("click", (e) => {
        if (e.target === guideModal) {
            guideModal.style.display = "none";
        }
    });

    document.addEventListener("keydown", (e) => {
        if (e.key === "Escape" && guideModal.style.display === "flex") {
            guideModal.style.display = "none";
        }
    });
}

function updateClearButtonVisibility() {
    clearBtn.style.display = urlInput.value.trim() ? "flex" : "none";
}

/**
 * Execute URL inspection with simulated scanner progression.
 */
async function runAnalysis(url) {
    // UI state: disable button, show loading scanner
    analyzeBtn.disabled = true;
    resultSection.style.display = "none";
    loadingScanner.style.display = "block";
    progressBar.style.width = "0%";

    try {
        // Animate scanner steps for presentation polish
        for (let i = 0; i < SCAN_STEPS.length; i++) {
            scannerStepTitle.textContent = SCAN_STEPS[i].title;
            scannerStepSub.textContent = SCAN_STEPS[i].sub;
            progressBar.style.width = `${((i + 1) / SCAN_STEPS.length) * 100}%`;
            await sleep(90); // Brief visual delay
        }

        // Send request to Flask API endpoint
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok || !data.valid) {
            throw new Error(data.error || "Failed to inspect the submitted URL.");
        }

        // Render analysis results
        renderResults(data);

        // Save to browser localStorage history
        saveToHistory(data);

        // Scroll smoothly to results
        resultSection.scrollIntoView({ behavior: "smooth", block: "start" });

    } catch (err) {
        alert("Inspection Error: " + err.message);
    } finally {
        analyzeBtn.disabled = false;
        loadingScanner.style.display = "none";
    }
}

/**
 * Render the complete analysis response onto the dashboard.
 */
function renderResults(data) {
    const riskClass = data.risk_class || "low"; // 'low', 'medium', or 'high'
    const warningCount = data.warning_count || 0;
    const totalChecks = data.total_checks || 6;

    // Reset and apply risk theme class to assessment card
    assessmentCard.className = `card assessment-card risk-${riskClass}`;
    riskLevelTitle.textContent = data.risk_level;
    riskSummaryText.textContent = data.risk_summary;
    riskBadgeScore.textContent = `${warningCount}/${totalChecks}`;

    // Target metadata
    metaUrl.textContent = data.url;
    metaLength.textContent = `${data.parsed_components.length} chars`;
    metaProtocol.textContent = (data.parsed_components.scheme || "Unspecified").toUpperCase();
    metaHostname.textContent = data.parsed_components.hostname || "(None)";

    // Mandatory Disclaimer Notice
    disclaimerText.textContent = data.disclaimer;

    // Render Detected Warnings
    warningCounter.textContent = warningCount;
    warningsList.innerHTML = "";

    if (warningCount === 0) {
        noWarningsPlaceholder.style.display = "block";
    } else {
        noWarningsPlaceholder.style.display = "none";
        data.warnings.forEach((warn, index) => {
            const warnEl = document.createElement("div");
            warnEl.className = "warning-item";
            const severityClass = (warn.severity || "medium").toLowerCase();

            warnEl.innerHTML = `
                <div class="warning-item-header">
                    <span class="warning-item-name">
                        <span>⚠️</span> ${escapeHTML(warn.name)}
                    </span>
                    <span class="severity-pill ${severityClass}">${escapeHTML(warn.severity || 'Indicator')}</span>
                </div>
                <div class="warning-detail-block">${escapeHTML(warn.technical_detail)}</div>
                <p class="warning-text">${escapeHTML(warn.description)}</p>
                <div class="warning-threat-box">
                    <strong>Why Attackers Use This:</strong> ${escapeHTML(warn.risk_explanation)}
                </div>
            `;
            warningsList.appendChild(warnEl);
        });
    }

    // Render Security Recommendations
    recommendationsList.innerHTML = "";
    (data.recommendations || []).forEach(rec => {
        const li = document.createElement("li");
        li.textContent = rec;
        recommendationsList.appendChild(li);
    });

    // Render Passed Heuristic Checks
    passedChecksList.innerHTML = "";
    (data.passed_checks || []).forEach(p => {
        const chip = document.createElement("div");
        chip.className = "passed-chip";
        chip.innerHTML = `
            <span class="passed-check-icon">✓</span>
            <span>${escapeHTML(p.name)}</span>
        `;
        passedChecksList.appendChild(chip);
    });

    // Show result section
    resultSection.style.display = "block";
}

/**
 * Save an analysis result record to browser localStorage.
 */
function saveToHistory(data) {
    try {
        const historyJson = localStorage.getItem(STORAGE_KEY);
        let history = historyJson ? JSON.parse(historyJson) : [];

        const record = {
            id: Date.now(),
            timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
            date: new Date().toLocaleDateString(),
            url: data.url,
            risk_level: data.risk_level,
            risk_class: data.risk_class,
            warning_count: data.warning_count
        };

        // Prepend new record, keep up to 20 recent items
        history.unshift(record);
        if (history.length > 20) {
            history = history.slice(0, 20);
        }

        localStorage.setItem(STORAGE_KEY, JSON.stringify(history));
        renderHistory();
    } catch (e) {
        console.warn("Could not save to localStorage:", e);
    }
}

/**
 * Render history table from localStorage.
 */
function renderHistory() {
    try {
        const historyJson = localStorage.getItem(STORAGE_KEY);
        const history = historyJson ? JSON.parse(historyJson) : [];

        historyTableBody.innerHTML = "";

        if (history.length === 0) {
            historyEmpty.style.display = "block";
            return;
        }

        historyEmpty.style.display = "none";

        history.forEach(item => {
            const tr = document.createElement("tr");

            tr.innerHTML = `
                <td>${escapeHTML(item.date)} ${escapeHTML(item.timestamp)}</td>
                <td class="history-url" title="${escapeHTML(item.url)}">${escapeHTML(item.url)}</td>
                <td>
                    <span class="history-risk-badge ${item.risk_class}">
                        ${escapeHTML(item.risk_level)}
                    </span>
                </td>
                <td><strong>${item.warning_count}</strong> / 6 flagged</td>
                <td>
                    <button type="button" class="history-action-btn" data-url="${escapeHTML(item.url)}">
                        Re-Inspect
                    </button>
                </td>
            `;

            // Re-inspect button handler
            const reInspectBtn = tr.querySelector(".history-action-btn");
            reInspectBtn.addEventListener("click", () => {
                const targetUrl = reInspectBtn.getAttribute("data-url");
                urlInput.value = targetUrl;
                updateClearButtonVisibility();
                runAnalysis(targetUrl);
            });

            historyTableBody.appendChild(tr);
        });

    } catch (e) {
        console.warn("Error rendering history:", e);
    }
}

/**
 * Utility: Safe HTML Escaping.
 */
function escapeHTML(str) {
    if (typeof str !== "string") return "";
    return str
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#039;");
}

/**
 * Utility: Delay helper for animation timing.
 */
function sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
}


const express = require('express');
const path = require('path');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const { initDatabase, saveDetectionResult } = require('./database');
const app = express();
const PORT = 3000;

// Initialize database
let db;
initDatabase().then(database => {
    db = database;
}).catch(err => {
    console.error('Database initialization failed:', err);
});

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Set EJS as the templating engine
app.set('views', path.join(__dirname, 'public'));
app.engine('html', require('ejs').renderFile);
app.set('view engine', 'html');

/**
 * 1. OUTPUT ENCODING FUNCTION
 * Safely converts special HTML characters into their harmless entity equivalents.
 */
function escapeHtml(unsafe) {
    if (!unsafe) return '';
    return unsafe.toString()
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

/**
 * Middleware for SECURITY HEADERS (CSP)
 */
app.use((req, res, next) => {
    // Generate a unique nonce for this request (needed for a strong CSP)
    const nonce = crypto.randomBytes(16).toString('base64');
    res.locals.nonce = nonce;

    // Define the Content Security Policy header
    const cspHeader = `
        default-src 'self';
        script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net;
        style-src 'self' 'unsafe-inline';
        connect-src 'self' https://cdn.jsdelivr.net;
        object-src 'none';
        base-uri 'self';
        form-action 'self';
    `.replace(/\s+/g, ' ').trim();

    // Set the CSP header
    res.setHeader('Content-Security-Policy', cspHeader);
    
    // Set other security headers (e.g., HttpOnly cookie is set later)
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    
    next();
});


// --- XSS DEMONSTRATION ENDPOINT ---
app.get('/search', (req, res) => {
    // Decode the query parameter properly
    const rawInput = decodeURIComponent(req.query.q || 'Default Search Term');
    // Default to vulnerable to demonstrate detection first; switch via mode=secure for prevention.
    const mode = req.query.mode === 'secure' ? 'secure' : 'vulnerable';
    // Get ground truth label if provided
    const groundTruth = req.query.truth || null;
    
    // Analyze the input for attack patterns
    const attackPatterns = {
        scriptTag: /<script[\s>]/i.test(rawInput),
        scriptClosing: /<\/script>/i.test(rawInput),
        onerror: /onerror\s*=/i.test(rawInput),
        onclick: /onclick\s*=/i.test(rawInput),
        javascript: /javascript:/i.test(rawInput),
        imgTag: /<img[\s>]/i.test(rawInput),
        iframeTag: /<iframe[\s>]/i.test(rawInput),
        eval: /eval\s*\(/i.test(rawInput),
        alert: /alert\s*\(/i.test(rawInput)
    };
    
    const attackScore = Object.values(attackPatterns).filter(Boolean).length;
    const isMalicious = attackScore > 0;
    
    // Process input based on mode
    let processedInput;
    let encodingApplied = false;
    
    if (mode === 'secure') {
        processedInput = escapeHtml(rawInput);
        encodingApplied = true;
    } else {
        processedInput = rawInput; // Vulnerable mode - no encoding
        encodingApplied = false;
    }
    
    // Prepare analysis data
    const analysisData = {
        rawInput: rawInput,
        processedInput: processedInput,
        mode: mode,
        encodingApplied: encodingApplied,
        attackPatterns: attackPatterns,
        attackScore: attackScore,
        isMalicious: isMalicious,
        groundTruth: groundTruth,
        timestamp: new Date().toISOString(),
        inputLength: rawInput.length,
        encodedLength: processedInput.length
    };
    
    // Save to database
    if (db) {
        saveDetectionResult(db, analysisData).catch(err => {
            console.error('Error saving to database:', err);
        });
    }
    
    res.render('vulnerable.html', { 
        userInput: processedInput, 
        nonce: res.locals.nonce,
        analysis: analysisData
    });
});

// For demonstrating HttpOnly cookies (though not part of this specific XSS demo)
app.get('/login', (req, res) => {
    res.cookie('session_id', 'user_session_token_123', {
        httpOnly: true, // Prevents client-side JS from reading it
        secure: true,   // Only send over HTTPS
        sameSite: 'Strict' 
    });
    res.send('Logged in. Session cookie set with HttpOnly.');
});


// Serve static test page
app.get('/test', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'test.html'));
});

// Serve scanner page
app.get('/scanner', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'scanner.html'));
});

// Metrics endpoint
app.get('/metrics', async (req, res) => {
    const { getStatistics, getRecentResults, getPatternFrequency, getConfusionMatrix, performKFoldCrossValidation } = require('./database');
    
    if (!db) {
        return res.status(500).send('Database not initialized');
    }
    
    try {
        const stats = await getStatistics(db);
        const recentResults = await getRecentResults(db, 20);
        const patternFreq = await getPatternFrequency(db);
        const confusion = await getConfusionMatrix(db);
        
        // Perform 4-fold cross-validation (25% test split)
        let kFoldResults = null;
        try {
            kFoldResults = await performKFoldCrossValidation(db, 4);
        } catch (kFoldErr) {
            console.warn('K-fold cross-validation error:', kFoldErr);
            // Continue without k-fold results if there's an error
        }
        
        res.render('metrics.html', {
            statistics: stats,
            recentResults: recentResults || [],
            patternFrequency: patternFreq || {},
            confusion: confusion,
            kFoldResults: kFoldResults,
            nonce: res.locals.nonce
        });
    } catch (err) {
        console.error('Error fetching metrics:', err);
        res.status(500).send('Error loading metrics');
    }
});

// Root endpoint - redirect to scanner page
app.get('/', (req, res) => {
    res.redirect('/scanner');
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
    console.log('---');
    console.log(`To test VULNERABILITY (Detection), use:`);
    console.log(`http://localhost:${PORT}/search?mode=vulnerable&q=<script>alert('XSS_ATTACK_DETECTED')</script>`);
    console.log('---');
    console.log(`To test PREVENTION (Secure Mode), use:`);
    console.log(`http://localhost:${PORT}/search?mode=secure&q=<script>alert('XSS_ATTACK_DETECTED')</script>`);
    console.log('---');
    console.log(`Default mode: vulnerable (detection demo). Pass mode=secure for prevention.`);
});
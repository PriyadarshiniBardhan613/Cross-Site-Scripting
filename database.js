const sqlite3 = require('sqlite3').verbose();
const path = require('path');

const DB_PATH = path.join(__dirname, 'xss_detection.db');

// Initialize database
function initDatabase() {
    return new Promise((resolve, reject) => {
        const db = new sqlite3.Database(DB_PATH, (err) => {
            if (err) {
                console.error('Error opening database:', err);
                reject(err);
                return;
            }
            console.log('Connected to SQLite database');
        });

        // Create table if it doesn't exist
        db.run(`
            CREATE TABLE IF NOT EXISTS detection_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                raw_input TEXT NOT NULL,
                processed_input TEXT,
                mode TEXT NOT NULL,
                is_malicious INTEGER NOT NULL,
                attack_score INTEGER NOT NULL,
                attack_patterns TEXT,
                encoding_applied INTEGER NOT NULL,
                input_length INTEGER,
                encoded_length INTEGER,
                ground_truth TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        `, (err) => {
            if (err) {
                console.error('Error creating table:', err);
                reject(err);
                return;
            }
            
            // Add ground_truth column if it doesn't exist (for existing databases)
            // SQLite doesn't support IF NOT EXISTS for ALTER TABLE, so we'll try and ignore errors
            db.run(`
                ALTER TABLE detection_results 
                ADD COLUMN ground_truth TEXT
            `, (alterErr) => {
                // Ignore error if column already exists (SQLite error code 1)
                if (alterErr && alterErr.code !== 'SQLITE_ERROR') {
                    console.warn('Note adding ground_truth column:', alterErr.message);
                }
                
                console.log('Database table ready');
                resolve(db);
            });
        });
    });
}

// Save detection result
function saveDetectionResult(db, analysisData) {
    return new Promise((resolve, reject) => {
        const stmt = db.prepare(`
            INSERT INTO detection_results 
            (raw_input, processed_input, mode, is_malicious, attack_score, 
             attack_patterns, encoding_applied, input_length, encoded_length, ground_truth)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        `);

        stmt.run(
            analysisData.rawInput,
            analysisData.processedInput,
            analysisData.mode,
            analysisData.isMalicious ? 1 : 0,
            analysisData.attackScore,
            JSON.stringify(analysisData.attackPatterns),
            analysisData.encodingApplied ? 1 : 0,
            analysisData.inputLength,
            analysisData.encodedLength,
            analysisData.groundTruth || null,
            function(err) {
                if (err) {
                    console.error('Error saving detection result:', err);
                    reject(err);
                } else {
                    resolve(this.lastID);
                }
                stmt.finalize();
            }
        );
    });
}

// Get all detection results
function getAllResults(db) {
    return new Promise((resolve, reject) => {
        db.all(`
            SELECT * FROM detection_results 
            ORDER BY timestamp DESC
        `, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
}

// Get statistics
function getStatistics(db) {
    return new Promise((resolve, reject) => {
        db.all(`
            SELECT 
                COUNT(*) as total_scans,
                SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as attacks_detected,
                SUM(CASE WHEN is_malicious = 0 THEN 1 ELSE 0 END) as clean_inputs,
                AVG(attack_score) as avg_attack_score,
                MAX(attack_score) as max_attack_score,
                SUM(CASE WHEN mode = 'vulnerable' THEN 1 ELSE 0 END) as vulnerable_scans,
                SUM(CASE WHEN mode = 'secure' THEN 1 ELSE 0 END) as secure_scans,
                SUM(CASE WHEN ground_truth IS NOT NULL THEN 1 ELSE 0 END) as labeled_samples,
                SUM(CASE WHEN ground_truth IS NULL THEN 1 ELSE 0 END) as unlabeled_samples
            FROM detection_results
        `, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows[0] || {});
            }
        });
    });
}

// Get recent results (last N)
function getRecentResults(db, limit = 50) {
    return new Promise((resolve, reject) => {
        db.all(`
            SELECT * FROM detection_results 
            ORDER BY timestamp DESC 
            LIMIT ?
        `, [limit], (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
}

// Get pattern frequency
function getPatternFrequency(db) {
    return new Promise((resolve, reject) => {
        db.all(`
            SELECT attack_patterns FROM detection_results 
            WHERE is_malicious = 1
        `, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                const patternCounts = {};
                rows.forEach(row => {
                    try {
                        const patterns = JSON.parse(row.attack_patterns);
                        Object.keys(patterns).forEach(pattern => {
                            if (patterns[pattern]) {
                                patternCounts[pattern] = (patternCounts[pattern] || 0) + 1;
                            }
                        });
                    } catch (e) {
                        // Skip invalid JSON
                    }
                });
                resolve(patternCounts);
            }
        });
    });
}

// Get confusion matrix data (TP, TN, FP, FN)
function getConfusionMatrix(db) {
    return new Promise((resolve, reject) => {
        db.all(`
            SELECT 
                -- True Positives: Detected as malicious AND ground truth is malicious
                SUM(CASE WHEN is_malicious = 1 AND ground_truth = 'malicious' THEN 1 ELSE 0 END) as true_positives,
                -- True Negatives: Detected as clean AND ground truth is clean
                SUM(CASE WHEN is_malicious = 0 AND ground_truth = 'clean' THEN 1 ELSE 0 END) as true_negatives,
                -- False Positives: Detected as malicious BUT ground truth is clean
                SUM(CASE WHEN is_malicious = 1 AND ground_truth = 'clean' THEN 1 ELSE 0 END) as false_positives,
                -- False Negatives: Detected as clean BUT ground truth is malicious
                SUM(CASE WHEN is_malicious = 0 AND ground_truth = 'malicious' THEN 1 ELSE 0 END) as false_negatives,
                -- Total with ground truth labels
                SUM(CASE WHEN ground_truth IS NOT NULL THEN 1 ELSE 0 END) as total_labeled
            FROM detection_results
        `, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                const result = rows[0] || {
                    true_positives: 0,
                    true_negatives: 0,
                    false_positives: 0,
                    false_negatives: 0,
                    total_labeled: 0
                };
                
                // Calculate metrics
                const tp = result.true_positives || 0;
                const tn = result.true_negatives || 0;
                const fp = result.false_positives || 0;
                const fn = result.false_negatives || 0;
                const total = tp + tn + fp + fn;
                
                const precision = (tp + fp) > 0 ? (tp / (tp + fp)) : 0;
                const recall = (tp + fn) > 0 ? (tp / (tp + fn)) : 0;
                const f1Score = (precision + recall) > 0 ? (2 * precision * recall / (precision + recall)) : 0;
                const accuracy = total > 0 ? ((tp + tn) / total) : 0;
                
                resolve({
                    true_positives: tp,
                    true_negatives: tn,
                    false_positives: fp,
                    false_negatives: fn,
                    total_labeled: result.total_labeled || 0,
                    precision: precision,
                    recall: recall,
                    f1_score: f1Score,
                    accuracy: accuracy
                });
            }
        });
    });
}

// Get labeled results for cross-validation
function getLabeledResults(db) {
    return new Promise((resolve, reject) => {
        db.all(`
            SELECT * FROM detection_results 
            WHERE ground_truth IS NOT NULL
            ORDER BY RANDOM()
        `, (err, rows) => {
            if (err) {
                reject(err);
            } else {
                resolve(rows);
            }
        });
    });
}

// Perform k-fold cross-validation
function performKFoldCrossValidation(db, k = 4) {
    return new Promise(async (resolve, reject) => {
        try {
            const allResults = await getLabeledResults(db);
            
            if (allResults.length < k) {
                return resolve({
                    error: `Not enough labeled data. Need at least ${k} samples, got ${allResults.length}`
                });
            }
            
            const foldSize = Math.floor(allResults.length / k);
            const folds = [];
            
            // Create k folds
            for (let i = 0; i < k; i++) {
                const start = i * foldSize;
                const end = i === k - 1 ? allResults.length : (i + 1) * foldSize;
                folds.push(allResults.slice(start, end));
            }
            
            const foldResults = [];
            
            // Perform cross-validation for each fold
            for (let foldIndex = 0; foldIndex < k; foldIndex++) {
                const testSet = folds[foldIndex];
                const trainSet = folds.filter((_, idx) => idx !== foldIndex).flat();
                
                // Calculate confusion matrix for this fold
                let tp = 0, tn = 0, fp = 0, fn = 0;
                
                testSet.forEach(result => {
                    const predicted = result.is_malicious === 1;
                    const actual = result.ground_truth === 'malicious';
                    
                    if (predicted && actual) tp++;
                    else if (!predicted && !actual) tn++;
                    else if (predicted && !actual) fp++;
                    else if (!predicted && actual) fn++;
                });
                
                const total = tp + tn + fp + fn;
                const accuracy = total > 0 ? (tp + tn) / total : 0;
                const precision = (tp + fp) > 0 ? tp / (tp + fp) : 0;
                const recall = (tp + fn) > 0 ? tp / (tp + fn) : 0;
                const f1Score = (precision + recall) > 0 ? (2 * precision * recall) / (precision + recall) : 0;
                
                foldResults.push({
                    fold: foldIndex + 1,
                    testSize: testSet.length,
                    trainSize: trainSet.length,
                    true_positives: tp,
                    true_negatives: tn,
                    false_positives: fp,
                    false_negatives: fn,
                    accuracy: accuracy,
                    precision: precision,
                    recall: recall,
                    f1_score: f1Score
                });
            }
            
            // Aggregate confusion matrix across all folds
            const aggregatedCM = {
                true_positives: foldResults.reduce((sum, f) => sum + f.true_positives, 0),
                true_negatives: foldResults.reduce((sum, f) => sum + f.true_negatives, 0),
                false_positives: foldResults.reduce((sum, f) => sum + f.false_positives, 0),
                false_negatives: foldResults.reduce((sum, f) => sum + f.false_negatives, 0)
            };
            
            // Calculate metrics from aggregated confusion matrix
            const totalAggregated = aggregatedCM.true_positives + aggregatedCM.true_negatives + 
                                   aggregatedCM.false_positives + aggregatedCM.false_negatives;
            const aggregatedAccuracy = totalAggregated > 0 ? 
                (aggregatedCM.true_positives + aggregatedCM.true_negatives) / totalAggregated : 0;
            const aggregatedPrecision = (aggregatedCM.true_positives + aggregatedCM.false_positives) > 0 ?
                aggregatedCM.true_positives / (aggregatedCM.true_positives + aggregatedCM.false_positives) : 0;
            const aggregatedRecall = (aggregatedCM.true_positives + aggregatedCM.false_negatives) > 0 ?
                aggregatedCM.true_positives / (aggregatedCM.true_positives + aggregatedCM.false_negatives) : 0;
            const aggregatedF1 = (aggregatedPrecision + aggregatedRecall) > 0 ?
                (2 * aggregatedPrecision * aggregatedRecall) / (aggregatedPrecision + aggregatedRecall) : 0;
            
            // Calculate average metrics across all folds
            const avgMetrics = {
                accuracy: foldResults.reduce((sum, f) => sum + f.accuracy, 0) / k,
                precision: foldResults.reduce((sum, f) => sum + f.precision, 0) / k,
                recall: foldResults.reduce((sum, f) => sum + f.recall, 0) / k,
                f1_score: foldResults.reduce((sum, f) => sum + f.f1_score, 0) / k
            };
            
            // Calculate standard deviation
            const stdDev = {
                accuracy: Math.sqrt(foldResults.reduce((sum, f) => sum + Math.pow(f.accuracy - avgMetrics.accuracy, 2), 0) / k),
                precision: Math.sqrt(foldResults.reduce((sum, f) => sum + Math.pow(f.precision - avgMetrics.precision, 2), 0) / k),
                recall: Math.sqrt(foldResults.reduce((sum, f) => sum + Math.pow(f.recall - avgMetrics.recall, 2), 0) / k),
                f1_score: Math.sqrt(foldResults.reduce((sum, f) => sum + Math.pow(f.f1_score - avgMetrics.f1_score, 2), 0) / k)
            };
            
            resolve({
                k: k,
                totalSamples: allResults.length,
                foldResults: foldResults,
                aggregatedConfusionMatrix: {
                    true_positives: aggregatedCM.true_positives,
                    true_negatives: aggregatedCM.true_negatives,
                    false_positives: aggregatedCM.false_positives,
                    false_negatives: aggregatedCM.false_negatives,
                    accuracy: aggregatedAccuracy,
                    precision: aggregatedPrecision,
                    recall: aggregatedRecall,
                    f1_score: aggregatedF1
                },
                averageMetrics: avgMetrics,
                standardDeviation: stdDev
            });
        } catch (err) {
            reject(err);
        }
    });
}

module.exports = {
    initDatabase,
    saveDetectionResult,
    getAllResults,
    getStatistics,
    getRecentResults,
    getPatternFrequency,
    getConfusionMatrix,
    performKFoldCrossValidation,
    DB_PATH
};


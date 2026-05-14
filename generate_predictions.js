const fs = require('fs');
const path = require('path');
const { extractFeatures, loadModel } = require('./ml_model');
const { parseCSV } = require('./train_from_csv');

const XSS_DATASET_PATH = path.join(__dirname, 'dataset', 'XSS_dataset.csv');
const CSS1_PATH = path.join(__dirname, 'dataset', 'css1.csv');
const OUTPUT_PATH = path.join(__dirname, 'predictions.json');

function parseXSSDataset(filePath) {
    const content = fs.readFileSync(filePath, 'utf-8');
    const lines = content.split('\n').filter(line => line.trim());
    const records = [];
    for (let i = 1; i < lines.length; i++) {
        const match = lines[i].match(/^(\d+),"(.*)",(0|1)\s*$/);
        if (!match) continue;
        records.push({
            sentence: match[2].replace(/""/g, '"'),
            label: parseInt(match[3], 10)
        });
    }
    return records;
}

function generateXSSPayload(testName, category, isVulnerable) {
    if (category.toLowerCase() !== 'xss') {
        return isVulnerable ? `test_${testName}_input` : `normal_input_${testName}`;
    }
    const testNum = parseInt(testName.replace('BenchmarkTest', '')) || 0;
    const payloads = [
        `<script>alert('XSS${testNum}')</script>`,
        `<img src=x onerror=alert('XSS${testNum}')>`,
        `<iframe src=javascript:alert('XSS${testNum}')></iframe>`,
        `<div onclick=alert('XSS${testNum}')>Click</div>`,
        `<svg/onload=alert('XSS${testNum}')>`,
        `<a href=javascript:alert('XSS${testNum}')>Link</a>`,
        `<script>eval('alert("XSS${testNum}")')</script>`,
        `<body onload=alert('XSS${testNum}')>`,
        `<input onfocus=alert('XSS${testNum}') autofocus>`,
        `<embed src=javascript:alert('XSS${testNum}')>`
    ];
    return isVulnerable ? payloads[testNum % payloads.length] : `Hello World ${testNum}`;
}

const classifier = loadModel();
if (!classifier) {
    console.error('Failed to load model from random_forest_model.json');
    process.exit(1);
}

console.log('Loading XSS_dataset.csv...');
const xssRecords = parseXSSDataset(XSS_DATASET_PATH);
console.log(`Loaded ${xssRecords.length} records`);

console.log('Loading css1.csv...');
const cssRecords = parseCSV(CSS1_PATH);
const cssXSS = cssRecords.filter(r => r.category && r.category.toLowerCase() === 'xss');
console.log(`Loaded ${cssXSS.length} XSS records from css1.csv`);

const samples = [];

for (const rec of xssRecords) {
    samples.push({ text: rec.sentence, label: rec.label });
}

for (const rec of cssXSS) {
    const payload = generateXSSPayload(rec.testName, rec.category, rec.realVulnerability);
    samples.push({ text: payload, label: rec.realVulnerability ? 1 : 0 });
}

console.log(`Total samples: ${samples.length}`);
console.log('Generating probability predictions...');

const predictions = samples.map(({ text, label }) => {
    const features = extractFeatures(text);
    const probMalicious = classifier.predictProbability([features], 1)[0] || 0;
    return { label, score: probMalicious };
});

fs.writeFileSync(OUTPUT_PATH, JSON.stringify(predictions, null, 2));
console.log(`Saved ${predictions.length} predictions to ${OUTPUT_PATH}`);

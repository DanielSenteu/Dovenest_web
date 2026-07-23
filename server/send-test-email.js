// send-test-email.js — one-shot test: sends both the client confirmation AND
// the internal staff notification for a mock motor quote submission.
// Run from the project root:  node server/send-test-email.js

const fs   = require('fs');
const path = require('path');

// ── Load .env manually (no dotenv dependency needed) ─────────────────────────
const envPath = path.resolve(__dirname, '../.env');
if (fs.existsSync(envPath)) {
  fs.readFileSync(envPath, 'utf8').split('\n').forEach(line => {
    const m = line.match(/^([^#=\s][^=]*)=(.*)$/);
    if (m) process.env[m[1].trim()] = m[2].trim();
  });
}

// For this test send both the client email and internal alert to the inbox.
process.env.DOVENEST_INBOX = 'info@dovenestinsurance.com';

const { notifyMotor } = require('./email');

// ── Realistic fake submission ─────────────────────────────────────────────────
const testQuote = {
  ref:              'DNM-TEST-001',
  first_name:       'James',
  last_name:        'Kariuki',
  email:            'info@dovenestinsurance.com',   // client copy → inbox for review
  phone:            '+254 722 000 000',
  date_of_birth:    '1985-06-14',
  experience_years: 8,
  policy_type:      'personal',
  vehicle_category: 'Private Saloon',
};

console.log('Sending test motor quote emails to info@dovenestinsurance.com …');
console.log('  • Client confirmation (ref DNM-TEST-001)');
console.log('  • Internal staff notification');

notifyMotor(testQuote);

// Give the fire-and-forget promises time to settle before the process exits.
setTimeout(() => {
  console.log('Done — check the inbox.');
}, 4000);

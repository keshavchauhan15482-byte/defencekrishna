/**
 * Sentinel Layer 1 — SQL AST Tokenizer & Syntactic Analyzer (Libinjection-Inspired)
 *
 * Scans raw input strings, decomposes them into formal SQL lexical tokens,
 * and matches syntactic AST fingerprints (Boolean Tautology, UNION SELECT,
 * DDL Alteration, Time/Blind Exploits) independent of regex or encoding tricks.
 */

function tokenizeSQL(input) {
  if (!input || typeof input !== 'string') return { tokens: [], fingerprint: '', isSQLi: false, reason: '' };

  const str = input.trim();
  const tokens = [];
  let i = 0;

  while (i < str.length) {
    const ch = str[i];

    // Whitespace
    if (/\s/.test(ch)) { i++; continue; }

    // Comments (-- , /*...*/, #)
    if (ch === '-' && str[i + 1] === '-') {
      tokens.push({ type: 'c', val: '--' });
      break;
    }
    if (ch === '/' && str[i + 1] === '*') {
      tokens.push({ type: 'c', val: '/*...*/' });
      const end = str.indexOf('*/', i + 2);
      i = (end === -1) ? str.length : end + 2;
      continue;
    }
    if (ch === '#') {
      tokens.push({ type: 'c', val: '#' });
      break;
    }

    // Quotes (single, double, backtick)
    if (ch === "'" || ch === '"' || ch === '`') {
      tokens.push({ type: 'q', val: ch });
      i++;
      continue;
    }

    // Hex literals: 0x...
    if (ch === '0' && (str[i + 1] === 'x' || str[i + 1] === 'X')) {
      let hex = '0x';
      i += 2;
      while (i < str.length && /[0-9a-fA-F]/.test(str[i])) { hex += str[i]; i++; }
      tokens.push({ type: '1', val: hex });
      continue;
    }

    // Numbers
    if (/[0-9]/.test(ch)) {
      let num = '';
      while (i < str.length && /[0-9\.]/.test(str[i])) { num += str[i]; i++; }
      tokens.push({ type: '1', val: num });
      continue;
    }

    // Operators
    if (ch === '=' || ch === '<' || ch === '>' || ch === '!' || ch === '&' || ch === '|') {
      let op = ch;
      i++;
      if (i < str.length && (str[i] === '=' || str[i] === '&' || str[i] === '|')) { op += str[i]; i++; }
      tokens.push({ type: 'o', val: op });
      continue;
    }

    // Parentheses / Punctuation
    if (ch === '(' || ch === ')' || ch === ',' || ch === ';') {
      tokens.push({ type: ch, val: ch });
      i++;
      continue;
    }

    // Words / Identifiers / Keywords
    if (/[a-zA-Z_]/.test(ch)) {
      let word = '';
      while (i < str.length && /[a-zA-Z0-9_\$]/.test(str[i])) { word += str[i]; i++; }
      const uWord = word.toUpperCase();

      const SQL_KEYWORDS = new Set(['SELECT', 'FROM', 'WHERE', 'UNION', 'ALL', 'DROP', 'TABLE', 'INSERT', 'INTO', 'UPDATE', 'SET', 'DELETE', 'HAVING', 'GROUP', 'ORDER', 'BY', 'LIMIT', 'EXEC', 'EXECUTE', 'DECLARE', 'WAITFOR', 'DELAY', 'CASE', 'WHEN', 'THEN', 'ELSE', 'END', 'NULL', 'XP_CMDSHELL']);
      const SQL_OPERATORS = new Set(['OR', 'AND', 'XOR', 'NOT', 'LIKE', 'ILIKE', 'IN', 'IS', 'BETWEEN']);
      const SQL_FUNCTIONS = new Set(['SLEEP', 'BENCHMARK', 'CHAR', 'CONCAT', 'VERSION', 'USER', 'DATABASE', 'SCHEMA', 'HEX', 'UNHEX', 'MD5', 'SHA1']);

      if (SQL_OPERATORS.has(uWord)) tokens.push({ type: 'o', val: uWord });
      else if (SQL_FUNCTIONS.has(uWord)) tokens.push({ type: 'f', val: uWord });
      else if (SQL_KEYWORDS.has(uWord)) tokens.push({ type: 'k', val: uWord });
      else tokens.push({ type: 'v', val: word });
      continue;
    }

    i++;
  }

  const fp = tokens.map(t => t.type).join('');

  // 1. Tautology Injections (e.g. ' OR 1=1--, ' OR '1'='1', ' OR 'a'='a', ' OR "x"="x")
  let isTautology = false;
  for (let idx = 0; idx < tokens.length; idx++) {
    const t = tokens[idx];
    if (t.type === 'o' && (t.val === 'OR' || t.val === 'AND')) {
      const slice = tokens.slice(idx + 1, idx + 7);
      const vals = slice.map(s => s.val).filter(v => v !== "'" && v !== '"' && v !== '`');
      if (vals.length >= 3 && (vals[1] === '=' || vals[1] === '==') && vals[0] === vals[2]) {
        isTautology = true;
        break;
      }
    }
  }

  // 2. UNION SELECT Extraction
  const isUnionSelect = /k.*k/.test(fp) && tokens.some((t, idx) => {
    if (t.val === 'UNION') {
      const rest = tokens.slice(idx + 1, idx + 5);
      return rest.some(r => r.val === 'SELECT');
    }
    return false;
  });

  // 3. DDL Alteration / Drop Table
  const isDDL = tokens.some((t, idx) => (t.val === 'DROP' || t.val === 'ALTER' || t.val === 'TRUNCATE') && tokens[idx + 1] && tokens[idx + 1].val === 'TABLE');

  // 4. Time-based Blind Exploits (SLEEP / BENCHMARK / WAITFOR DELAY)
  const isTimeBlind = tokens.some(t => t.val === 'SLEEP' || t.val === 'BENCHMARK') || tokens.some((t, idx) => t.val === 'WAITFOR' && tokens[idx + 1] && tokens[idx + 1].val === 'DELAY');

  const isSQLi = isTautology || isUnionSelect || isDDL || isTimeBlind;
  let reason = '';
  if (isTautology) reason = 'SQL AST: Boolean Tautology Injection Fingerprint (libinjection signature)';
  else if (isUnionSelect) reason = 'SQL AST: UNION SELECT Data Extraction Fingerprint';
  else if (isDDL) reason = 'SQL AST: DDL Schema Alteration Fingerprint';
  else if (isTimeBlind) reason = 'SQL AST: Time-Based Blind Injection Fingerprint';

  return { tokens, fingerprint: fp, isSQLi, reason };
}

module.exports = { tokenizeSQL };

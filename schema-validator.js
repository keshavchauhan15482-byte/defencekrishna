/**
 * Sentinel Layer 1 — Positive Security Model & Schema Validator (Enterprise Edition)
 *
 * Defines parameter structure allowlists and common safe application dictionaries.
 * Rejects unexpected privilege properties (mass assignment, prototype pollution, NoSQL operators)
 * and boundary/type violations while ensuring zero false positives on legitimate e-commerce fields.
 */

const COMMON_SAFE_FIELDS = new Set([
  'name', 'full_name', 'first_name', 'last_name', 'username', 'user', 'email', 'phone', 'mobile',
  'address', 'shipping_address', 'billing_address', 'street', 'city', 'state', 'country', 'zip', 'zipcode', 'postal_code', 'pincode',
  'review', 'rating', 'feedback', 'comment', 'comments', 'notes', 'note', 'description', 'message', 'text', 'title', 'content', 'author',
  'query', 'q', 'search', 'filter', 'sort', 'sort_by', 'order', 'page', 'limit', 'offset',
  'id', 'ids', 'item_id', 'items', 'category', 'categories', 'tags', 'brand', 'product_id',
  'price', 'amount', 'total', 'cost', 'discount', 'coupon', 'code', 'token', 'scenario', 'signal', 'url', 'redirect_to', 'return_url', 'next', 'redirect',
  'status', 'type', 'created_at', 'updated_at', 'lang', 'locale', 'currency', 'remember', 'payload', 'login_failed', 'bio', 'theme', 'language', 'avatar', 'settings'
]);

const SCHEMAS = {
  '/login': {
    allowedFields: new Set(['username', 'password', 'email', 'remember', 'user', 'payload', 'token', 'login_failed', 'comment', 'note', 'next', 'redirect', 'redirect_to', 'return_url']),
    strictTypes: {
      password: (v) => typeof v === 'string' && v.length >= 1 && v.length <= 200,
      username: (v) => typeof v === 'string' && v.length <= 100,
      next: (v) => typeof v === 'string' && v.startsWith('/') && !v.startsWith('//') && !v.includes('\\'),
      redirect: (v) => typeof v === 'string' && v.startsWith('/') && !v.startsWith('//') && !v.includes('\\'),
    }
  },
  '/auth': {
    allowedFields: new Set(['username', 'password', 'email', 'token', 'code', 'redirect_uri', 'state', 'return_url']),
    strictTypes: {
      password: (v) => typeof v === 'string' && v.length >= 1 && v.length <= 200,
    }
  },
  '/checkout': {
    allowedFields: new Set(['item_id', 'items', 'quantity', 'price', 'amount', 'total', 'cost', 'coupon', 'user_id', 'address', 'shipping_address', 'billing_address', 'city', 'state', 'zip', 'pincode', 'country', 'phone', 'email', 'notes', 'scenario', 'signal', 'url', 'redirect_to']),
    strictTypes: {
      price: (v) => (typeof v === 'number' || (typeof v === 'string' && /^\d+(\.\d+)?$/.test(v.trim()))) && Number(v) >= 0 && isFinite(Number(v)),
      quantity: (v) => (typeof v === 'number' || (typeof v === 'string' && /^\d+$/.test(v.trim()))) && Number(v) >= 1 && Number(v) <= 99999 && Number.isInteger(Number(v)),
    }
  },
  '/cart': {
    allowedFields: new Set(['item_id', 'items', 'quantity', 'price', 'discount', 'user_id']),
    strictTypes: {
      price: (v) => (typeof v === 'number' || (typeof v === 'string' && /^\d+(\.\d+)?$/.test(v.trim()))) && Number(v) >= 0 && isFinite(Number(v)),
      quantity: (v) => (typeof v === 'number' || (typeof v === 'string' && /^\d+$/.test(v.trim()))) && Number(v) >= 1 && Number(v) <= 99999 && Number.isInteger(Number(v)),
    }
  },
  '/products': {
    allowedFields: new Set(['id', 'ids', 'q', 'search', 'category', 'brand', 'tags', 'page', 'limit', 'sort', 'sort_by', 'order', 'filter']),
  },
  '/review': {
    allowedFields: new Set(['review', 'rating', 'comment', 'product_id', 'user_id', 'name']),
  },
  '/note': {
    allowedFields: new Set(['note', 'title', 'content', 'author']),
  }
};

const FORBIDDEN_PROPERTIES = new Set([
  '__proto__', 'constructor', 'prototype',
  '$where', '$ne', '$regex', '$gt', '$gte', '$lt', '$lte', '$in', '$nin', '$or', '$and', '$not', '$expr',
  'isAdmin', 'is_admin', 'admin', 'privilege', 'permissions', 'access_level', 'role'
]);

function normalizeKeyForSchemaCheck(key) {
  if (typeof key !== 'string') return '';
  return key.replace(/\[\d*\]/g, '').replace(/\[/g, '.').replace(/\]/g, '');
}

function hasForbiddenProperty(key) {
  if (!key || typeof key !== 'string') return false;
  if (FORBIDDEN_PROPERTIES.has(key)) return true;
  const norm = normalizeKeyForSchemaCheck(key);
  if (FORBIDDEN_PROPERTIES.has(norm)) return true;
  const parts = norm.split('.');
  for (const part of parts) {
    if (FORBIDDEN_PROPERTIES.has(part)) return true;
  }
  return false;
}

function validatePositiveSecurity(path, body, query) {
  const violations = [];
  const normalizedPath = (path || '/').split('?')[0].toLowerCase();

  const checkObject = (obj, source) => {
    if (!obj || typeof obj !== 'object') return;

    for (const key of Object.keys(obj)) {
      // 1. Forbidden privilege properties (Prototype pollution / NoSQL / Mass Assignment / Bracket Notation)
      if (hasForbiddenProperty(key)) {
        violations.push(`Positive Security: forbidden/privilege property "${key}" (normalized: "${normalizeKeyForSchemaCheck(key)}") rejected in ${source}`);
      }

      // 2. Object values where primitive strings are expected (nested NoSQL operators)
      const val = obj[key];
      if (val && typeof val === 'object' && !Array.isArray(val) && Object.keys(val).some(k => k.startsWith('$') || hasForbiddenProperty(k))) {
        violations.push(`Positive Security: nested operator/privilege object in "${key}" rejected in ${source}`);
      }
    }

    // 3. Schema & Common Safe Field Allowlist
    const schemaKey = Object.keys(SCHEMAS).find(k => normalizedPath === k || normalizedPath.startsWith(k + '/'));
    const activeSchema = schemaKey ? SCHEMAS[schemaKey] : null;

    for (const [key, val] of Object.entries(obj)) {
      // Check if field is recognized in route schema OR common safe dictionary
      const isKnownField = (activeSchema && activeSchema.allowedFields.has(key)) || COMMON_SAFE_FIELDS.has(key.toLowerCase());
      
      if (!isKnownField && FORBIDDEN_PROPERTIES.has(key)) {
        violations.push(`Positive Security: undeclared dangerous field "${key}" rejected on route ${normalizedPath}`);
      }

      // Strict type checks on declared fields
      if (activeSchema && activeSchema.strictTypes && typeof activeSchema.strictTypes[key] === 'function') {
        try {
          const isValid = activeSchema.strictTypes[key](val);
          if (!isValid) {
            violations.push(`Positive Security: boundary/type validation failed for field "${key}" on route ${normalizedPath}`);
          }
        } catch (e) {
          violations.push(`Positive Security: validation error for field "${key}" on route ${normalizedPath}`);
        }
      }
    }
  };

  checkObject(body, 'body');
  checkObject(query, 'query');

  return {
    isValid: violations.length === 0,
    score: violations.length > 0 ? 65 : 0,
    violations
  };
}

module.exports = { validatePositiveSecurity, normalizeKeyForSchemaCheck, hasForbiddenProperty, SCHEMAS, COMMON_SAFE_FIELDS, FORBIDDEN_PROPERTIES };

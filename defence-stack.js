'use strict';

// Load current Arjuna/Krishna/Sudarshana hardening, bounded mutation evolution,
// unknown-to-known promotion, canonical memory dedupe, and trusted-only Bloom
// reconstruction before the legacy-compatible proxy module is evaluated.
require('./defence-stack-v4-patch');
require('./proxy');

'use strict';

// Load current Arjuna/Krishna/Sudarshana hardening, bounded mutation evolution,
// unknown-to-known promotion, canonical memory dedupe, trusted-only memory,
// and separate known-attack / validated-mutation Bloom stores before proxy load.
require('./defence-stack-v5-patch');
require('./proxy');

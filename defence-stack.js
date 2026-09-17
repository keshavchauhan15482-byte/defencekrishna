'use strict';

// Load current Arjuna/Krishna/Sudarshana hardening, bounded mutation evolution,
// unknown-to-known promotion, canonical memory dedupe, trusted-only memory,
// separate known-attack / validated-mutation Bloom stores, and mutually
// exclusive Arjuna-known vs Krishna-unknown routing before proxy load.
require('./defence-stack-v6-patch');
require('./proxy');

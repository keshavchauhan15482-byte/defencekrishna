'use strict';

// Load the validated Arjuna/Krishna/Sudarshana runtime hardening plus the
// round-2 mutation-budget and decoded-evidence safety contracts before the
// legacy-compatible proxy module is evaluated.
require('./defence-stack-round2-patch');
require('./proxy');

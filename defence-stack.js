'use strict';

// Load the validated Arjuna/Krishna/Sudarshana runtime hardening before the
// legacy-compatible proxy module is evaluated.
require('./defence-stack-patch');
require('./proxy');

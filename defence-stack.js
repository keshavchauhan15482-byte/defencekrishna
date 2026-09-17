'use strict';

// Load the validated defence loop plus structural-evidence normalization before
// the legacy-compatible proxy module is evaluated.
require('./defence-evidence-hardening');
require('./proxy');

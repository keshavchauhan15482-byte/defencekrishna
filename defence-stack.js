'use strict';

// Load current main-branch hardening plus the V2 bounded-mutation/nested-evidence
// overlay before the legacy-compatible proxy module is evaluated.
require('./defence-stack-v2-patch');
require('./proxy');

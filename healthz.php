<?php
/** Exact production readiness entrypoint. Route only /healthz to this script. */
require_once __DIR__ . '/config/config.php';
require_once __DIR__ . '/config/database.php';
require_once __DIR__ . '/includes/health.php';

emitCtvLmsHealth(getDB());

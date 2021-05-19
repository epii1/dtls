package dtls

import "sync"

// Sessions session_id => master_secret
var Sessions sync.Map

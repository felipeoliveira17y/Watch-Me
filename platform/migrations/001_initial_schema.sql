CREATE TABLE devices (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  hardware_id TEXT UNIQUE,
  firmware TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','revoked')),
  token_hash TEXT,
  created_at TEXT NOT NULL,
  last_seen_at TEXT
);

CREATE TABLE contacts (
  id TEXT PRIMARY KEY,
  device_id TEXT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  position INTEGER NOT NULL CHECK(position BETWEEN 1 AND 5),
  name TEXT NOT NULL,
  phone TEXT NOT NULL,
  category TEXT NOT NULL CHECK(category IN ('official','personal')),
  is_official INTEGER NOT NULL DEFAULT 0 CHECK(is_official IN (0,1)),
  active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0,1)),
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  UNIQUE(device_id,position),
  CHECK((position IN (1,2) AND is_official=1 AND category='official') OR
        (position IN (3,4,5) AND is_official=0 AND category='personal'))
);

CREATE TABLE events (
  id TEXT PRIMARY KEY,
  device_id TEXT REFERENCES devices(id) ON DELETE SET NULL,
  event_key TEXT,
  event_type TEXT NOT NULL CHECK(event_type IN ('sos_manual','possible_fall','fall_confirmed','test','system')),
  source TEXT NOT NULL CHECK(source IN ('device','simulator')),
  status TEXT NOT NULL CHECK(status IN ('received','open','monitoring','resolved','cancelled','closed')),
  received_at TEXT NOT NULL,
  occurred_at TEXT,
  latitude REAL CHECK(latitude IS NULL OR latitude BETWEEN -90 AND 90),
  longitude REAL CHECK(longitude IS NULL OR longitude BETWEEN -180 AND 180),
  accuracy REAL CHECK(accuracy IS NULL OR accuracy >= 0),
  is_simulated INTEGER NOT NULL DEFAULT 0 CHECK(is_simulated IN (0,1)),
  updated_at TEXT NOT NULL,
  UNIQUE(device_id,event_key),
  CHECK((source='simulator' AND is_simulated=1) OR (source='device' AND is_simulated=0))
);

CREATE TABLE rooms (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL UNIQUE REFERENCES events(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  expires_at TEXT NOT NULL,
  revoked_at TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE event_updates (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  update_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE notification_attempts (
  id TEXT PRIMARY KEY,
  event_id TEXT NOT NULL REFERENCES events(id) ON DELETE CASCADE,
  contact_id TEXT REFERENCES contacts(id) ON DELETE SET NULL,
  channel TEXT NOT NULL,
  status TEXT NOT NULL CHECK(status IN ('not_configured','requested','accepted','delivered','failed','unknown')),
  attempted_at TEXT NOT NULL,
  provider_reference TEXT,
  error_code TEXT
);

CREATE TABLE sessions (
  token_hash TEXT PRIMARY KEY,
  expires_at TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE audit_logs (
  id TEXT PRIMARY KEY,
  actor TEXT,
  action TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id TEXT,
  created_at TEXT NOT NULL,
  metadata TEXT
);

CREATE INDEX events_received_at_idx ON events(received_at DESC);
CREATE INDEX events_device_idx ON events(device_id,received_at DESC);
CREATE INDEX event_updates_event_idx ON event_updates(event_id,created_at);
CREATE INDEX contacts_device_idx ON contacts(device_id,position);
CREATE INDEX rooms_expiry_idx ON rooms(expires_at);

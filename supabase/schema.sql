-- Security Event Logger & SIEM Lite - Database Schema
-- Run this in your Supabase SQL Editor

-- Enable necessary extensions
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- Log Events Table
CREATE TABLE IF NOT EXISTS log_events (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source VARCHAR(255) NOT NULL,
    severity VARCHAR(20) NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'info')),
    event_type VARCHAR(100) NOT NULL,
    message TEXT NOT NULL,
    source_ip INET,
    destination_ip INET,
    user_agent TEXT,
    username VARCHAR(255),
    metadata JSONB,
    is_anomaly BOOLEAN DEFAULT FALSE,
    anomaly_score FLOAT,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Create indexes for performance
CREATE INDEX idx_log_events_timestamp ON log_events(timestamp DESC);
CREATE INDEX idx_log_events_severity ON log_events(severity);
CREATE INDEX idx_log_events_source ON log_events(source);
CREATE INDEX idx_log_events_event_type ON log_events(event_type);
CREATE INDEX idx_log_events_source_ip ON log_events(source_ip);
CREATE INDEX idx_log_events_is_anomaly ON log_events(is_anomaly) WHERE is_anomaly = TRUE;
CREATE INDEX idx_log_events_metadata ON log_events USING GIN(metadata);

-- Alert Rules Table
CREATE TABLE IF NOT EXISTS alert_rules (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    description TEXT,
    condition JSONB NOT NULL,
    severity VARCHAR(20) NOT NULL,
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

-- Alerts Table
CREATE TABLE IF NOT EXISTS alerts (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    rule_id UUID REFERENCES alert_rules(id),
    severity VARCHAR(20) NOT NULL,
    title VARCHAR(255) NOT NULL,
    description TEXT,
    triggered_at TIMESTAMPTZ DEFAULT NOW(),
    acknowledged BOOLEAN DEFAULT FALSE,
    acknowledged_at TIMESTAMPTZ,
    acknowledged_by VARCHAR(255),
    related_events UUID[] DEFAULT ARRAY[]::UUID[],
    metadata JSONB
);

CREATE INDEX idx_alerts_triggered_at ON alerts(triggered_at DESC);
CREATE INDEX idx_alerts_acknowledged ON alerts(acknowledged);
CREATE INDEX idx_alerts_severity ON alerts(severity);

-- Event Statistics (for dashboard)
CREATE TABLE IF NOT EXISTS event_statistics (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    time_bucket TIMESTAMPTZ NOT NULL,
    source VARCHAR(255),
    event_type VARCHAR(100),
    severity VARCHAR(20),
    count INTEGER DEFAULT 0,
    unique_ips INTEGER DEFAULT 0,
    anomaly_count INTEGER DEFAULT 0,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX idx_event_stats_time_bucket ON event_statistics(time_bucket DESC);
CREATE INDEX idx_event_stats_source ON event_statistics(source);

-- Threat Intelligence Table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    ip_address INET NOT NULL UNIQUE,
    threat_type VARCHAR(100),
    threat_level VARCHAR(20),
    description TEXT,
    first_seen TIMESTAMPTZ DEFAULT NOW(),
    last_seen TIMESTAMPTZ DEFAULT NOW(),
    occurrence_count INTEGER DEFAULT 1,
    metadata JSONB
);

CREATE INDEX idx_threat_intelligence_ip ON threat_intelligence(ip_address);
CREATE INDEX idx_threat_intelligence_threat_level ON threat_intelligence(threat_level);

-- Row Level Security (RLS)
ALTER TABLE log_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE alert_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE event_statistics ENABLE ROW LEVEL SECURITY;
ALTER TABLE threat_intelligence ENABLE ROW LEVEL SECURITY;

-- Policies (allow authenticated users to read/write)
CREATE POLICY "Allow authenticated users to view logs" ON log_events
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Allow authenticated users to insert logs" ON log_events
    FOR INSERT TO authenticated WITH CHECK (true);

CREATE POLICY "Allow authenticated users to view alerts" ON alerts
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Allow authenticated users to update alerts" ON alerts
    FOR UPDATE TO authenticated USING (true);

CREATE POLICY "Allow authenticated users to view alert rules" ON alert_rules
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Allow authenticated users to view statistics" ON event_statistics
    FOR SELECT TO authenticated USING (true);

CREATE POLICY "Allow authenticated users to view threat intelligence" ON threat_intelligence
    FOR SELECT TO authenticated USING (true);

-- Sample alert rules
INSERT INTO alert_rules (name, description, condition, severity) VALUES
    (
        'Multiple Failed Login Attempts',
        'Detects 5 or more failed login attempts from the same IP within 5 minutes',
        '{"event_type": "failed_login", "threshold": 5, "window_minutes": 5}',
        'high'
    ),
    (
        'Critical Error Spike',
        'Detects unusual spike in critical errors',
        '{"severity": "critical", "threshold": 10, "window_minutes": 10}',
        'critical'
    ),
    (
        'Suspicious IP Activity',
        'Activity from known malicious IP addresses',
        '{"check_threat_intelligence": true}',
        'high'
    );
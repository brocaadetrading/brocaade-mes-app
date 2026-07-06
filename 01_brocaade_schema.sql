-- ============================================================================
-- BROCAADE MANUFACTURING EXECUTION SYSTEM (MES) & INTERIOR PROJECT WORKFLOW
-- Complete PostgreSQL Schema with Role-Based Access Control
-- ============================================================================

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- 1. CORE USER & AUTHENTICATION
-- ============================================================================

CREATE TYPE user_role_enum AS ENUM (
  'owner',
  'design_head',
  'factory_manager',
  'contractor',
  'delivery_team'
);

CREATE TABLE users (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  email VARCHAR(255) UNIQUE NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role user_role_enum NOT NULL,
  first_name VARCHAR(100),
  last_name VARCHAR(100),
  phone VARCHAR(20),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}$')
);

-- ============================================================================
-- 2. COMPANY PROFILE & WHITE-LABEL CONFIGURATION
-- ============================================================================

CREATE TABLE company_profiles (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  owner_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  company_name VARCHAR(255) NOT NULL,
  logo_url VARCHAR(500),
  address TEXT,
  city VARCHAR(100),
  state VARCHAR(100),
  postal_code VARCHAR(20),
  country VARCHAR(100),
  phone VARCHAR(20),
  email VARCHAR(255),
  tax_id VARCHAR(50),
  currency_symbol VARCHAR(5) DEFAULT '₹',
  payment_terms TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 3. MASTER DATA MANAGEMENT (MDM) TABLES
-- ============================================================================

-- Master Materials Catalog
CREATE TABLE master_materials (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  company_id UUID NOT NULL REFERENCES company_profiles(id) ON DELETE CASCADE,
  category VARCHAR(100) NOT NULL,
  material_name VARCHAR(255) NOT NULL,
  description TEXT,
  unit_of_measure VARCHAR(50),
  cost_per_unit DECIMAL(12, 2),
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(company_id, category, material_name)
);

-- Categories: wood, foam, hardware, mattress_components, fabrics, interior_materials
-- interior_materials: false_ceiling_materials, lighting_fixtures, paint_colors, tiles, 
-- modular_kitchen_components, curtains_blinds, wallpapers, door_accessories, 
-- bathroom_fixtures, furniture_components, hardware_fittings

-- Master Contractor Rate Cards
CREATE TABLE contractor_rate_cards (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  contractor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  project_type VARCHAR(100) NOT NULL,
  milestone_name VARCHAR(255) NOT NULL,
  rate_amount DECIMAL(12, 2) NOT NULL,
  rate_type VARCHAR(50),
  description TEXT,
  is_active BOOLEAN DEFAULT TRUE,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 4. PROJECT & JOB SHEET MANAGEMENT
-- ============================================================================

CREATE TYPE project_type_enum AS ENUM (
  'manufacturing',
  'interior_renovation',
  'mixed'
);

CREATE TYPE job_type_enum AS ENUM (
  'custom_sofa',
  'mattress',
  'readymade_retail',
  'false_ceiling',
  'lighting_installation',
  'painting',
  'tiling',
  'modular_kitchen',
  'curtains_blinds',
  'furniture_assembly',
  'wall_covering',
  'door_installation',
  'bathroom_renovation',
  'balcony_work',
  'shoe_rack_installation',
  'tv_unit_assembly',
  'dining_set_assembly',
  'bedroom_furniture',
  'other'
);

CREATE TYPE job_status_enum AS ENUM (
  'draft',
  'submitted',
  'approved',
  'in_progress',
  'completed',
  'on_hold',
  'cancelled'
);

CREATE TABLE projects (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  company_id UUID NOT NULL REFERENCES company_profiles(id) ON DELETE CASCADE,
  project_name VARCHAR(255) NOT NULL,
  project_type project_type_enum NOT NULL,
  client_name VARCHAR(255) NOT NULL,
  client_phone VARCHAR(20),
  client_email VARCHAR(255),
  client_address TEXT,
  client_city VARCHAR(100),
  project_start_date DATE,
  project_end_date DATE,
  budget_amount DECIMAL(12, 2),
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Individual Job Sheets within a Project
CREATE TABLE job_sheets (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  project_id UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  company_id UUID NOT NULL REFERENCES company_profiles(id) ON DELETE CASCADE,
  job_number VARCHAR(50) NOT NULL UNIQUE,
  job_type job_type_enum NOT NULL,
  status job_status_enum DEFAULT 'draft',
  assigned_contractor_id UUID REFERENCES users(id) ON DELETE SET NULL,
  
  -- Design Head Specifications (from master dropdowns)
  design_specs JSONB,
  
  -- Conditional flags for readymade retail
  is_minor_touchup_required BOOLEAN DEFAULT FALSE,
  
  -- SLA & Timeline
  promised_delivery_date DATE,
  actual_completion_date DATE,
  
  -- Financial tracking
  estimated_labor_cost DECIMAL(12, 2),
  
  created_by UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_job_sheets_project ON job_sheets(project_id);
CREATE INDEX idx_job_sheets_contractor ON job_sheets(assigned_contractor_id);
CREATE INDEX idx_job_sheets_status ON job_sheets(status);

-- ============================================================================
-- 5. MILESTONE & WORKFLOW TRACKING
-- ============================================================================

CREATE TYPE milestone_status_enum AS ENUM (
  'pending',
  'in_progress',
  'photo_pending',
  'awaiting_approval',
  'approved',
  'rejected',
  'skipped'
);

CREATE TABLE job_milestones (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  job_sheet_id UUID NOT NULL REFERENCES job_sheets(id) ON DELETE CASCADE,
  milestone_sequence INT NOT NULL,
  milestone_name VARCHAR(255) NOT NULL,
  milestone_description TEXT,
  status milestone_status_enum DEFAULT 'pending',
  
  -- Photo & Evidence
  photo_url VARCHAR(500),
  photo_uploaded_at TIMESTAMP WITH TIME ZONE,
  uploaded_by UUID REFERENCES users(id) ON DELETE SET NULL,
  
  -- Approvals
  approved_by UUID REFERENCES users(id) ON DELETE SET NULL,
  approval_notes TEXT,
  approved_at TIMESTAMP WITH TIME ZONE,
  
  -- Timestamps
  started_at TIMESTAMP WITH TIME ZONE,
  completed_at TIMESTAMP WITH TIME ZONE,
  sla_hours INT,
  is_sla_breached BOOLEAN DEFAULT FALSE,
  
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_milestones_job ON job_milestones(job_sheet_id);
CREATE INDEX idx_milestones_status ON job_milestones(status);

-- ============================================================================
-- 6. MATERIAL REQUISITION & INVENTORY TRACKING
-- ============================================================================

CREATE TYPE inventory_status_enum AS ENUM (
  'requested',
  'partially_issued',
  'fully_issued',
  'returned',
  'wastage_logged'
);

CREATE TABLE material_requisitions (
  id UUID PRIMARY KEY DEFAULT UUID_generate_v4(),
  job_sheet_id UUID NOT NULL REFERENCES job_sheets(id) ON DELETE CASCADE,
  material_id UUID NOT NULL REFERENCES master_materials(id) ON DELETE RESTRICT,
  quantity_requested DECIMAL(12, 2) NOT NULL,
  quantity_issued DECIMAL(12, 2) DEFAULT 0,
  unit_of_measure VARCHAR(50),
  status inventory_status_enum DEFAULT 'requested',
  
  -- Issue tracking
  issued_by UUID REFERENCES users(id) ON DELETE SET NULL,
  issued_at TIMESTAMP WITH TIME ZONE,
  
  -- Returns & Wastage
  quantity_returned DECIMAL(12, 2) DEFAULT 0,
  quantity_wasted DECIMAL(12, 2) DEFAULT 0,
  wastage_reason TEXT,
  
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_requisitions_job ON material_requisitions(job_sheet_id);

-- ============================================================================
-- 7. CONTRACTOR FINANCIAL LEDGER
-- ============================================================================

CREATE TABLE contractor_financial_ledger (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  contractor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  job_sheet_id UUID NOT NULL REFERENCES job_sheets(id) ON DELETE CASCADE,
  
  -- Potential vs Earned
  potential_earnings DECIMAL(12, 2) NOT NULL DEFAULT 0,
  earned_amount_gross DECIMAL(12, 2) DEFAULT 0,
  
  -- Advances
  total_advances_paid DECIMAL(12, 2) DEFAULT 0,
  
  -- Calculated field
  net_balance_due DECIMAL(12, 2) GENERATED ALWAYS AS 
    (earned_amount_gross - total_advances_paid) STORED,
  
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_ledger_contractor ON contractor_financial_ledger(contractor_id);

-- Advance Payment History
CREATE TABLE advance_payments (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  ledger_id UUID NOT NULL REFERENCES contractor_financial_ledger(id) ON DELETE CASCADE,
  contractor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  amount DECIMAL(12, 2) NOT NULL,
  payment_date DATE NOT NULL,
  payment_method VARCHAR(50),
  notes TEXT,
  recorded_by UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Settlement Records (Final Payout)
CREATE TABLE contractor_settlements (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  contractor_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  settlement_date TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  
  -- Settlement amounts
  total_earned_amount DECIMAL(12, 2) NOT NULL,
  total_advances_paid DECIMAL(12, 2) NOT NULL,
  net_amount_paid DECIMAL(12, 2) NOT NULL,
  
  -- Settlement details
  settlement_notes TEXT,
  settled_by UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  
  -- After settlement, ledgers reset
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 8. DELIVERY & COD TRACKING
-- ============================================================================

CREATE TYPE delivery_status_enum AS ENUM (
  'pending',
  'in_transit',
  'delivered',
  'failed',
  'returned'
);

CREATE TABLE deliveries (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  job_sheet_id UUID NOT NULL REFERENCES job_sheets(id) ON DELETE CASCADE,
  delivery_team_member_id UUID NOT NULL REFERENCES users(id) ON DELETE SET NULL,
  
  -- Delivery details
  delivery_date DATE,
  delivery_time TIME,
  delivery_address TEXT,
  delivery_city VARCHAR(100),
  delivery_phone VARCHAR(20),
  
  -- Status tracking
  status delivery_status_enum DEFAULT 'pending',
  
  -- COD & Payment
  cod_amount DECIMAL(12, 2),
  amount_collected DECIMAL(12, 2) DEFAULT 0,
  payment_method VARCHAR(50),
  
  -- Photo evidence
  delivery_photo_url VARCHAR(500),
  delivery_photo_timestamp TIMESTAMP WITH TIME ZONE,
  
  -- Signature or confirmation
  customer_signature_url VARCHAR(500),
  delivery_notes TEXT,
  
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_deliveries_job ON deliveries(job_sheet_id);
CREATE INDEX idx_deliveries_status ON deliveries(status);

-- ============================================================================
-- 9. AUDIT & COMPLIANCE LOGGING
-- ============================================================================

CREATE TABLE audit_logs (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  user_id UUID REFERENCES users(id) ON DELETE SET NULL,
  action VARCHAR(255) NOT NULL,
  table_name VARCHAR(100),
  record_id UUID,
  old_values JSONB,
  new_values JSONB,
  ip_address INET,
  user_agent TEXT,
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX idx_audit_logs_table ON audit_logs(table_name, record_id);

-- ============================================================================
-- 10. SLA & ALERT TRACKING
-- ============================================================================

CREATE TABLE sla_alerts (
  id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
  job_sheet_id UUID NOT NULL REFERENCES job_sheets(id) ON DELETE CASCADE,
  milestone_id UUID REFERENCES job_milestones(id) ON DELETE CASCADE,
  
  alert_type VARCHAR(50) NOT NULL,
  severity VARCHAR(20),
  message TEXT,
  is_resolved BOOLEAN DEFAULT FALSE,
  resolved_at TIMESTAMP WITH TIME ZONE,
  resolved_by UUID REFERENCES users(id) ON DELETE SET NULL,
  
  created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- 11. ROW LEVEL SECURITY (RLS) POLICIES
-- ============================================================================

-- Enable RLS on all sensitive tables
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE projects ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_sheets ENABLE ROW LEVEL SECURITY;
ALTER TABLE job_milestones ENABLE ROW LEVEL SECURITY;
ALTER TABLE contractor_financial_ledger ENABLE ROW LEVEL SECURITY;
ALTER TABLE deliveries ENABLE ROW LEVEL SECURITY;
ALTER TABLE advance_payments ENABLE ROW LEVEL SECURITY;
ALTER TABLE contractor_settlements ENABLE ROW LEVEL SECURITY;

-- Owner: Full Access
CREATE POLICY owner_full_access ON projects
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM users WHERE users.id = auth.uid() AND users.role = 'owner'
    )
  );

CREATE POLICY owner_full_access_jobs ON job_sheets
  FOR ALL USING (
    EXISTS (
      SELECT 1 FROM users WHERE users.id = auth.uid() AND users.role = 'owner'
    )
  );

-- Design Head: Create/Edit Job Sheets Only
CREATE POLICY design_head_job_sheet_access ON job_sheets
  FOR ALL USING (
    (
      EXISTS (
        SELECT 1 FROM users WHERE users.id = auth.uid() AND users.role = 'design_head'
      )
    )
  )
  WITH CHECK (
    (
      EXISTS (
        SELECT 1 FROM users WHERE users.id = auth.uid() AND users.role = 'design_head'
      )
    )
  );

-- Factory Manager: View all jobs, approve milestones
CREATE POLICY factory_mgr_view_all_jobs ON job_sheets
  FOR SELECT USING (
    EXISTS (
      SELECT 1 FROM users WHERE users.id = auth.uid() AND users.role = 'factory_manager'
    )
  );

-- Contractor: Only their assigned jobs
CREATE POLICY contractor_own_jobs ON job_sheets
  FOR SELECT USING (
    assigned_contractor_id = auth.uid()
  );

CREATE POLICY contractor_own_ledger ON contractor_financial_ledger
  FOR SELECT USING (
    contractor_id = auth.uid()
  );

-- Delivery Team: Only delivery records
CREATE POLICY delivery_team_deliveries ON deliveries
  FOR SELECT USING (
    delivery_team_member_id = auth.uid()
  );

-- ============================================================================
-- 12. VIEWS FOR REPORTING & DASHBOARDS
-- ============================================================================

-- Owner Dashboard: Total Pipeline Values
CREATE VIEW owner_dashboard_summary AS
SELECT
  (SELECT COUNT(*) FROM job_sheets WHERE status IN ('in_progress', 'submitted')) as active_jobs,
  (SELECT SUM(estimated_labor_cost) FROM job_sheets WHERE status IN ('in_progress', 'submitted')) as pipeline_value,
  (SELECT SUM(net_balance_due) FROM contractor_financial_ledger) as total_outstanding_liabilities,
  (SELECT COUNT(*) FROM deliveries WHERE status IN ('pending', 'in_transit')) as pending_deliveries,
  (SELECT SUM(cod_amount) FROM deliveries WHERE status IN ('pending', 'in_transit')) as pending_cod_value;

-- SLA Breach Alert View
CREATE VIEW sla_breach_alerts AS
SELECT
  js.id as job_id,
  js.job_number,
  jm.milestone_name,
  jm.sla_hours,
  EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - jm.started_at)) / 3600 as hours_elapsed,
  (EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - jm.started_at)) / 3600) > jm.sla_hours as is_breached,
  CASE 
    WHEN (EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - jm.started_at)) / 3600) > jm.sla_hours THEN 'CRITICAL'
    ELSE 'WARNING'
  END as alert_severity
FROM job_sheets js
JOIN job_milestones jm ON js.id = jm.job_sheet_id
WHERE jm.status NOT IN ('approved', 'skipped') AND jm.started_at IS NOT NULL;

-- Contractor Earnings Summary
CREATE VIEW contractor_earnings_summary AS
SELECT
  c.id,
  c.first_name || ' ' || c.last_name as contractor_name,
  COUNT(DISTINCT cfl.job_sheet_id) as total_jobs,
  SUM(cfl.potential_earnings) as total_potential,
  SUM(cfl.earned_amount_gross) as total_earned,
  SUM(cfl.total_advances_paid) as total_advances,
  SUM(cfl.net_balance_due) as total_balance_due
FROM users c
LEFT JOIN contractor_financial_ledger cfl ON c.id = cfl.contractor_id
WHERE c.role = 'contractor'
GROUP BY c.id, c.first_name, c.last_name;

-- ============================================================================
-- 13. INDEXES FOR PERFORMANCE
-- ============================================================================

CREATE INDEX idx_projects_company ON projects(company_id);
CREATE INDEX idx_company_owner ON company_profiles(owner_id);
CREATE INDEX idx_materials_category ON master_materials(category);
CREATE INDEX idx_contractor_rates ON contractor_rate_cards(contractor_id);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at);
CREATE INDEX idx_sla_alerts_created ON sla_alerts(created_at);
CREATE INDEX idx_sla_alerts_job ON sla_alerts(job_sheet_id);

-- ============================================================================
-- 14. SAMPLE DATA INITIALIZATION (OPTIONAL - For Testing)
-- ============================================================================

-- Insert sample owner
INSERT INTO users (email, password_hash, role, first_name, last_name, phone)
VALUES 
  ('owner@brocaade.com', crypt('SecurePass123!', gen_salt('bf')), 'owner', 'Raj', 'Kumar', '+91-9876543210'),
  ('design@brocaade.com', crypt('DesignPass123!', gen_salt('bf')), 'design_head', 'Priya', 'Singh', '+91-9876543211'),
  ('manager@brocaade.com', crypt('ManagerPass123!', gen_salt('bf')), 'factory_manager', 'Amit', 'Patel', '+91-9876543212'),
  ('contractor@brocaade.com', crypt('ContractorPass123!', gen_salt('bf')), 'contractor', 'Vikram', 'Das', '+91-9876543213'),
  ('delivery@brocaade.com', crypt('DeliveryPass123!', gen_salt('bf')), 'delivery_team', 'Ravi', 'Kumar', '+91-9876543214');

-- Insert sample company profile
INSERT INTO company_profiles (owner_id, company_name, address, city, state, postal_code, country, currency_symbol)
SELECT id, 'Brocaade Interior Solutions', '123 Furniture Lane', 'Bangalore', 'Karnataka', '560001', 'India', '₹'
FROM users WHERE email = 'owner@brocaade.com';

-- Insert sample master materials
INSERT INTO master_materials (company_id, category, material_name, description, unit_of_measure, cost_per_unit)
SELECT 
  cp.id,
  'wood',
  'Teak',
  'Premium Teak Wood',
  'sq.ft',
  850.00
FROM company_profiles cp
WHERE cp.company_name = 'Brocaade Interior Solutions';

-- ============================================================================
-- END OF SCHEMA
-- ============================================================================

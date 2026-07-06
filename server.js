// ============================================================================
// BROCAADE MES - BACKEND SERVICE
// Express.js + PostgreSQL with Full RBAC & Security
// ============================================================================

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const dotenv = require('dotenv');
const multer = require('multer');
const axios = require('axios');
const { v4: uuidv4 } = require('uuid');

dotenv.config();

// ============================================================================
// DATABASE CONNECTION POOL
// ============================================================================

const pool = new Pool({
  user: process.env.DB_USER || 'postgres',
  password: process.env.DB_PASSWORD || 'password',
  host: process.env.DB_HOST || 'localhost',
  port: process.env.DB_PORT || 5432,
  database: process.env.DB_NAME || 'brocaade_mes',
});

// Test database connection
pool.on('error', (err) => {
  console.error('Unexpected error on idle client', err);
});

// ============================================================================
// EXPRESS APP SETUP
// ============================================================================

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-in-production';
const CLOUDINARY_API_KEY = process.env.CLOUDINARY_API_KEY;
const CLOUDINARY_API_SECRET = process.env.CLOUDINARY_API_SECRET;
const CLOUDINARY_CLOUD_NAME = process.env.CLOUDINARY_CLOUD_NAME;

// Middleware
app.use(helmet());
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ limit: '50mb', extended: true }));

// Multer for file uploads
const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 50 * 1024 * 1024 } });

// ============================================================================
// AUTHENTICATION & JWT UTILITIES
// ============================================================================

// JWT Verification Middleware
const verifyToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  
  if (!token) {
    return res.status(401).json({ error: 'No token provided' });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(403).json({ error: 'Invalid or expired token' });
  }
};

// Role-Based Access Control Middleware
const requireRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({
        error: `Access denied. Required role(s): ${allowedRoles.join(', ')}`
      });
    }
    next();
  };
};

// ============================================================================
// AUTHENTICATION ENDPOINTS
// ============================================================================

// User Registration
app.post('/api/auth/register', async (req, res) => {
  const { email, password, first_name, last_name, phone, role } = req.body;

  try {
    // Validate input
    if (!email || !password || !role) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    // Check if user already exists
    const existingUser = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user
    const result = await pool.query(
      `INSERT INTO users (email, password_hash, role, first_name, last_name, phone)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING id, email, role, first_name, last_name`,
      [email, hashedPassword, role, first_name, last_name, phone]
    );

    const user = result.rows[0];

    // Generate JWT
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Log audit
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values)
       VALUES ($1, $2, $3, $4, $5)`,
      [user.id, 'USER_REGISTERED', 'users', user.id, JSON.stringify(user)]
    );

    res.status(201).json({
      message: 'User registered successfully',
      user,
      token,
    });
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).json({ error: 'Server error during registration' });
  }
});

// User Login
app.post('/api/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password required' });
    }

    // Fetch user
    const userResult = await pool.query(
      'SELECT id, email, password_hash, role, first_name, last_name, is_active FROM users WHERE email = $1',
      [email]
    );

    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const user = userResult.rows[0];

    if (!user.is_active) {
      return res.status(403).json({ error: 'User account is inactive' });
    }

    // Verify password
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    // Generate JWT
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role,
      },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // Log audit
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, table_name, record_id)
       VALUES ($1, $2, $3, $4)`,
      [user.id, 'USER_LOGIN', 'users', user.id]
    );

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        role: user.role,
        first_name: user.first_name,
        last_name: user.last_name,
      },
      token,
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Server error during login' });
  }
});

// ============================================================================
// COMPANY PROFILE ENDPOINTS (Owner Only)
// ============================================================================

// Get Company Profile
app.get('/api/company/profile', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM company_profiles WHERE owner_id = $1 LIMIT 1`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Company profile not found' });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching company profile:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Company Profile (Owner Only)
app.put('/api/company/profile', verifyToken, requireRole('owner'), async (req, res) => {
  const {
    company_name,
    logo_url,
    address,
    city,
    state,
    postal_code,
    country,
    phone,
    email,
    tax_id,
    currency_symbol,
    payment_terms,
  } = req.body;

  try {
    const result = await pool.query(
      `UPDATE company_profiles
       SET company_name = COALESCE($1, company_name),
           logo_url = COALESCE($2, logo_url),
           address = COALESCE($3, address),
           city = COALESCE($4, city),
           state = COALESCE($5, state),
           postal_code = COALESCE($6, postal_code),
           country = COALESCE($7, country),
           phone = COALESCE($8, phone),
           email = COALESCE($9, email),
           tax_id = COALESCE($10, tax_id),
           currency_symbol = COALESCE($11, currency_symbol),
           payment_terms = COALESCE($12, payment_terms),
           updated_at = CURRENT_TIMESTAMP
       WHERE owner_id = $13
       RETURNING *`,
      [
        company_name,
        logo_url,
        address,
        city,
        state,
        postal_code,
        country,
        phone,
        email,
        tax_id,
        currency_symbol,
        payment_terms,
        req.user.id,
      ]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Company profile not found' });
    }

    res.json({
      message: 'Company profile updated successfully',
      profile: result.rows[0],
    });
  } catch (error) {
    console.error('Error updating company profile:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================================
// MASTER MATERIALS ENDPOINTS (Owner Only)
// ============================================================================

// Get Master Materials by Category
app.get('/api/master-materials/:category', verifyToken, async (req, res) => {
  const { category } = req.params;

  try {
    // Get user's company
    const companyResult = await pool.query(
      'SELECT id FROM company_profiles WHERE owner_id = $1 LIMIT 1',
      [req.user.id]
    );

    if (companyResult.rows.length === 0) {
      return res.status(403).json({ error: 'Company profile not found' });
    }

    const companyId = companyResult.rows[0].id;

    const result = await pool.query(
      `SELECT * FROM master_materials
       WHERE company_id = $1 AND category = $2 AND is_active = TRUE
       ORDER BY material_name ASC`,
      [companyId, category]
    );

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching materials:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Add Master Material (Owner Only)
app.post('/api/master-materials', verifyToken, requireRole('owner'), async (req, res) => {
  const { category, material_name, description, unit_of_measure, cost_per_unit } = req.body;

  try {
    // Get company ID
    const companyResult = await pool.query(
      'SELECT id FROM company_profiles WHERE owner_id = $1 LIMIT 1',
      [req.user.id]
    );

    if (companyResult.rows.length === 0) {
      return res.status(403).json({ error: 'Company profile not found' });
    }

    const companyId = companyResult.rows[0].id;

    const result = await pool.query(
      `INSERT INTO master_materials 
       (company_id, category, material_name, description, unit_of_measure, cost_per_unit)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [companyId, category, material_name, description, unit_of_measure, cost_per_unit]
    );

    // Audit log
    await pool.query(
      `INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.id, 'CREATE_MATERIAL', 'master_materials', result.rows[0].id, JSON.stringify(result.rows[0])]
    );

    res.status(201).json({
      message: 'Material added successfully',
      material: result.rows[0],
    });
  } catch (error) {
    console.error('Error adding material:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================================
// PROJECT ENDPOINTS
// ============================================================================

// Create Project (Owner & Design Head Only)
app.post('/api/projects', verifyToken, requireRole('owner', 'design_head'), async (req, res) => {
  const {
    project_name,
    project_type,
    client_name,
    client_phone,
    client_email,
    client_address,
    client_city,
    project_start_date,
    project_end_date,
    budget_amount,
  } = req.body;

  try {
    // Get company ID
    const companyResult = await pool.query(
      'SELECT id FROM company_profiles WHERE owner_id = $1 LIMIT 1',
      [req.user.id]
    );

    let companyId;
    if (req.user.role === 'owner') {
      companyId = companyResult.rows[0]?.id;
    } else {
      // For design_head, need to get their associated company
      companyId = companyResult.rows[0]?.id || req.body.company_id;
    }

    if (!companyId) {
      return res.status(403).json({ error: 'Company not found' });
    }

    const result = await pool.query(
      `INSERT INTO projects
       (company_id, project_name, project_type, client_name, client_phone, client_email,
        client_address, client_city, project_start_date, project_end_date, budget_amount, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
       RETURNING *`,
      [
        companyId,
        project_name,
        project_type,
        client_name,
        client_phone,
        client_email,
        client_address,
        client_city,
        project_start_date,
        project_end_date,
        budget_amount,
        req.user.id,
      ]
    );

    await pool.query(
      `INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.id, 'CREATE_PROJECT', 'projects', result.rows[0].id, JSON.stringify(result.rows[0])]
    );

    res.status(201).json({
      message: 'Project created successfully',
      project: result.rows[0],
    });
  } catch (error) {
    console.error('Error creating project:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Projects
app.get('/api/projects', verifyToken, async (req, res) => {
  try {
    let query, params;

    if (req.user.role === 'owner') {
      query = `
        SELECT p.* FROM projects p
        JOIN company_profiles cp ON p.company_id = cp.id
        WHERE cp.owner_id = $1
        ORDER BY p.created_at DESC
      `;
      params = [req.user.id];
    } else if (req.user.role === 'design_head' || req.user.role === 'factory_manager') {
      query = `
        SELECT p.* FROM projects p
        JOIN company_profiles cp ON p.company_id = cp.id
        WHERE cp.owner_id = $1
        ORDER BY p.created_at DESC
      `;
      params = [req.user.id]; // Assuming company association
    } else {
      return res.status(403).json({ error: 'Access denied' });
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================================
// JOB SHEET ENDPOINTS
// ============================================================================

// Create Job Sheet (Design Head Only)
app.post('/api/job-sheets', verifyToken, requireRole('design_head'), async (req, res) => {
  const {
    project_id,
    job_type,
    design_specs,
    is_minor_touchup_required,
    promised_delivery_date,
    estimated_labor_cost,
  } = req.body;

  try {
    // Verify project exists and user has access
    const projectResult = await pool.query(
      `SELECT p.* FROM projects p
       JOIN company_profiles cp ON p.company_id = cp.id
       WHERE p.id = $1 AND cp.owner_id = $2`,
      [project_id, req.user.id]
    );

    if (projectResult.rows.length === 0) {
      return res.status(404).json({ error: 'Project not found' });
    }

    const project = projectResult.rows[0];
    const jobNumber = `JOB-${Date.now()}-${Math.random().toString(36).substr(2, 9).toUpperCase()}`;

    const result = await pool.query(
      `INSERT INTO job_sheets
       (project_id, company_id, job_number, job_type, design_specs, is_minor_touchup_required,
        promised_delivery_date, estimated_labor_cost, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
      [
        project_id,
        project.company_id,
        jobNumber,
        job_type,
        JSON.stringify(design_specs || {}),
        is_minor_touchup_required || false,
        promised_delivery_date,
        estimated_labor_cost,
        req.user.id,
      ]
    );

    const jobSheet = result.rows[0];

    // Initialize milestones based on job type
    await initializeMilestones(jobSheet.id, job_type);

    await pool.query(
      `INSERT INTO audit_logs (user_id, action, table_name, record_id, new_values)
       VALUES ($1, $2, $3, $4, $5)`,
      [req.user.id, 'CREATE_JOB_SHEET', 'job_sheets', jobSheet.id, JSON.stringify(jobSheet)]
    );

    res.status(201).json({
      message: 'Job sheet created successfully',
      jobSheet,
    });
  } catch (error) {
    console.error('Error creating job sheet:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Initialize Milestones Based on Job Type
async function initializeMilestones(jobSheetId, jobType) {
  const milestoneMap = {
    custom_sofa: [
      { sequence: 1, name: 'Design Submitted' },
      { sequence: 2, name: 'Manager Approved' },
      { sequence: 3, name: 'Contractor Material Requisition' },
      { sequence: 4, name: 'Inventory Issued' },
      { sequence: 5, name: 'Wooden Frame Completed' },
      { sequence: 6, name: 'Foaming Completed' },
      { sequence: 7, name: 'Final Sofa Completed' },
      { sequence: 8, name: 'Factory Loading' },
      { sequence: 9, name: 'Customer Site Delivery' },
    ],
    mattress: [
      { sequence: 1, name: 'Order Created' },
      { sequence: 2, name: 'Material Allocation' },
      { sequence: 3, name: 'Foam Cutting' },
      { sequence: 4, name: 'Foam Pasting' },
      { sequence: 5, name: 'Quilt Cutting' },
      { sequence: 6, name: 'Mattress Stitching' },
      { sequence: 7, name: 'Final Packing' },
      { sequence: 8, name: 'Factory Loading' },
      { sequence: 9, name: 'Customer Site Delivery' },
    ],
    readymade_retail: [
      { sequence: 1, name: 'Order Created' },
      { sequence: 2, name: 'Touch-up Evaluation' },
      { sequence: 3, name: 'Factory Loading' },
      { sequence: 4, name: 'Delivery' },
    ],
    false_ceiling: [
      { sequence: 1, name: 'Design Approved' },
      { sequence: 2, name: 'Material Procurement' },
      { sequence: 3, name: 'Installation Started' },
      { sequence: 4, name: 'Installation Completed' },
      { sequence: 5, name: 'Finishing & Inspection' },
      { sequence: 6, name: 'Final Delivery' },
    ],
    lighting_installation: [
      { sequence: 1, name: 'Design Approved' },
      { sequence: 2, name: 'Fixtures Procurement' },
      { sequence: 3, name: 'Installation In Progress' },
      { sequence: 4, name: 'Wiring & Testing' },
      { sequence: 5, name: 'Final Testing' },
      { sequence: 6, name: 'Handover' },
    ],
    painting: [
      { sequence: 1, name: 'Surface Preparation' },
      { sequence: 2, name: 'Primer Applied' },
      { sequence: 3, name: 'Base Coat Applied' },
      { sequence: 4, name: 'Final Coat Applied' },
      { sequence: 5, name: 'Inspection & Touch-up' },
      { sequence: 6, name: 'Completion' },
    ],
    tiling: [
      { sequence: 1, name: 'Surface Preparation' },
      { sequence: 2, name: 'Adhesive & Grout Procurement' },
      { sequence: 3, name: 'Tile Installation Started' },
      { sequence: 4, name: 'Tile Installation Completed' },
      { sequence: 5, name: 'Grouting & Curing' },
      { sequence: 6, name: 'Sealing & Final Inspection' },
    ],
    modular_kitchen: [
      { sequence: 1, name: 'Design Finalization' },
      { sequence: 2, name: 'Materials Procurement' },
      { sequence: 3, name: 'Cabinet Installation' },
      { sequence: 4, name: 'Countertop Installation' },
      { sequence: 5, name: 'Appliance Installation' },
      { sequence: 6, name: 'Plumbing & Electrical' },
      { sequence: 7, name: 'Final Testing & Inspection' },
    ],
    curtains_blinds: [
      { sequence: 1, name: 'Measurements Taken' },
      { sequence: 2, name: 'Material Selection Confirmed' },
      { sequence: 3, name: 'Fabrication In Progress' },
      { sequence: 4, name: 'Installation In Progress' },
      { sequence: 5, name: 'Fitting & Adjustment' },
      { sequence: 6, name: 'Final Inspection' },
    ],
    furniture_assembly: [
      { sequence: 1, name: 'Parts Received & Verified' },
      { sequence: 2, name: 'Assembly Started' },
      { sequence: 3, name: 'Assembly Completed' },
      { sequence: 4, name: 'Quality Check' },
      { sequence: 5, name: 'Delivery Ready' },
    ],
    wall_covering: [
      { sequence: 1, name: 'Wall Preparation' },
      { sequence: 2, name: 'Material Procurement' },
      { sequence: 3, name: 'Installation In Progress' },
      { sequence: 4, name: 'Finishing & Sealing' },
      { sequence: 5, name: 'Inspection' },
    ],
    door_installation: [
      { sequence: 1, name: 'Door Frame Installation' },
      { sequence: 2, name: 'Door Panel Installation' },
      { sequence: 3, name: 'Hardware Installation' },
      { sequence: 4, name: 'Hinges & Lock Adjustment' },
      { sequence: 5, name: 'Final Testing & Handover' },
    ],
    bathroom_renovation: [
      { sequence: 1, name: 'Planning & Design' },
      { sequence: 2, name: 'Demolition Complete' },
      { sequence: 3, name: 'Plumbing Work' },
      { sequence: 4, name: 'Tiling & Finishing' },
      { sequence: 5, name: 'Fixtures Installation' },
      { sequence: 6, name: 'Final Inspection' },
    ],
    balcony_work: [
      { sequence: 1, name: 'Design Approved' },
      { sequence: 2, name: 'Waterproofing Applied' },
      { sequence: 3, name: 'Flooring Installation' },
      { sequence: 4, name: 'Railing Installation' },
      { sequence: 5, name: 'Finishing Work' },
      { sequence: 6, name: 'Inspection & Handover' },
    ],
    shoe_rack_installation: [
      { sequence: 1, name: 'Wall Measurement & Marking' },
      { sequence: 2, name: 'Rack Assembly' },
      { sequence: 3, name: 'Installation In Progress' },
      { sequence: 4, name: 'Wall Fixing & Leveling' },
      { sequence: 5, name: 'Final Inspection' },
    ],
    tv_unit_assembly: [
      { sequence: 1, name: 'Design Approved' },
      { sequence: 2, name: 'Material Procurement' },
      { sequence: 3, name: 'Assembly In Progress' },
      { sequence: 4, name: 'Installation In Progress' },
      { sequence: 5, name: 'Cable Management & Testing' },
      { sequence: 6, name: 'Final Inspection' },
    ],
    dining_set_assembly: [
      { sequence: 1, name: 'Parts Received' },
      { sequence: 2, name: 'Table Assembly' },
      { sequence: 3, name: 'Chairs Assembly' },
      { sequence: 4, name: 'Quality Check' },
      { sequence: 5, name: 'Site Delivery & Setup' },
    ],
    bedroom_furniture: [
      { sequence: 1, name: 'Design Approved' },
      { sequence: 2, name: 'Material Procurement' },
      { sequence: 3, name: 'Assembly In Progress' },
      { sequence: 4, name: 'Finishing & Polishing' },
      { sequence: 5, name: 'Quality Inspection' },
      { sequence: 6, name: 'Site Delivery & Assembly' },
    ],
  };

  const milestones = milestoneMap[jobType] || [
    { sequence: 1, name: 'Start' },
    { sequence: 2, name: 'In Progress' },
    { sequence: 3, name: 'Completion' },
  ];

  for (const milestone of milestones) {
    await pool.query(
      `INSERT INTO job_milestones
       (job_sheet_id, milestone_sequence, milestone_name, sla_hours)
       VALUES ($1, $2, $3, $4)`,
      [jobSheetId, milestone.sequence, milestone.name, 48]
    );
  }
}

// Get Job Sheets
app.get('/api/job-sheets', verifyToken, async (req, res) => {
  try {
    let query, params;

    if (req.user.role === 'owner') {
      query = `
        SELECT js.* FROM job_sheets js
        JOIN company_profiles cp ON js.company_id = cp.id
        WHERE cp.owner_id = $1
        ORDER BY js.created_at DESC
      `;
      params = [req.user.id];
    } else if (req.user.role === 'factory_manager') {
      query = `SELECT * FROM job_sheets WHERE status != 'draft' ORDER BY created_at DESC`;
      params = [];
    } else if (req.user.role === 'contractor') {
      query = `
        SELECT * FROM job_sheets
        WHERE assigned_contractor_id = $1
        ORDER BY created_at DESC
      `;
      params = [req.user.id];
    } else {
      return res.status(403).json({ error: 'Access denied' });
    }

    const result = await pool.query(query, params);
    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching job sheets:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Get Single Job Sheet with Milestones
app.get('/api/job-sheets/:id', verifyToken, async (req, res) => {
  const { id } = req.params;

  try {
    const jobResult = await pool.query(
      'SELECT * FROM job_sheets WHERE id = $1',
      [id]
    );

    if (jobResult.rows.length === 0) {
      return res.status(404).json({ error: 'Job sheet not found' });
    }

    const job = jobResult.rows[0];

    // Check access
    if (
      req.user.role === 'contractor' &&
      job.assigned_contractor_id !== req.user.id
    ) {
      return res.status(403).json({ error: 'Access denied' });
    }

    // Get milestones
    const milestonesResult = await pool.query(
      `SELECT * FROM job_milestones
       WHERE job_sheet_id = $1
       ORDER BY milestone_sequence ASC`,
      [id]
    );

    res.json({
      ...job,
      milestones: milestonesResult.rows,
    });
  } catch (error) {
    console.error('Error fetching job sheet:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Assign Contractor to Job (Factory Manager)
app.post('/api/job-sheets/:id/assign-contractor', verifyToken, requireRole('factory_manager'), async (req, res) => {
  const { id } = req.params;
  const { contractor_id } = req.body;

  try {
    const result = await pool.query(
      `UPDATE job_sheets
       SET assigned_contractor_id = $1, status = 'approved', updated_at = CURRENT_TIMESTAMP
       WHERE id = $2
       RETURNING *`,
      [contractor_id, id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Job sheet not found' });
    }

    const jobSheet = result.rows[0];

    // Create financial ledger entry
    await pool.query(
      `INSERT INTO contractor_financial_ledger
       (contractor_id, job_sheet_id, potential_earnings)
       VALUES ($1, $2, $3)`,
      [contractor_id, id, jobSheet.estimated_labor_cost]
    );

    res.json({
      message: 'Contractor assigned successfully',
      jobSheet,
    });
  } catch (error) {
    console.error('Error assigning contractor:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================================
// MILESTONE & PHOTO UPLOAD ENDPOINTS
// ============================================================================

// Upload Milestone Photo
app.post(
  '/api/milestones/:id/upload-photo',
  verifyToken,
  upload.single('photo'),
  async (req, res) => {
    const { id } = req.params;

    if (!req.file) {
      return res.status(400).json({ error: 'No photo provided' });
    }

    try {
      // Upload to Cloudinary
      const b64 = Buffer.from(req.file.buffer).toString('base64');
      const dataURI = 'data:' + req.file.mimetype + ';base64,' + b64;

      const cloudinaryResponse = await axios.post(
        `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/image/upload`,
        {
          file: dataURI,
          upload_preset: process.env.CLOUDINARY_UPLOAD_PRESET || 'brocaade_mes',
          folder: 'brocaade-mes/milestones',
        }
      );

      const photoUrl = cloudinaryResponse.data.secure_url;

      // Update milestone
      const result = await pool.query(
        `UPDATE job_milestones
         SET photo_url = $1, 
             photo_uploaded_at = CURRENT_TIMESTAMP,
             uploaded_by = $2,
             status = 'awaiting_approval'
         WHERE id = $3
         RETURNING *`,
        [photoUrl, req.user.id, id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Milestone not found' });
      }

      res.json({
        message: 'Photo uploaded successfully',
        milestone: result.rows[0],
      });
    } catch (error) {
      console.error('Error uploading photo:', error);
      res.status(500).json({ error: 'Error uploading photo' });
    }
  }
);

// Approve Milestone (Factory Manager)
app.post(
  '/api/milestones/:id/approve',
  verifyToken,
  requireRole('factory_manager'),
  async (req, res) => {
    const { id } = req.params;
    const { approval_notes } = req.body;

    try {
      // Get milestone
      const milestoneResult = await pool.query(
        'SELECT * FROM job_milestones WHERE id = $1',
        [id]
      );

      if (milestoneResult.rows.length === 0) {
        return res.status(404).json({ error: 'Milestone not found' });
      }

      const milestone = milestoneResult.rows[0];

      // Update milestone
      const result = await pool.query(
        `UPDATE job_milestones
         SET status = 'approved',
             approved_by = $1,
             approved_at = CURRENT_TIMESTAMP,
             approval_notes = $2,
             completed_at = CURRENT_TIMESTAMP
         WHERE id = $3
         RETURNING *`,
        [req.user.id, approval_notes, id]
      );

      // Update contractor's earned amount
      if (milestone.job_sheet_id) {
        // Calculate percentage: (current milestone / total milestones) * job labor cost
        const jobResult = await pool.query(
          'SELECT estimated_labor_cost FROM job_sheets WHERE id = $1',
          [milestone.job_sheet_id]
        );

        const totalMilestonesResult = await pool.query(
          'SELECT COUNT(*) as total FROM job_milestones WHERE job_sheet_id = $1',
          [milestone.job_sheet_id]
        );

        const jobLaborCost = jobResult.rows[0].estimated_labor_cost;
        const totalMilestones = parseInt(totalMilestonesResult.rows[0].total);
        const earnedPerMilestone = jobLaborCost / totalMilestones;

        await pool.query(
          `UPDATE contractor_financial_ledger
           SET earned_amount_gross = earned_amount_gross + $1,
               updated_at = CURRENT_TIMESTAMP
           WHERE job_sheet_id = $2`,
          [earnedPerMilestone, milestone.job_sheet_id]
        );
      }

      res.json({
        message: 'Milestone approved successfully',
        milestone: result.rows[0],
      });
    } catch (error) {
      console.error('Error approving milestone:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// ============================================================================
// CONTRACTOR FINANCIAL ENDPOINTS
// ============================================================================

// Get Contractor Financial Summary
app.get('/api/contractor/financial-summary', verifyToken, requireRole('contractor'), async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT
        contractor_id,
        SUM(potential_earnings) as total_potential_earnings,
        SUM(earned_amount_gross) as total_earned_amount,
        SUM(total_advances_paid) as total_advances_paid,
        SUM(net_balance_due) as total_balance_due
       FROM contractor_financial_ledger
       WHERE contractor_id = $1
       GROUP BY contractor_id`,
      [req.user.id]
    );

    if (result.rows.length === 0) {
      return res.json({
        total_potential_earnings: 0,
        total_earned_amount: 0,
        total_advances_paid: 0,
        total_balance_due: 0,
      });
    }

    res.json(result.rows[0]);
  } catch (error) {
    console.error('Error fetching financial summary:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Log Advance Payment (Owner/Manager)
app.post(
  '/api/contractor/:contractorId/log-advance',
  verifyToken,
  requireRole('owner', 'factory_manager'),
  async (req, res) => {
    const { contractorId } = req.params;
    const { amount, payment_date, payment_method, notes } = req.body;

    try {
      // Get latest ledger for contractor
      const ledgerResult = await pool.query(
        `SELECT id FROM contractor_financial_ledger
         WHERE contractor_id = $1
         ORDER BY created_at DESC
         LIMIT 1`,
        [contractorId]
      );

      if (ledgerResult.rows.length === 0) {
        return res.status(404).json({ error: 'Contractor ledger not found' });
      }

      const ledgerId = ledgerResult.rows[0].id;

      // Log advance
      const advanceResult = await pool.query(
        `INSERT INTO advance_payments
         (ledger_id, contractor_id, amount, payment_date, payment_method, notes, recorded_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *`,
        [ledgerId, contractorId, amount, payment_date, payment_method, notes, req.user.id]
      );

      // Update ledger
      await pool.query(
        `UPDATE contractor_financial_ledger
         SET total_advances_paid = total_advances_paid + $1,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $2`,
        [amount, ledgerId]
      );

      res.json({
        message: 'Advance payment recorded successfully',
        advance: advanceResult.rows[0],
      });
    } catch (error) {
      console.error('Error logging advance:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// Settlement & Zero-Out Payout (Owner Only)
app.post(
  '/api/contractor/:contractorId/settle-payout',
  verifyToken,
  requireRole('owner'),
  async (req, res) => {
    const { contractorId } = req.params;

    try {
      // Get all ledger entries for contractor
      const ledgerResult = await pool.query(
        `SELECT id, earned_amount_gross, total_advances_paid
         FROM contractor_financial_ledger
         WHERE contractor_id = $1`,
        [contractorId]
      );

      if (ledgerResult.rows.length === 0) {
        return res.status(404).json({ error: 'No ledger found for contractor' });
      }

      let totalEarned = 0;
      let totalAdvances = 0;

      for (const ledger of ledgerResult.rows) {
        totalEarned += ledger.earned_amount_gross || 0;
        totalAdvances += ledger.total_advances_paid || 0;
      }

      const netAmount = totalEarned - totalAdvances;

      // Create settlement record
      await pool.query(
        `INSERT INTO contractor_settlements
         (contractor_id, total_earned_amount, total_advances_paid, net_amount_paid, settled_by)
         VALUES ($1, $2, $3, $4, $5)`,
        [contractorId, totalEarned, totalAdvances, netAmount, req.user.id]
      );

      // Reset ledgers (but keep potential earnings)
      await pool.query(
        `UPDATE contractor_financial_ledger
         SET earned_amount_gross = 0,
             total_advances_paid = 0,
             updated_at = CURRENT_TIMESTAMP
         WHERE contractor_id = $1`,
        [contractorId]
      );

      res.json({
        message: 'Contractor payment settled successfully',
        settlement: {
          contractor_id: contractorId,
          total_earned_amount: totalEarned,
          total_advances_paid: totalAdvances,
          net_amount_paid: netAmount,
        },
      });
    } catch (error) {
      console.error('Error settling payout:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// ============================================================================
// DELIVERY ENDPOINTS
// ============================================================================

// Create Delivery Record
app.post('/api/deliveries', verifyToken, requireRole('delivery_team'), async (req, res) => {
  const {
    job_sheet_id,
    delivery_date,
    delivery_time,
    delivery_address,
    delivery_city,
    delivery_phone,
    cod_amount,
  } = req.body;

  try {
    const result = await pool.query(
      `INSERT INTO deliveries
       (job_sheet_id, delivery_team_member_id, delivery_date, delivery_time,
        delivery_address, delivery_city, delivery_phone, cod_amount, status)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending')
       RETURNING *`,
      [
        job_sheet_id,
        req.user.id,
        delivery_date,
        delivery_time,
        delivery_address,
        delivery_city,
        delivery_phone,
        cod_amount,
      ]
    );

    res.status(201).json({
      message: 'Delivery record created',
      delivery: result.rows[0],
    });
  } catch (error) {
    console.error('Error creating delivery:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Update Delivery Status & COD Collection
app.put(
  '/api/deliveries/:id',
  verifyToken,
  requireRole('delivery_team'),
  upload.single('delivery_photo'),
  async (req, res) => {
    const { id } = req.params;
    const { status, amount_collected, payment_method, delivery_notes } = req.body;

    try {
      let photoUrl = null;

      if (req.file) {
        const b64 = Buffer.from(req.file.buffer).toString('base64');
        const dataURI = 'data:' + req.file.mimetype + ';base64,' + b64;

        const cloudinaryResponse = await axios.post(
          `https://api.cloudinary.com/v1_1/${CLOUDINARY_CLOUD_NAME}/image/upload`,
          {
            file: dataURI,
            upload_preset: process.env.CLOUDINARY_UPLOAD_PRESET || 'brocaade_mes',
            folder: 'brocaade-mes/deliveries',
          }
        );

        photoUrl = cloudinaryResponse.data.secure_url;
      }

      const result = await pool.query(
        `UPDATE deliveries
         SET status = COALESCE($1, status),
             amount_collected = COALESCE($2, amount_collected),
             payment_method = COALESCE($3, payment_method),
             delivery_notes = COALESCE($4, delivery_notes),
             delivery_photo_url = COALESCE($5, delivery_photo_url),
             delivery_photo_timestamp = CASE WHEN $5 IS NOT NULL THEN CURRENT_TIMESTAMP ELSE delivery_photo_timestamp END,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = $6
         RETURNING *`,
        [status, amount_collected, payment_method, delivery_notes, photoUrl, id]
      );

      if (result.rows.length === 0) {
        return res.status(404).json({ error: 'Delivery not found' });
      }

      res.json({
        message: 'Delivery updated successfully',
        delivery: result.rows[0],
      });
    } catch (error) {
      console.error('Error updating delivery:', error);
      res.status(500).json({ error: 'Server error' });
    }
  }
);

// ============================================================================
// REPORTING & ANALYTICS ENDPOINTS
// ============================================================================

// Owner Dashboard Summary
app.get('/api/owner/dashboard-summary', verifyToken, requireRole('owner'), async (req, res) => {
  try {
    const activeJobsResult = await pool.query(
      `SELECT COUNT(*) as count FROM job_sheets
       WHERE company_id IN (SELECT id FROM company_profiles WHERE owner_id = $1)
       AND status IN ('in_progress', 'submitted')`,
      [req.user.id]
    );

    const pipelineValueResult = await pool.query(
      `SELECT SUM(estimated_labor_cost) as total FROM job_sheets
       WHERE company_id IN (SELECT id FROM company_profiles WHERE owner_id = $1)
       AND status IN ('in_progress', 'submitted')`,
      [req.user.id]
    );

    const liabilitiesResult = await pool.query(
      `SELECT SUM(net_balance_due) as total FROM contractor_financial_ledger
       WHERE job_sheet_id IN (
         SELECT id FROM job_sheets
         WHERE company_id IN (SELECT id FROM company_profiles WHERE owner_id = $1)
       )`,
      [req.user.id]
    );

    const pendingDeliveriesResult = await pool.query(
      `SELECT COUNT(*) as count, SUM(cod_amount) as total FROM deliveries
       WHERE job_sheet_id IN (
         SELECT id FROM job_sheets
         WHERE company_id IN (SELECT id FROM company_profiles WHERE owner_id = $1)
       )
       AND status IN ('pending', 'in_transit')`,
      [req.user.id]
    );

    const slaBreachesResult = await pool.query(
      `SELECT COUNT(*) as count FROM sla_breach_alerts
       WHERE job_id IN (
         SELECT id FROM job_sheets
         WHERE company_id IN (SELECT id FROM company_profiles WHERE owner_id = $1)
       )
       AND is_breached = TRUE`,
      [req.user.id]
    );

    res.json({
      active_jobs: parseInt(activeJobsResult.rows[0]?.count || 0),
      pipeline_value: pipelineValueResult.rows[0]?.total || 0,
      total_outstanding_liabilities: liabilitiesResult.rows[0]?.total || 0,
      pending_deliveries: parseInt(pendingDeliveriesResult.rows[0]?.count || 0),
      pending_cod_value: pendingDeliveriesResult.rows[0]?.total || 0,
      sla_breaches: parseInt(slaBreachesResult.rows[0]?.count || 0),
    });
  } catch (error) {
    console.error('Error fetching dashboard summary:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// SLA Alerts
app.get('/api/sla-alerts', verifyToken, requireRole('owner', 'factory_manager'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        js.id as job_id,
        js.job_number,
        jm.milestone_name,
        jm.sla_hours,
        EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - jm.started_at)) / 3600 as hours_elapsed,
        CASE 
          WHEN EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - jm.started_at)) / 3600 > jm.sla_hours THEN 'CRITICAL'
          ELSE 'WARNING'
        END as severity,
        jm.status
      FROM job_sheets js
      JOIN job_milestones jm ON js.id = jm.job_sheet_id
      WHERE jm.status NOT IN ('approved', 'skipped')
        AND jm.started_at IS NOT NULL
      ORDER BY hours_elapsed DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching SLA alerts:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// Contractor Earnings Summary
app.get('/api/contractors/earnings-summary', verifyToken, requireRole('owner'), async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT
        c.id,
        c.first_name || ' ' || c.last_name as contractor_name,
        COUNT(DISTINCT cfl.job_sheet_id) as total_jobs,
        COALESCE(SUM(cfl.potential_earnings), 0) as total_potential,
        COALESCE(SUM(cfl.earned_amount_gross), 0) as total_earned,
        COALESCE(SUM(cfl.total_advances_paid), 0) as total_advances,
        COALESCE(SUM(cfl.net_balance_due), 0) as total_balance_due
      FROM users c
      LEFT JOIN contractor_financial_ledger cfl ON c.id = cfl.contractor_id
      WHERE c.role = 'contractor'
      GROUP BY c.id, c.first_name, c.last_name
      ORDER BY total_balance_due DESC
    `);

    res.json(result.rows);
  } catch (error) {
    console.error('Error fetching earnings summary:', error);
    res.status(500).json({ error: 'Server error' });
  }
});

// ============================================================================
// ERROR HANDLING & SERVER START
// ============================================================================

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

const server = app.listen(PORT, () => {
  console.log(`Brocaade MES Backend running on http://localhost:${PORT}`);
  console.log('Environment:', process.env.NODE_ENV || 'development');
  console.log('Database:', process.env.DB_NAME || 'brocaade_mes');
});

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully...');
  server.close(() => {
    console.log('Server closed');
    pool.end();
    process.exit(0);
  });
});

module.exports = app;

import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcryptjs from 'bcryptjs';
import pkg from 'pg';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const { Pool } = pkg;
dotenv.config();

const app = express();
const __dirname = path.dirname(fileURLToPath(import.meta.url));

// Middleware
app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(cors());
app.use(express.json());
app.use(express.static('.'));

// Database connection
const pool = new Pool({
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
});

// ============================================================================
// SERVE FRONTEND.HTML
// ============================================================================

app.get('/frontend.html', (req, res) => {
  const filePath = path.join(__dirname, 'frontend.html');
  if (fs.existsSync(filePath)) {
    res.sendFile(filePath);
  } else {
    res.status(404).json({ error: 'frontend.html not found' });
  }
});

app.get('/', (req, res) => {
  res.json({ message: 'Brocaade MES Backend API', version: '1.0.0' });
});

// ============================================================================
// AUTHENTICATION ENDPOINTS
// ============================================================================

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Demo users
    const demoUsers = {
      'owner@brocaade.com': { id: 1, email: 'owner@brocaade.com', role: 'owner', password: 'SecurePass123!' },
      'design@brocaade.com': { id: 2, email: 'design@brocaade.com', role: 'design_head', password: 'DesignPass123!' },
      'manager@brocaade.com': { id: 3, email: 'manager@brocaade.com', role: 'factory_manager', password: 'ManagerPass123!' },
      'contractor@brocaade.com': { id: 4, email: 'contractor@brocaade.com', role: 'contractor', password: 'ContractorPass123!' },
      'delivery@brocaade.com': { id: 5, email: 'delivery@brocaade.com', role: 'delivery_team', password: 'DeliveryPass123!' }
    };

    const user = demoUsers[email];
    if (!user || user.password !== password) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign({ id: user.id, email: user.email, role: user.role }, process.env.JWT_SECRET, { expiresIn: '7d' });

    res.json({
      token,
      user: { id: user.id, email: user.email, role: user.role }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// PROTECTED ROUTES - REQUIRE JWT
// ============================================================================

const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
};

// ============================================================================
// PROJECTS ENDPOINTS
// ============================================================================

app.get('/api/projects', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM projects LIMIT 10');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/projects', verifyToken, async (req, res) => {
  try {
    const { project_name, project_type, client_name, client_phone, budget_amount } = req.body;
    const result = await pool.query(
      'INSERT INTO projects (project_name, project_type, client_name, client_phone, budget_amount, created_by) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *',
      [project_name, project_type, client_name, client_phone, budget_amount, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// JOB SHEETS ENDPOINTS
// ============================================================================

app.get('/api/job-sheets', verifyToken, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM job_sheets LIMIT 10');
    res.json(result.rows);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/job-sheets', verifyToken, async (req, res) => {
  try {
    const { project_id, job_type, material_type, promised_delivery_date } = req.body;
    const result = await pool.query(
      'INSERT INTO job_sheets (project_id, job_type, material_type, promised_delivery_date, created_by) VALUES ($1, $2, $3, $4, $5) RETURNING *',
      [project_id, job_type, material_type, promised_delivery_date, req.user.id]
    );
    res.json(result.rows[0]);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// DASHBOARD ENDPOINT
// ============================================================================

app.get('/api/owner/dashboard-summary', verifyToken, async (req, res) => {
  try {
    const result = await pool.query(`
      SELECT 
        COUNT(*) FILTER (WHERE status != 'completed') as active_jobs,
        COALESCE(SUM(CASE WHEN status != 'completed' THEN estimated_labor_cost ELSE 0 END), 0) as pipeline_value,
        COALESCE(SUM(earned_amount_gross - total_advances_paid), 0) as total_outstanding_liabilities,
        0 as pending_cod_value
      FROM job_sheets
    `);
    
    res.json({
      active_jobs: parseInt(result.rows[0].active_jobs) || 0,
      pipeline_value: parseFloat(result.rows[0].pipeline_value) || 0,
      total_outstanding_liabilities: parseFloat(result.rows[0].total_outstanding_liabilities) || 0,
      pending_cod_value: 0
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ============================================================================
// HEALTH CHECK
// ============================================================================

app.get('/health', (req, res) => {
  res.json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ============================================================================
// ERROR HANDLING
// ============================================================================

app.use((req, res) => {
  res.status(404).json({ error: 'Route not found' });
});

// ============================================================================
// START SERVER
// ============================================================================

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Brocaade MES Backend running on port ${PORT}`);
});

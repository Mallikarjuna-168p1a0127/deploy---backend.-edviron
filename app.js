const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const fs = require('fs');
const csv = require('csv-parser');

const app = express();
const JWT_SECRET = 'your-secret-key'; // In production, use environment variable

// Middleware
app.use(cors());
app.use(express.json());

// Database setup
const db = new sqlite3.Database('school_payments.db', (err) => {
  if (err) {
    console.error('Error connecting to database:', err);
  } else {
    console.log('Connected to SQLite database');
    initializeDatabase();
  }
});

// Database initialization
function initializeDatabase() {
  db.serialize(() => {
    // Users table for authentication
    db.run(`CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      role TEXT NOT NULL
    )`);

    // Collect requests table
    db.run(`CREATE TABLE IF NOT EXISTS collect_requests (
      _id TEXT PRIMARY KEY,
      school_id TEXT NOT NULL,
      trustee_id TEXT NOT NULL,
      gateway TEXT NOT NULL,
      order_amount REAL NOT NULL,
      custom_order_id TEXT UNIQUE NOT NULL
    )`);

    // Transaction status table
    db.run(`CREATE TABLE IF NOT EXISTS transaction_status (
      _id TEXT PRIMARY KEY,
      collect_id TEXT NOT NULL,
      status TEXT NOT NULL,
      payment_method TEXT,
      gateway TEXT,
      transaction_amount REAL,
      bank_refrence TEXT,
      FOREIGN KEY (collect_id) REFERENCES collect_requests(_id)
    )`);

    // Import CSV data after table creation
    importCSVData();
  });
}

// Function to import CSV data
function importCSVData() {
  // Import collect requests
  const collectRequests = [];
  fs.createReadStream('test.collect_request.csv')
    .pipe(csv())
    .on('data', (row) => {
      collectRequests.push(row);
    })
    .on('end', () => {
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO collect_requests 
        (_id, school_id, trustee_id, gateway, order_amount, custom_order_id)
        VALUES (?, ?, ?, ?, ?, ?)
      `);

      collectRequests.forEach(row => {
        stmt.run(
          row._id,
          row.school_id,
          row.trustee_id,
          row.gateway,
          parseFloat(row.order_amount),
          row.custom_order_id
        );
      });
      stmt.finalize();
      console.log('Collect requests imported successfully');
    });

  // Import transaction status
  const transactionStatus = [];
  fs.createReadStream('test.collect_request_status.csv')
    .pipe(csv())
    .on('data', (row) => {
      transactionStatus.push(row);
    })
    .on('end', () => {
      const stmt = db.prepare(`
        INSERT OR REPLACE INTO transaction_status 
        (_id, collect_id, status, payment_method, gateway, transaction_amount, bank_refrence)
        VALUES (?, ?, ?, ?, ?, ?, ?)
      `);

      transactionStatus.forEach(row => {
        stmt.run(
          row._id,
          row.collect_id,
          row.status,
          row.payment_method,
          row.gateway,
          parseFloat(row.transaction_amount),
          row.bank_refrence
        );
      });
      stmt.finalize();
      console.log('Transaction status imported successfully');
    });
}

// Authentication middleware
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Authentication token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

app.post('/api/register', async (req, res) => {
    try {
      const { username, password, role } = req.body;
      const hashedPassword = await bcrypt.hash(password, 10);
  
      db.run('INSERT INTO users (username, password, role) VALUES (?, ?, ?)',
        [username, hashedPassword, role],
        function(err) {
          if (err) {
            return res.status(400).json({ error: 'Username already exists' });
          }
          res.status(201).json({ message: 'User registered successfully' });
        });
    } catch (error) {
      res.status(500).json({ error: 'Error registering user' });
    }
  });
  
  // User login
  app.post('/api/login', async (req, res) => {
    try {
      const { username, password } = req.body;
  
      db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
        if (err || !user) {
          return res.status(400).json({ error: 'User not found' });
        }
  
        const validPassword = await bcrypt.compare(password, user.password);
        if (!validPassword) {
          return res.status(400).json({ error: 'Invalid password' });
        }
  
        const token = jwt.sign({ id: user.id, role: user.role }, JWT_SECRET, { expiresIn: '24h' });
        res.json({ token });
      });
    } catch (error) {
      res.status(500).json({ error: 'Error logging in' });
    }
  });

// Fetch all transactions
app.get('/api/transactions', authenticateToken, (req, res) => {
  const query = `
    SELECT 
      cr._id as collect_id,
      cr.school_id,
      cr.gateway,
      cr.order_amount,
      ts.transaction_amount,
      ts.status,
      cr.custom_order_id,
      ts.payment_method,
      ts.bank_refrence
    FROM collect_requests cr
    LEFT JOIN transaction_status ts ON cr._id = ts.collect_id
    ORDER BY cr._id DESC
  `;

  db.all(query, [], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Error fetching transactions' });
    }
    res.json(rows);
  });
});

// Fetch transactions by school
app.get('/api/transactions/school/:schoolId', authenticateToken, (req, res) => {
  const { schoolId } = req.params;
  
  const query = `
    SELECT 
      cr._id as collect_id,
      cr.school_id,
      cr.gateway,
      cr.order_amount,
      ts.transaction_amount,
      ts.status,
      cr.custom_order_id,
      ts.payment_method,
      ts.bank_refrence
    FROM collect_requests cr
    LEFT JOIN transaction_status ts ON cr._id = ts.collect_id
    WHERE cr.school_id = ?
    ORDER BY cr._id DESC
  `;

  db.all(query, [schoolId], (err, rows) => {
    if (err) {
      return res.status(500).json({ error: 'Error fetching school transactions' });
    }
    res.json(rows);
  });
});

// Check transaction status
app.get('/api/transaction/status/:customOrderId', authenticateToken, (req, res) => {
  const { customOrderId } = req.params;
  
  const query = `
    SELECT ts.status, ts.payment_method, ts.transaction_amount, ts.bank_refrence
    FROM collect_requests cr
    LEFT JOIN transaction_status ts ON cr._id = ts.collect_id
    WHERE cr.custom_order_id = ?
  `;

  db.get(query, [customOrderId], (err, row) => {
    if (err) {
      return res.status(500).json({ error: 'Error checking transaction status' });
    }
    if (!row) {
      return res.status(404).json({ error: 'Transaction not found' });
    }
    res.json(row);
  });
});

// Webhook for status updates
app.post('/api/webhook/transaction', (req, res) => {
  const { order_info } = req.body;
  
  if (!order_info) {
    return res.status(400).json({ error: 'Invalid webhook payload' });
  }

  const { order_id, order_amount, transaction_amount, gateway, bank_reference } = order_info;

  db.run(`
    INSERT INTO transaction_status 
    (collect_id, status, transaction_amount, gateway, bank_refrence)
    VALUES (?, 'SUCCESS', ?, ?, ?)
    ON CONFLICT(collect_id) DO UPDATE SET 
    status = 'SUCCESS',
    transaction_amount = excluded.transaction_amount,
    gateway = excluded.gateway,
    bank_refrence = excluded.bank_refrence
  `,
    [order_id, transaction_amount, gateway, bank_reference],
    function(err) {
      if (err) {
        return res.status(500).json({ error: 'Error updating transaction status' });
      }
      res.json({ message: 'Transaction status updated successfully' });
    }
  );
});

// Manual status update
app.post('/api/transaction/status/update', authenticateToken, (req, res) => {
  const { customOrderId, status, payment_method } = req.body;
  
  if (!customOrderId || !status) {
    return res.status(400).json({ error: 'Custom order ID and status are required' });
  }

  db.get(
    'SELECT _id FROM collect_requests WHERE custom_order_id = ?',
    [customOrderId],
    (err, row) => {
      if (err || !row) {
        return res.status(404).json({ error: 'Transaction not found' });
      }

      db.run(`
        INSERT INTO transaction_status (collect_id, status, payment_method)
        VALUES (?, ?, ?)
        ON CONFLICT(collect_id) DO UPDATE SET 
        status = excluded.status,
        payment_method = excluded.payment_method
      `,
        [row._id, status, payment_method],
        function(err) {
          if (err) {
            return res.status(500).json({ error: 'Error updating transaction status' });
          }
          res.json({ message: 'Transaction status updated successfully' });
        }
      );
    }
  );
});

// Start server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
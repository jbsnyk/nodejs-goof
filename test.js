// SQL Injection Vulnerability Example
// This code is vulnerable to SQL injection attacks

const express = require('express');
const mysql = require('mysql2');
const app = express();

// Database connection setup
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: 'password',
  database: 'testdb'
});

// VULNERABLE FUNCTION - SQL Injection Example
function getUserByEmail(userEmail) {
  // This is vulnerable because user input is directly concatenated into the SQL query
  const query = `SELECT * FROM users WHERE email = '${userEmail}'`;
  
  console.log('Executing query:', query);
  
  connection.query(query, (error, results, fields) => {
    if (error) {
      console.error('Database error:', error);
      return;
    }
    
    if (results.length > 0) {
      console.log('User found:', results[0]);
    } else {
      console.log('No user found with email:', userEmail);
    }
  });
}

// Example usage that demonstrates the vulnerability
function demonstrateSQLInjection() {
  console.log('--- Normal usage ---');
  getUserByEmail('user@example.com');
  
  console.log('\n--- SQL Injection Attack ---');
  // This malicious input can bypass authentication or extract sensitive data
  const maliciousInput = "' OR '1'='1"; // This will return all users
  getUserByEmail(maliciousInput);
  
  console.log('\n--- More advanced SQL Injection ---');
  // This could be used to drop tables or perform other malicious operations
  const destructiveInput = "'; DROP TABLE users; --";
  getUserByEmail(destructiveInput);
}

// Express route that's vulnerable to SQL injection
app.get('/user/:email', (req, res) => {
  const userEmail = req.params.email;
  
  // VULNERABLE: Direct string concatenation in SQL query
  const query = `SELECT * FROM users WHERE email = '${userEmail}'`;
  
  connection.query(query, (error, results) => {
    if (error) {
      res.status(500).json({ error: 'Database error' });
      return;
    }
    res.json(results);
  });
});

// Run the demonstration
demonstrateSQLInjection();

app.listen(3000, () => {
  console.log('Server running on port 3000');
});

// SECURE VERSION (commented out for comparison)
/*
function getUserByEmailSecure(userEmail) {
  // This is secure because it uses parameterized queries
  const query = 'SELECT * FROM users WHERE email = ?';
  
  connection.query(query, [userEmail], (error, results, fields) => {
    if (error) {
      console.error('Database error:', error);
      return;
    }
    
    if (results.length > 0) {
      console.log('User found:', results[0]);
    } else {
      console.log('No user found with email:', userEmail);
    }
  });
}
*/
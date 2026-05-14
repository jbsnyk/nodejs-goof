// Cross-Site Scripting (XSS) Vulnerability Examples
// This code contains multiple XSS vulnerabilities for demonstration

const express = require('express');
const app = express();

// Middleware to parse URL-encoded bodies
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// In-memory storage for demonstration (normally would be a database)
const comments = [];
const users = [
  { id: 1, name: 'John Doe', email: 'john@example.com' },
  { id: 2, name: 'Jane Smith', email: 'jane@example.com' }
];

// VULNERABLE: Reflected XSS - User input directly rendered without sanitization
app.get('/search', (req, res) => {
  const searchTerm = req.query.q;
  
  // Vulnerable: Direct insertion of user input into HTML response
  const html = `
    <html>
      <head><title>Search Results</title></head>
      <body>
        <h1>Search Results</h1>
        <p>You searched for: ${searchTerm}</p>
        <p>No results found for "${searchTerm}"</p>
        <a href="/">Back to Home</a>
      </body>
    </html>
  `;
  
  res.send(html);
});

// VULNERABLE: Reflected XSS in error messages
app.get('/user/:id', (req, res) => {
  const userId = req.params.id;
  const user = users.find(u => u.id == userId);
  
  if (!user) {
    // Vulnerable: User input reflected in error message
    return res.send(`<h1>Error</h1><p>User with ID ${userId} not found!</p>`);
  }
  
  res.json(user);
});

// VULNERABLE: Stored XSS - User input stored and displayed without sanitization
app.post('/comment', (req, res) => {
  const { name, comment } = req.body;
  
  // Vulnerable: Storing unsanitized user input
  comments.push({
    id: comments.length + 1,
    name: name,
    comment: comment,
    timestamp: new Date().toISOString()
  });
  
  res.redirect('/comments');
});

// VULNERABLE: Displaying stored XSS content
app.get('/comments', (req, res) => {
  let commentsHtml = '';
  
  comments.forEach(comment => {
    // Vulnerable: Direct insertion of stored user content
    commentsHtml += `
      <div style="border: 1px solid #ccc; margin: 10px; padding: 10px;">
        <strong>${comment.name}</strong> said:
        <p>${comment.comment}</p>
        <small>Posted on: ${comment.timestamp}</small>
      </div>
    `;
  });
  
  const html = `
    <html>
      <head><title>Comments</title></head>
      <body>
        <h1>User Comments</h1>
        
        <!-- Comment Form -->
        <form method="POST" action="/comment">
          <div>
            <label>Name: <input type="text" name="name" required></label>
          </div>
          <div>
            <label>Comment: <textarea name="comment" required></textarea></label>
          </div>
          <button type="submit">Post Comment</button>
        </form>
        
        <hr>
        
        <!-- Display Comments (VULNERABLE) -->
        <h2>All Comments:</h2>
        ${commentsHtml}
        
      </body>
    </html>
  `;
  
  res.send(html);
});

// VULNERABLE: DOM-based XSS simulation
app.get('/welcome', (req, res) => {
  const html = `
    <html>
      <head><title>Welcome</title></head>
      <body>
        <h1>Welcome Page</h1>
        <div id="welcome-message"></div>
        
        <script>
          // Vulnerable: Using URL parameters directly in DOM manipulation
          const urlParams = new URLSearchParams(window.location.search);
          const userName = urlParams.get('name');
          
          if (userName) {
            // This is vulnerable to DOM-based XSS
            document.getElementById('welcome-message').innerHTML = 
              '<h2>Welcome, ' + userName + '!</h2>';
          }
        </script>
      </body>
    </html>
  `;
  
  res.send(html);
});

// Home page with links to demonstrate vulnerabilities
app.get('/', (req, res) => {
  const html = `
    <html>
      <head><title>XSS Vulnerability Demo</title></head>
      <body>
        <h1>XSS Vulnerability Demonstration</h1>
        
        <h2>Try these XSS attacks:</h2>
        
        <h3>1. Reflected XSS via Search:</h3>
        <p>Try: <a href="/search?q=<script>alert('XSS')</script>">
          /search?q=&lt;script&gt;alert('XSS')&lt;/script&gt;</a></p>
        
        <h3>2. Reflected XSS via User ID:</h3>
        <p>Try: <a href="/user/<script>alert('XSS')</script>">
          /user/&lt;script&gt;alert('XSS')&lt;/script&gt;</a></p>
        
        <h3>3. Stored XSS via Comments:</h3>
        <p><a href="/comments">Go to Comments Page</a> and try posting:</p>
        <ul>
          <li>Name: <code>&lt;script&gt;alert('Stored XSS')&lt;/script&gt;</code></li>
          <li>Comment: <code>&lt;img src=x onerror=alert('XSS')&gt;</code></li>
        </ul>
        
        <h3>4. DOM-based XSS:</h3>
        <p>Try: <a href="/welcome?name=<script>alert('DOM XSS')</script>">
          /welcome?name=&lt;script&gt;alert('DOM XSS')&lt;/script&gt;</a></p>
        
        <hr>
        <p><strong>Note:</strong> These are intentional vulnerabilities for demonstration purposes.</p>
      </body>
    </html>
  `;
  
  res.send(html);
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`XSS Demo Server running on http://localhost:${PORT}`);
  console.log('Visit http://localhost:3000 to see XSS vulnerability examples');
});

module.exports = app;
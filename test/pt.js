// Path Traversal Vulnerability Examples
// This code contains multiple path traversal vulnerabilities for demonstration

const express = require('express');
const fs = require('fs');
const path = require('path');
const app = express();

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// VULNERABLE: Basic Path Traversal - Direct file access
app.get('/file/:filename', (req, res) => {
  const filename = req.params.filename;
  
  // Vulnerable: No validation of filename parameter
  // Allows access to any file on the system
  const filePath = './uploads/' + filename;
  
  console.log('Attempting to read file:', filePath);
  
  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send(`File not found: ${filename}`);
    }
    
    res.send(`<pre>${data}</pre>`);
  });
});

// VULNERABLE: Path Traversal with query parameter
app.get('/download', (req, res) => {
  const file = req.query.file;
  
  if (!file) {
    return res.status(400).send('File parameter required');
  }
  
  // Vulnerable: Direct concatenation without validation
  const downloadPath = path.join('./public/downloads/', file);
  
  console.log('Download path:', downloadPath);
  
  // Check if file exists and send it
  fs.access(downloadPath, fs.constants.F_OK, (err) => {
    if (err) {
      return res.status(404).send(`File ${file} not found`);
    }
    
    // Vulnerable: Sends any accessible file
    res.download(downloadPath, (err) => {
      if (err) {
        console.error('Download error:', err);
        res.status(500).send('Error downloading file');
      }
    });
  });
});

// VULNERABLE: Path Traversal in static file serving
app.get('/static/:path(*)', (req, res) => {
  const requestedPath = req.params.path;
  
  // Vulnerable: No sanitization of path parameter
  const fullPath = path.join('./static/', requestedPath);
  
  console.log('Serving static file:', fullPath);
  
  fs.readFile(fullPath, (err, data) => {
    if (err) {
      return res.status(404).send('File not found');
    }
    
    // Determine content type based on file extension
    const ext = path.extname(fullPath).toLowerCase();
    let contentType = 'text/plain';
    
    switch (ext) {
      case '.html': contentType = 'text/html'; break;
      case '.js': contentType = 'application/javascript'; break;
      case '.css': contentType = 'text/css'; break;
      case '.json': contentType = 'application/json'; break;
      case '.png': contentType = 'image/png'; break;
      case '.jpg': case '.jpeg': contentType = 'image/jpeg'; break;
    }
    
    res.setHeader('Content-Type', contentType);
    res.send(data);
  });
});

// VULNERABLE: Path Traversal in file upload directory listing
app.get('/list', (req, res) => {
  const dir = req.query.dir || '.';
  
  // Vulnerable: No validation of directory parameter
  const targetDir = path.join('./uploads/', dir);
  
  console.log('Listing directory:', targetDir);
  
  fs.readdir(targetDir, (err, files) => {
    if (err) {
      return res.status(500).send(`Cannot read directory: ${dir}`);
    }
    
    let html = `<h1>Directory Listing: ${dir}</h1><ul>`;
    
    files.forEach(file => {
      const filePath = path.join(dir, file);
      html += `<li><a href="/file/${encodeURIComponent(filePath)}">${file}</a></li>`;
    });
    
    html += '</ul>';
    html += '<p><a href="/list">Back to root</a></p>';
    
    res.send(html);
  });
});

// VULNERABLE: Path Traversal in file deletion
app.delete('/delete/:filename', (req, res) => {
  const filename = req.params.filename;
  
  // Vulnerable: No path validation
  const filePath = './temp/' + filename;
  
  console.log('Attempting to delete file:', filePath);
  
  fs.unlink(filePath, (err) => {
    if (err) {
      return res.status(500).send(`Error deleting file: ${filename}`);
    }
    
    res.send(`File ${filename} deleted successfully`);
  });
});

// VULNERABLE: Path Traversal with POST body
app.post('/view-log', (req, res) => {
  const { logFile } = req.body;
  
  if (!logFile) {
    return res.status(400).send('Log file name required');
  }
  
  // Vulnerable: Direct path construction
  const logPath = `./logs/${logFile}`;
  
  console.log('Reading log file:', logPath);
  
  fs.readFile(logPath, 'utf8', (err, data) => {
    if (err) {
      return res.status(404).send('Log file not found');
    }
    
    res.send(`<h2>Log File: ${logFile}</h2><pre>${data}</pre>`);
  });
});

// Demo page showing attack vectors
app.get('/', (req, res) => {
  const html = `
    <html>
      <head><title>Path Traversal Vulnerability Demo</title></head>
      <body>
        <h1>Path Traversal Vulnerability Demonstration</h1>
        
        <h2>Try these Path Traversal attacks:</h2>
        
        <h3>1. Basic Path Traversal (File Parameter):</h3>
        <ul>
          <li><a href="/file/../../package.json">Read package.json: /file/../../package.json</a></li>
          <li><a href="/file/../../../../etc/passwd">Read /etc/passwd: /file/../../../../etc/passwd</a></li>
          <li><a href="/file/../../../.env">Read .env file: /file/../../../.env</a></li>
        </ul>
        
        <h3>2. Download Path Traversal (Query Parameter):</h3>
        <ul>
          <li><a href="/download?file=../../package.json">Download package.json</a></li>
          <li><a href="/download?file=../../../.gitignore">Download .gitignore</a></li>
          <li><a href="/download?file=../../../../etc/hosts">Download /etc/hosts</a></li>
        </ul>
        
        <h3>3. Static File Path Traversal:</h3>
        <ul>
          <li><a href="/static/../../package.json">Static package.json</a></li>
          <li><a href="/static/../../../README.md">Static README.md</a></li>
        </ul>
        
        <h3>4. Directory Listing Path Traversal:</h3>
        <ul>
          <li><a href="/list?dir=../">List parent directory</a></li>
          <li><a href="/list?dir=../../">List grandparent directory</a></li>
          <li><a href="/list?dir=../../../">List great-grandparent</a></li>
        </ul>
        
        <h3>5. File Deletion (use with caution!):</h3>
        <p>DELETE request to: <code>/delete/../important-file.txt</code></p>
        
        <h3>6. Log File Viewer (POST):</h3>
        <form method="POST" action="/view-log">
          <label>Log File: <input name="logFile" value="../../../package.json" placeholder="Enter log file path"></label>
          <button type="submit">View Log</button>
        </form>
        
        <hr>
        
        <h2>Common Path Traversal Payloads:</h2>
        <ul>
          <li><code>../</code> - Navigate up one directory</li>
          <li><code>../../</code> - Navigate up two directories</li>
          <li><code>../../../../etc/passwd</code> - Access system files (Linux/Mac)</li>
          <li><code>..\\..\\..\\windows\\system32\\drivers\\etc\\hosts</code> - Access system files (Windows)</li>
          <li><code>....//....//....//etc/passwd</code> - Double encoding bypass</li>
          <li><code>%2e%2e%2f</code> - URL encoded ../</li>
          <li><code>..%252f</code> - Double URL encoded</li>
        </ul>
        
        <h2>Impact of Path Traversal:</h2>
        <ul>
          <li>Access sensitive configuration files (.env, config files)</li>
          <li>Read system files (/etc/passwd, /etc/hosts)</li>
          <li>Access application source code</li>
          <li>Read database files or backups</li>
          <li>Access log files containing sensitive information</li>
          <li>Delete or modify critical files</li>
        </ul>
        
        <p><strong>⚠️ Warning:</strong> These are intentional vulnerabilities for demonstration. Never use in production!</p>
      </body>
    </html>
  `;
  
  res.send(html);
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => {
  console.log(`Path Traversal Demo Server running on http://localhost:${PORT}`);
  console.log('Visit http://localhost:3001 to see path traversal vulnerability examples');
  console.log('⚠️  WARNING: This server contains intentional security vulnerabilities!');
});

module.exports = app;
const express = require('express');
const path = require('path');
const session = require('express-session');
// const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const { prettyDate } = require('./helpers');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Connect to SQLite database
const sqlite3 = require('sqlite3').verbose();
const db = new sqlite3.Database('./views/cv.db');

db.serialize(() => {
  // Create users table
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
  )`);

  // Create resumes table
  db.run(`CREATE TABLE IF NOT EXISTS resumes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    userId INTEGER NOT NULL,
    FOREIGN KEY (userId) REFERENCES users(id)
  )`);
  
  // Add the 'content' column if it doesn't exist
  db.run("ALTER TABLE resumes ADD COLUMN content TEXT", (err) => {
    if (err) {
      // Column might already exist, which is fine
      console.log("Content column might already exist:", err.message);
    } else {
      console.log("Content column added successfully");
    }
  });
});

// Middleware
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));

// Set up session
app.use(session({
  secret: 'your_session_secret',
  resave: false,
  saveUninitialized: true
}));

// Get all resumes from the database
function getAllResumes(userId, callback) {
  const query = 'SELECT * FROM resumes WHERE userId = ?';
  db.all(query, [userId], (err, rows) => {
    if (err) {
      return callback(err, null);
    }
    callback(null, rows);
  });
}

// Routes
app.get('/', (req, res) => {
  res.redirect('/login');
});

app.get('/login', (req, res) => {
  const eventDateRef = new Date();
  res.render('auth', { 
      prettyDate, 
      eventDateRef,
      pageType: 'login',
      children: 'Login'
  });
});

app.get('/register', (req, res) => {
  const eventDateRef = new Date();
  res.render('auth', { 
      prettyDate, 
      eventDateRef,
      pageType: 'register',
      children: 'Register'
  });
});

app.get('/forgot-password/email', (req, res) => {
  const eventDateRef = new Date();
  res.render('auth', { 
      prettyDate, 
      eventDateRef,
      pageType: 'forgot-password',
      children: 'Reset Password'
  });
});

// Registration route
app.post('/register', (req, res) => {
  const { name, email, password, confirm_password } = req.body;

  if (password !== confirm_password) {
    return res.status(400).send('Passwords do not match');
  }

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, row) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    if (row) {
      return res.status(400).send('User already exists');
    }

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) {
        return res.status(500).send('Error hashing password');
      }

      db.run('INSERT INTO users (name, email, password) VALUES (?, ?, ?)', [name, email, hash], function(err) {
        if (err) {
          return res.status(500).send('Database error');
        }
        res.redirect('/login');
      });
    });
  });
});

// Login route
app.post('/login', (req, res) => {
  const { email, password } = req.body;

  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      return res.status(500).send('Database error');
    }
    if (!user) {
      return res.status(401).send('Invalid email or password');
    }

    bcrypt.compare(password, user.password, (err, result) => {
      if (err) {
        return res.status(500).send('Error comparing passwords');
      }
      if (!result) {
        return res.status(401).send('Invalid email or password');
      }

      req.session.user = user;
      res.redirect('/dashboard');
    });
  });
});

// Dashboard route
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  getAllResumes(req.session.user.id, (err, resumes) => {
    if (err) {
      return res.status(500).send('Error fetching resumes');
    }

    res.render('dashboard', { resumes });
  });
});

// Save CV route
app.post('/resume/save', (req, res) => {
  if (!req.session.user) {
    return res.status(401).json({ error: 'Unauthorized' });
  }

  const { title, content } = req.body;
  const userId = req.session.user.id;

  const query = `
    INSERT INTO resumes (title, content, userId) 
    VALUES (?, ?, ?)
  `;
  db.run(query, [title, content, userId], function (err) {
    if (err) {
      console.error('Error saving resume:', err);
      return res.status(500).json({ error: 'Error saving resume', details: err.message });
    }
    res.status(200).json({ message: 'Resume saved successfully' });
  });
});

// Get CV route
app.get('/resume/:id', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }

  const resumeId = req.params.id;
  const userId = req.session.user.id;

  db.get('SELECT * FROM resumes WHERE id = ? AND userId = ?', [resumeId, userId], (err, resume) => {
    if (err) {
      console.error('Error fetching resume:', err);
      return res.status(500).send('Failed to fetch resume');
    }
    if (!resume) {
      return res.status(404).send('Resume not found');
    }
    res.json(resume);
  });
});

// DELETE resume route
app.delete('/resume/delete/:id', (req, res) => {
  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }

  const resumeId = req.params.id;
  const userId = req.session.user.id;

  db.run('DELETE FROM resumes WHERE id = ? AND userId = ?', [resumeId, userId], function(err) {
    if (err) {
      console.error('Error deleting resume:', err);
      return res.status(500).send('Failed to delete resume');
    }
    if (this.changes === 0) {
      return res.status(404).send('Resume not found');
    }
    res.status(200).send('Resume deleted successfully');
  });
});

// Logout route
app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Error during logout:', err);
    }
    res.redirect('/login');
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server is running on http://localhost:${PORT}`);
});
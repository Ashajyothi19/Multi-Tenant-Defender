const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');

const path = require('path');

const app = express();

// Middleware
app.use(bodyParser.json());
app.use(cors());

// MongoDB Connection
mongoose.connect('mongodb://localhost:27017/MTD')
  .then(() => console.log('Connected to MongoDB'))
  .catch((err) => console.error('Failed to connect to MongoDB', err));

// MongoDB User Model
const User = require('./models/User');

// Routes

// User Registration
app.post('/api/register', async (req, res) => {
  try {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10); // Hash password
    const user = new User({ name, email, password: hashedPassword }); // Store hashed password
    await user.save();
    res.status(200).send('User registered successfully');
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});

// User Login
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (user) {
      const isPasswordValid = await bcrypt.compare(password, user.password); // Compare hashed passwords
      if (isPasswordValid) {
        res.status(200).send('Login successful');
      } else {
        res.status(401).send('Invalid email or password');
      }
    } else {
      res.status(401).send('Invalid email or password');
    }
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});

// Dashboard Data
app.get('/api/user/dashboard', async (req, res) => {
  try {
    const usersCount = await User.countDocuments();
    const blockedUsersCount = await User.countDocuments({ blocked: true });
    
    const dashboardData = {
      totalUsers: usersCount,
      blockedUsers: blockedUsersCount
    };
    
    res.status(200).json(dashboardData);
  } catch (error) {
    console.error(error);
    res.status(500).send('Internal server error');
  }
});

// Endpoint for threat prediction


// Security Information
const securityInfo = {
  firewallStatus: 'Active',
  antivirusStatus: 'Enabled',
  intrusionDetection: 'Enabled'
};

// Endpoint to retrieve security information
app.get('/security', (req, res) => {
  res.json(securityInfo);
});
const websiteSchema = new mongoose.Schema({
  domain: String,
  backendURL: String,
  email: String,
});

// Create model from schema
const Website = mongoose.model('Website', websiteSchema);

app.use(bodyParser.json());

// Endpoint for deploying a website
app.post('/api/deploy-website', async (req, res) => {
  const { domain, backendURL, email } = req.body;

  try {
    // Check if the user already has a deployed website
    const existingWebsite = await Website.findOne({ email });
    if (existingWebsite) {
      return res.status(400).json({ success: false, message: 'Website already deployed' });
    }

    // Create a new website document
    const website = new Website({ domain, backendURL, email });

    // Save the website details to the database
    await website.save();

    // Return success response
    res.status(200).json({ success: true, message: 'Website deployed successfully' });
  } catch (error) {
    // If an error occurs, return error response
    console.error('Error saving website details:', error);
    res.status(500).json({ success: false, error: 'Error saving website details' });
  }
});
app.post('/api/user/deployment-status', async (req, res) => {
  const { email } = req.body;

  try {
    const website = await Website.findOne({ email });

    if (website) {
      res.json({ deployed: true });
    } else {
      res.json({ deployed: false });
    }
  } catch (error) {
    console.error('Error checking deployment status:', error);
    res.status(500).json({ deployed: false });
  }
});
// Express route to fetch user credentials for the deployed website
app.post('/api/user/traffic-details', async (req, res) => {
  const { email } = req.body;

  try {
    // Find the website deployed by this user
    const website = await Website.findOne({ email });
    
    if (!website) {
      return res.status(404).json({ error: 'No website deployed by this user' });
    }

    // Find the user credentials related to the deployed website
    const userCredentials = await UserCredential.find({ domain: website.domain });
    
    res.json({ user_credentials: userCredentials });
  } catch (error) {
    console.error('Error fetching user credentials:', error);
    res.status(500).json({ error: 'Error fetching user credentials' });
  }
});
app.post('/api/threat-detection', (req, res) => {
  try {
    const { url } = req.body;

    // Check for potential threats
    let threatDetected = false;

    // Check for script tag (XSS threat)
    if (url.includes('<script>')) {
      threatDetected = true;
    }

    // Check for SQL injection threat
    const sqlInjectionPatterns = [
      /SELECT.*FROM/i, // Basic SELECT statement
      /INSERT\s+INTO/i, // INSERT INTO statement
      /UPDATE.*SET/i, // UPDATE statement
      /DELETE\s+FROM/i, // DELETE FROM statement
      /DROP\s+TABLE/i, // DROP TABLE statement
    ];
    if (sqlInjectionPatterns.some(pattern => pattern.test(url))) {
      threatDetected = true;
    }

    // Return the prediction
    if (threatDetected) {
      return res.status(200).json({ prediction: 1 }); // Threat detected
    } else {
      return res.status(200).json({ prediction: 0 }); // No threat detected
    }
  } catch (error) {
    console.error('Error detecting threat:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server is running on http://localhost:${PORT}`));

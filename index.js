const express = require('express');
const cors = require('cors');
require('dotenv').config();

const app = express();

app.use(cors());
app.use(express.json());

const authRoutes = require('./routes/auth');
app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
const path = require('path');

// This allows your server to "see" your HTML/CSS files in the folder
app.use(express.static(__dirname)); 

// This tells the server to show login.html when you visit the main URL
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'login.html'));
});
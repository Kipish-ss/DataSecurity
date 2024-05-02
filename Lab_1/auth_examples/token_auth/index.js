const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const jwt = require('jsonwebtoken');
const port = 3000;

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const JWT_SECRET = 'IP11_Sidak';

const generateToken = (user) => {
  return jwt.sign({
    username: user.username,
    login: user.login
  }, JWT_SECRET, { expiresIn: '1h' });
};

app.use((req, res, next) => {
  const header = req.headers['authorization'];
  const token = header && header.split(' ')[1];

  if (token) {
    jwt.verify(token, JWT_SECRET, (err, decoded) => {
      if (err) {
        return res.status(403).json({ error: 'Failed to authenticate token.' });
      } else {
        req.user = decoded;
        next();
      }
    });
  } else {
    next();
  }
});

app.get('/', (req, res) => {
  if (req.user) {
    return res.json({
      username: req.user.username,
      logout: 'http://localhost:3000/logout'
    });
  }
  res.sendFile(path.join(__dirname+'/index.html'));
});

app.get('/logout', (req, res) => {
  res.redirect('/'); 
});

const users = [
  { login: 'Login', password: 'Password', username: 'Username' },
  { login: 'Login1', password: 'Password1', username: 'Username1' }
];

app.post('/api/login', (req, res) => {
  const { login, password } = req.body;

  const user = users.find(user => user.login === login && user.password === password);

  if (user) {
    const token = generateToken(user);
    return res.json({ token });
  } else {
    return res.status(401).send('Authentication failed.');
  }
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});

require('dotenv').config()
const express = require('express')
const axios = require('axios')
const path = require('path')
const session = require('express-session')

const app = express()
const port = process.env.PORT || 3000

app.use(express.json())
app.use(express.urlencoded({ extended: true }))
app.use(
  session({
    secret: 'secret',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false },
  })
)

async function refreshToken(req, res, next) {
  const tokens = req.session.tokens;
  if (tokens?.expires_in) {
    const expirationDate = new Date(tokens.expires_in);
    console.log(`Token expires on: ${expirationDate.toLocaleString()}`);
  }
  if (tokens && Date.now() > tokens.expires_in - 5 * 60 * 1000) { 
    try {
      const response = await axios({
        method: 'post',
        url: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        data: new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: process.env.AUTH0_CLIENT_ID,
          client_secret: process.env.AUTH0_CLIENT_SECRET,
          refresh_token: tokens.refresh_token,
        }),
      });

      req.session.tokens = {
        access_token: response.data.access_token,
        refresh_token: tokens.refresh_token,
        expires_in: Date.now() + response.data.expires_in * 1000 
      };
    } catch (error) {
      console.error('Error refreshing token:', error.response?.data || error.message);
      return res.status(401).json({ error: 'Failed to refresh token' });
    }
  }
  next();
}

app.use(refreshToken);

app.get('/', async (req, res) => {
  if (req.session.tokens) {
    try {
      const { access_token } = req.session.tokens
      const response = await axios.get(
        `https://${process.env.AUTH0_DOMAIN}/userinfo`,
        {
          headers: {
            Authorization: `Bearer ${access_token}`,
          },
        }
      )

      return res.json({
        user: response.data,
        logout: '/logout',
      })
    } catch (error) {
      console.error('Error:', error.response?.data || error.message)
      req.session.destroy()
    }
  }

  res.sendFile(path.join(__dirname, 'index.html'))
})

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/')
  })
})

app.post('/api/login', async (req, res) => {
  try {
    const { login, password } = req.body
    const response = await axios({
      method: 'post',
      url: `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      data: new URLSearchParams({
        grant_type: 'password',
        username: login,
        password: password,
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        audience: `https://${process.env.AUTH0_DOMAIN}/api/v2/`,
        scope: 'offline_access openid profile email',
      }),
    })

    req.session.tokens = {
      access_token: response.data.access_token,
      refresh_token: response.data.refresh_token,
      expires_in: Date.now() + response.data.expires_in * 1000,
    }
    res.json({ success: true, token: response.data.access_token })
  } catch (error) {
    console.error('Login failed:', error.response?.data || error.message)
    res.status(401).send('Login failed')
  }
})

app.post('/api/register', async (req, res) => {
  const { email, password, name, nickname } = req.body

  try {
    // Отримання токену
    const authData = await axios.post(
      `https://${process.env.AUTH0_DOMAIN}/oauth/token`,
      new URLSearchParams({
        grant_type: 'client_credentials',
        client_id: process.env.AUTH0_CLIENT_ID,
        client_secret: process.env.AUTH0_CLIENT_SECRET,
        audience: `https://${process.env.AUTH0_DOMAIN}/api/v2/`,
      }),
      {
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
      }
    )

    // Запит реєстрації
    const userResponse = await axios.post(
      `https://${process.env.AUTH0_DOMAIN}/api/v2/users`,
      {
        email: email,
        password: password,
        connection: 'Username-Password-Authentication',
        verify_email: true,
        name: name,
        nickname: nickname,
        picture:
          'https://i.pinimg.com/originals/e1/4c/ae/e14cae2f0f44121ab4e3506002ba1a55.jpg',
      },
      {
        headers: {
          Authorization: `Bearer ${authData.data.access_token}`,
          'content-type': 'application/json',
        },
      }
    )
    res.status(201).json({
      success: true,
      userId: userResponse.data,
      login: '/',
    })
  } catch (error) {
    console.error('Registration failed:', error.response?.data || error.message)
    res.status(400).json({
      success: false,
      error: error.response?.data,
    })
  }
})

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`)
})

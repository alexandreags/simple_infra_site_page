require('dotenv').config(); // Carrega as variáveis de ambiente
const express = require('express');
const mysql = require('mysql2');
const os = require('os');
const fs = require('fs');
const si = require('systeminformation');
const session = require('express-session');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path'); // Adiciona essa linha aqui


const app = express();
const port = process.env.PORT || 3000;

// Configura o CORS
app.use(cors());

// Configura a sessão
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: process.env.NODE_ENV === 'production' }
}));

app.use(passport.initialize());
app.use(passport.session());

// Configura a conexão com o MySQL
const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  connectionLimit: 10
});

// Middleware pra parsear o body das requisições
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Configura a autenticação
passport.use(new LocalStrategy(
  (username, password, done) => {
    console.log('Tentando autenticar:', username);
    pool.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
      if (err) {
        console.error('Erro na consulta ao banco:', err);
        return done(err);
      }
      if (results.length === 0) {
        console.log('Usuário não encontrado:', username);
        return done(null, false, { message: 'Usuário não encontrado' });
      }
      const user = results[0];
      bcrypt.compare(password, user.password, (err, result) => {
        if (err) {
          console.error('Erro ao comparar senhas:', err);
          return done(err);
        }
        if (!result) {
          console.log('Senha incorreta para:', username);
          return done(null, false, { message: 'Senha incorreta' });
        }
        console.log('Autenticação bem-sucedida para:', username);
        return done(null, user);
      });
    });
  }
));

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser((id, done) => {
  pool.query('SELECT * FROM users WHERE id = ?', [id], (err, results) => {
    if (err) return done(err);
    done(null, results[0]);
  });
});

// Middleware pra checar se o usuário tá logado
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/login');
}
// Rota para Logar
app.get('/login', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

// Rota para logout
app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/login');
});

// Rota de login POST
app.post('/login', (req, res, next) => {
  console.log('Tentativa de login:', req.body);
  passport.authenticate('local', (err, user, info) => {
    if (err) {
      console.error('Erro na autenticação:', err);
      return next(err);
    }
    if (!user) {
      console.log('Login falhou:', info);
      return res.status(401).json({ message: 'Login falhou, meu parceiro!' });
    }
    req.logIn(user, (err) => {
      if (err) {
        console.error('Erro ao logar o usuário:', err);
        return next(err);
      }
      console.log('Login bem-sucedido para:', user.username);
      return res.status(200).json({ 
        message: 'Login firmeza, meu chapa!',
        redirect: '/'  // Adiciona essa informação de redirecionamento 
      });
    });
  })(req, res, next);
});

// Rota protegida de informações do sistema
app.get('/info', ensureAuthenticated, (req, res) => {
  const hostname = os.hostname();
  const ip = Object.values(os.networkInterfaces())
    .flat()
    .filter(({ family, internal }) => family === 'IPv4' && !internal)
    .map(({ address }) => address)[0];
  
  const diskSpace = fs.statSync('/').blocks * fs.statSync('/').blksize;

  res.json({ hostname, ip, diskSpace });
});

// Rota protegida para registrar cliques
app.post('/click', ensureAuthenticated, (req, res) => {
  const clientIp = req.ip;
  const clickDate = new Date();
  console.log('Data do clique', clickDate);

  const query = 'INSERT INTO clicks (ip, click_date) VALUES (?, ?)';
  pool.query(query, [clientIp, clickDate], (error) => {
    if (error) {
      console.error('Erro ao salvar o clique:', error);
      res.status(500).send('Erro ao salvar o clique');
    } else {
      res.sendStatus(200);
    }
  });
});

// Rota protegida para obter cliques
app.get('/clicks', ensureAuthenticated, (req, res) => {
  const query = `
    SELECT 
      DATE_FORMAT(click_date, '%Y-%m-%d %H:%i:00') - INTERVAL MINUTE(click_date) % 10 MINUTE AS interval_start,
      COUNT(*) AS count
    FROM 
      clicks
    GROUP BY 
      interval_start
    ORDER BY 
      interval_start DESC
    LIMIT 100
  `;
  pool.query(query, (error, results) => {
    if (error) {
      console.error('Erro ao pegar os cliques:', error);
      res.status(500).send('Deu ruim pra pegar os cliques');
    } else {
      // Formata os resultados pra um formato mais amigável pro frontend
      const formattedResults = results.map(row => ({
        click_date: new Date(row.interval_start).toISOString(),
        count: row.count
      }));
      res.json(formattedResults);
    }
  });
});

// Rota protegida para informações do sistema
app.get('/system-info', ensureAuthenticated, async (req, res) => {
  try {
    const cpu = await si.currentLoad();
    const mem = await si.mem();
    res.json({
      cpuUsage: cpu.currentLoad,
      memUsage: (mem.used / mem.total) * 100
    });
  } catch (error) {
    console.error('Erro ao obter informações do sistema:', error);
    res.status(500).send('Deu ruim pra pegar as infos do sistema');
  }
});

// Rota protegida para uso do disco
app.get('/disk-usage', ensureAuthenticated, (req, res) => {
  si.fsSize()
    .then(data => {
      const rootDisk = data.find(disk => disk.mount === '/');
      const usagePercent = (rootDisk.used / rootDisk.size) * 100;
      res.json({
        usage: usagePercent,
        warning: usagePercent > 90
      });
    })
    .catch(error => {
      console.error('Erro ao verificar uso do disco:', error);
      res.status(500).send('Deu ruim pra checar o disco');
    });
});

// Middleware de tratamento de erros
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).send('Opa, deu ruim aqui no servidor!');
});

// Rota raiz
app.get('/', ensureAuthenticated, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));;
});

app.listen(port, () => {
  console.log(`Aplicação rodando na porta ${port}`);
});
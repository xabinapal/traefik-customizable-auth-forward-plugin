import express, { json, urlencoded } from 'express';

const app = express();
const PORT = process.env.PORT || 3000;

app.use(json());
app.use(urlencoded({ extended: true }));

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  console.log('Headers:', JSON.stringify(req.headers, null, 2));
  next();
});

app.all('/', (req, res) => {
  res.json({
    method: req.method,
    path: req.path,
    headers: req.headers,
    query: req.query,
    body: req.body
  });
});

app.all('/auth', (req, res) => {
  res.set({
    'X-Auth-User': 'admin-user',
    'X-Auth-Email': 'admin@example.com',
    'X-Auth-Groups': 'admin,users',
    'X-Auth-Role': 'admin'
  });

  return res.status(200).send('OK');
});

app.all('/auth/deny', (req, res) => {
  return res.status(401).send('Unauthorized');
});

app.all('/auth/redirect', (req, res) => {
  return res.status(302).location('/').send('Found');
});

const server = app.listen(PORT, () => {
  console.log(`Trasefik Customizable Auth Test Server running on port ${PORT}`);
  console.log(`Available endpoints:`);
  console.log(`  • / - Debug information`);
  console.log(`  • /auth/ - Returns 200 with auth headers`);
  console.log(`  • /auth/deny - Returns 401 unauthorized`);
  console.log(`  • /auth/redirect - Returns 302 redirect`);
});

const shutdown = (signal) => {
  console.log(`\nReceived ${signal}.`);
  server.close(() => {
    process.exit(0);
  });
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT')); 
process.on('SIGHUP', () => shutdown('SIGHUP'));
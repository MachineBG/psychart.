const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');
const crypto = require('crypto');

const app = express();
app.use(express.json());
app.use(cors());

const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

// ── CREDENCIAIS DE ACESSO ────────────────────────────────────────────
// Configure via variáveis de ambiente no Railway
// ADMIN_USER e ADMIN_PASS definem o login
const ADMIN_USER = process.env.ADMIN_USER || 'nathany';
const ADMIN_PASS = process.env.ADMIN_PASS || 'psychart2024';

// Sessões em memória (simples e seguro para uso individual)
const sessions = new Map();

function gerarToken() {
  return crypto.randomBytes(32).toString('hex');
}

function autenticado(req, res, next) {
  const token = req.headers['x-session-token'] || req.cookies?.session;
  if (token && sessions.has(token)) {
    const s = sessions.get(token);
    if (s.expiresAt > Date.now()) {
      s.expiresAt = Date.now() + 12 * 3600 * 1000; // renova sessão
      return next();
    }
    sessions.delete(token);
  }
  res.status(401).json({ error: 'Não autorizado' });
}

// ── LOGIN ────────────────────────────────────────────────────────────
app.post('/api/login', (req, res) => {
  const { usuario, senha } = req.body;
  if (usuario === ADMIN_USER && senha === ADMIN_PASS) {
    const token = gerarToken();
    sessions.set(token, { expiresAt: Date.now() + 12 * 3600 * 1000 });
    res.json({ ok: true, token });
  } else {
    res.status(401).json({ ok: false, error: 'Usuário ou senha incorretos' });
  }
});

app.post('/api/logout', (req, res) => {
  const token = req.headers['x-session-token'];
  if (token) sessions.delete(token);
  res.json({ ok: true });
});

app.get('/api/me', autenticado, (req, res) => {
  res.json({ ok: true });
});

// ── PROXY: ViaCEP ────────────────────────────────────────────────────
app.get('/api/cep/:cep', autenticado, async (req, res) => {
  try {
    const cep = req.params.cep.replace(/\D/g, '');
    if (cep.length !== 8) return res.status(400).json({ erro: true });
    const r = await fetch(`https://viacep.com.br/ws/${cep}/json/`);
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ erro: true, msg: e.message });
  }
});

// ── PROXY: Claude AI ─────────────────────────────────────────────────
app.post('/api/ai/summary', autenticado, async (req, res) => {
  const { transcript } = req.body;
  if (!transcript) return res.status(400).json({ error: 'transcript required' });
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': ANTHROPIC_API_KEY,
        'anthropic-version': '2023-06-01'
      },
      body: JSON.stringify({
        model: 'claude-sonnet-4-6',
        max_tokens: 1000,
        system: `Você é assistente clínico em psiquiatria. Analise a transcrição da consulta e produza um resumo clínico estruturado em português, com: 1) Queixa principal 2) Pontos relevantes da anamnese 3) Estado mental observado 4) Hipóteses diagnósticas sugeridas 5) Conduta e orientações. Seja conciso e técnico. Não invente informações ausentes.`,
        messages: [{ role: 'user', content: `Transcrição:\n\n${transcript}` }]
      })
    });
    const data = await r.json();
    res.json({ summary: data.content?.[0]?.text || 'Erro ao gerar resumo.' });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── VIDaaS OAuth ─────────────────────────────────────────────────────
app.get('/api/vidaas/auth-url', autenticado, (req, res) => {
  const clientId    = process.env.VIDAAS_CLIENT_ID || '';
  const redirectUri = process.env.VIDAAS_REDIRECT_URI || `https://${req.headers.host}/api/vidaas/callback`;
  const cpf         = req.query.cpf || '';
  const lifetime    = req.query.lifetime || '28800';

  if (!clientId) {
    return res.status(503).json({ error: 'VIDaaS não configurado. Adicione VIDAAS_CLIENT_ID no Railway.' });
  }

  const codeVerifier = 'psychart_' + crypto.randomBytes(24).toString('hex');
  const state = crypto.randomBytes(16).toString('hex');
  global._vidaasState = { codeVerifier, state, cpf, lifetime };

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'signature_session',
    code_challenge: codeVerifier,
    code_challenge_method: 'plain',
    state,
    login_hint: cpf,
    lifetime
  });

  res.json({ authUrl: `https://certificado.vidaas.com.br/v0/oauth/authorize?${params}`, state });
});

app.get('/api/vidaas/callback', async (req, res) => {
  const { code, state } = req.query;
  const stored = global._vidaasState;
  if (!stored || stored.state !== state) return res.status(400).send('Estado inválido.');

  try {
    const r = await fetch('https://certificado.vidaas.com.br/v0/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: process.env.VIDAAS_REDIRECT_URI || `https://${req.headers.host}/api/vidaas/callback`,
        client_id: process.env.VIDAAS_CLIENT_ID || '',
        client_secret: process.env.VIDAAS_CLIENT_SECRET || '',
        code_verifier: stored.codeVerifier
      })
    });
    const token = await r.json();
    if (token.access_token) {
      global._vidaasToken = { accessToken: token.access_token, expiresAt: Date.now() + (token.expires_in || 28800) * 1000 };
      res.redirect('/?vidaas=ok');
    } else {
      res.redirect('/?vidaas=erro');
    }
  } catch (e) {
    res.redirect('/?vidaas=erro');
  }
});

app.post('/api/vidaas/sign', autenticado, async (req, res) => {
  const token = global._vidaasToken;
  if (!token || token.expiresAt < Date.now()) return res.status(401).json({ error: 'Sessão VIDaaS expirada.' });
  const { documentHash, documentName } = req.body;
  try {
    const r = await fetch('https://certificado.vidaas.com.br/valid-api/api/v1/trusted-services/signatures', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token.accessToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        alias: documentName || 'documento',
        hashes: [{ id: 'doc1', alias: documentName, hash: documentHash, hash_algorithm: 'SHA-256', signature_format: 'CADES_T', base64_content: '' }]
      })
    });
    res.json(await r.json());
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get('/api/vidaas/status', autenticado, (req, res) => {
  const token = global._vidaasToken;
  if (!token) return res.json({ active: false });
  const restante = Math.max(0, token.expiresAt - Date.now());
  res.json({ active: restante > 0, expiresAt: token.expiresAt, restanteMs: restante });
});

// ── Arquivos estáticos só após login ────────────────────────────────
// login.html é público, tudo mais protegido
app.use('/login.html', express.static(path.join(__dirname, 'public', 'login.html')));
app.use('/api', (req, res, next) => next()); // rotas api já tratadas acima

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.get('/app', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'login.html'));
});

app.listen(PORT, () => {
  console.log(`PsyChart rodando na porta ${PORT}`);
  console.log(`Usuário: ${ADMIN_USER}`);
  console.log(`Claude AI: ${ANTHROPIC_API_KEY ? '✅' : '❌ falta ANTHROPIC_API_KEY'}`);
  console.log(`VIDaaS: ${process.env.VIDAAS_CLIENT_ID ? '✅' : '⚠️  modo demo'}`);
});

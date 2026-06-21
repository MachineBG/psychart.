const express = require('express');
const fetch = require('node-fetch');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(express.json());
app.use(cors());
app.use(express.static(path.join(__dirname, 'public')));

const PORT = process.env.PORT || 3000;
const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || '';

// ── PROXY: ViaCEP (evita bloqueio CORS no browser) ──────────────────
app.get('/api/cep/:cep', async (req, res) => {
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

// ── PROXY: Claude AI (evita CORS e esconde a chave) ──────────────────
app.post('/api/ai/summary', async (req, res) => {
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

// ── VIDaaS OAuth — Passo 1: Gerar URL de autorização ────────────────
// Documentação: https://valid-sa.atlassian.net/wiki/spaces/PDD/pages/958365697
app.get('/api/vidaas/auth-url', (req, res) => {
  const clientId     = process.env.VIDAAS_CLIENT_ID || '';
  const redirectUri  = process.env.VIDAAS_REDIRECT_URI || `https://${req.headers.host}/api/vidaas/callback`;
  const cpf          = req.query.cpf || '';
  const lifetime     = req.query.lifetime || '28800'; // 8h padrão

  if (!clientId) {
    return res.status(503).json({
      error: 'VIDaaS não configurado',
      msg: 'Defina VIDAAS_CLIENT_ID nas variáveis de ambiente do Railway.'
    });
  }

  // OAuth 2.0 PKCE — na produção gere code_verifier/challenge dinâmicos
  const codeVerifier  = 'psychart_' + Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  const state         = Math.random().toString(36).slice(2);

  // Armazena temporariamente (em produção use Redis ou DB)
  global._vidaasState = { codeVerifier, state, cpf, lifetime };

  const params = new URLSearchParams({
    response_type: 'code',
    client_id: clientId,
    redirect_uri: redirectUri,
    scope: 'signature_session',
    code_challenge: codeVerifier, // Simplificado — em produção use SHA-256
    code_challenge_method: 'plain',
    state,
    login_hint: cpf,
    lifetime
  });

  const authUrl = `https://certificado.vidaas.com.br/v0/oauth/authorize?${params}`;
  res.json({ authUrl, state });
});

// ── VIDaaS OAuth — Passo 2: Callback com code ───────────────────────
app.get('/api/vidaas/callback', async (req, res) => {
  const { code, state } = req.query;
  const stored = global._vidaasState;

  if (!stored || stored.state !== state) {
    return res.status(400).send('Estado inválido. Tente autenticar novamente.');
  }

  const clientId     = process.env.VIDAAS_CLIENT_ID || '';
  const clientSecret = process.env.VIDAAS_CLIENT_SECRET || '';
  const redirectUri  = process.env.VIDAAS_REDIRECT_URI || `https://${req.headers.host}/api/vidaas/callback`;

  try {
    const r = await fetch('https://certificado.vidaas.com.br/v0/oauth/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'authorization_code',
        code,
        redirect_uri: redirectUri,
        client_id: clientId,
        client_secret: clientSecret,
        code_verifier: stored.codeVerifier
      })
    });
    const token = await r.json();

    if (token.access_token) {
      global._vidaasToken = {
        accessToken: token.access_token,
        expiresAt: Date.now() + (token.expires_in || 28800) * 1000
      };
      // Redireciona de volta ao sistema com sucesso
      res.redirect('/?vidaas=ok');
    } else {
      res.redirect('/?vidaas=erro&msg=' + encodeURIComponent(JSON.stringify(token)));
    }
  } catch (e) {
    res.redirect('/?vidaas=erro&msg=' + encodeURIComponent(e.message));
  }
});

// ── VIDaaS — Passo 3: Assinar documento (hash) ──────────────────────
app.post('/api/vidaas/sign', async (req, res) => {
  const token = global._vidaasToken;
  if (!token || token.expiresAt < Date.now()) {
    return res.status(401).json({ error: 'Sessão VIDaaS expirada. Autentique novamente.' });
  }

  const { documentHash, documentName } = req.body;
  try {
    const r = await fetch('https://certificado.vidaas.com.br/valid-api/api/v1/trusted-services/signatures', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token.accessToken}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        alias: documentName || 'documento',
        hashes: [{ id: 'doc1', alias: documentName, hash: documentHash, hash_algorithm: 'SHA-256', signature_format: 'CADES_T', base64_content: '' }]
      })
    });
    const data = await r.json();
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ── VIDaaS — Status da sessão ────────────────────────────────────────
app.get('/api/vidaas/status', (req, res) => {
  const token = global._vidaasToken;
  if (!token) return res.json({ active: false });
  const restante = Math.max(0, token.expiresAt - Date.now());
  res.json({ active: restante > 0, expiresAt: token.expiresAt, restanteMs: restante });
});

// ── Serve o app ──────────────────────────────────────────────────────
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
  console.log(`PsyChart rodando na porta ${PORT}`);
  console.log(`Claude AI: ${ANTHROPIC_API_KEY ? '✅ configurado' : '❌ falta ANTHROPIC_API_KEY'}`);
  console.log(`VIDaaS: ${process.env.VIDAAS_CLIENT_ID ? '✅ configurado' : '⚠️  falta VIDAAS_CLIENT_ID (opcional)'}`);
});

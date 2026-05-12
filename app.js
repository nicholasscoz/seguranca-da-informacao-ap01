/**
 * Sistema de Ocorrências Acadêmicas
 * Versão com melhorias de segurança — protótipo didático
 * Disciplina: Segurança da Informação — Católica SC
 *
 * AVISO: Este é um protótipo front-end. Todas as proteções são simuladas
 * e podem ser contornadas via DevTools. Não use em produção com dados reais.
 */

'use strict';

/* ============================================================
   1. CONFIGURAÇÃO DE USUÁRIOS (demonstração)
   Em produção: senhas devem ser hashes no servidor (bcrypt/argon2).
   Credenciais NUNCA devem ficar no front-end.
   ============================================================ */
const USERS = [
  { id: 'u1', name: 'Ana Alves',      email: 'aluno@faculdade.local',     role: 'aluno',          passwordHash: hashDemoPassword('Demo@2026') },
  { id: 'u2', name: 'Prof. Carlos',   email: 'professor@faculdade.local', role: 'professor',      passwordHash: hashDemoPassword('Demo@2026') },
  { id: 'u3', name: 'Administrador',  email: 'admin@faculdade.local',     role: 'administrador',  passwordHash: hashDemoPassword('Admin@2026') },
];

/* Hash simples para demonstração — NÃO use em produção (use bcrypt/argon2 no servidor) */
function hashDemoPassword(password) {
  let hash = 0;
  for (let i = 0; i < password.length; i++) {
    hash = (hash << 5) - hash + password.charCodeAt(i);
    hash |= 0;
  }
  return 'demo_' + Math.abs(hash).toString(16);
}

/* ============================================================
   2. CONTROLE DE ACESSO (RBAC)
   Princípio do menor privilégio: cada perfil tem apenas o necessário.
   Em produção: validar no servidor a cada requisição.
   ============================================================ */
const PERMISSIONS = {
  aluno: {
    canViewOccurrences: true,     // apenas as próprias
    canCreateOccurrence: false,
    canEditStatus: false,
    canDeleteOccurrence: false,
    canExport: false,
    canViewLogs: false,
    canClearLogs: false,
    canRestore: false,
    canViewInternalObs: false,
    canViewAllOccurrences: false,
  },
  professor: {
    canViewOccurrences: true,
    canCreateOccurrence: true,
    canEditStatus: true,
    canDeleteOccurrence: false,
    canExport: false,
    canViewLogs: false,
    canClearLogs: false,
    canRestore: false,
    canViewInternalObs: false,
    canViewAllOccurrences: true,
  },
  administrador: {
    canViewOccurrences: true,
    canCreateOccurrence: true,
    canEditStatus: true,
    canDeleteOccurrence: true,
    canExport: true,
    canViewLogs: true,
    canClearLogs: true,
    canRestore: true,
    canViewInternalObs: true,
    canViewAllOccurrences: true,
  },
};

function hasPermission(permission) {
  const session = getSession();
  if (!session) return false;
  const perms = PERMISSIONS[session.role];
  return perms ? !!perms[permission] : false;
}

/* ============================================================
   3. DADOS INICIAIS (sem CPF, e-mail pessoal ou telefone — LGPD art. 6, III)
   ============================================================ */
const INITIAL_DATA = [
  { id: genId(), aluno: 'João Silva',    matricula: '2024001', tipo: 'Nota',        prioridade: 'Alta',  status: 'Aberto',   descricao: 'Nota abaixo da média na prova P1.',           obsInterna: 'Verificar histórico anterior.', criadoPor: 'u2', criadoEm: new Date(Date.now()-86400000*3).toISOString() },
  { id: genId(), aluno: 'Maria Souza',   matricula: '2024002', tipo: 'Frequência',  prioridade: 'Média', status: 'Aberto',   descricao: 'Três faltas consecutivas sem justificativa.', obsInterna: '',                               criadoPor: 'u2', criadoEm: new Date(Date.now()-86400000*2).toISOString() },
  { id: genId(), aluno: 'Pedro Santos',  matricula: '2024003', tipo: 'Comportamento', prioridade: 'Crítica', status: 'Em análise', descricao: 'Incidente durante aula prática.',       obsInterna: 'Aguardar reunião com coordenação.', criadoPor: 'u3', criadoEm: new Date(Date.now()-86400000).toISOString() },
  { id: genId(), aluno: 'Ana Lima',      matricula: '2024004', tipo: 'Solicitação administrativa', prioridade: 'Baixa', status: 'Resolvido', descricao: 'Solicitação de revisão de prova.', obsInterna: '', criadoPor: 'u2', criadoEm: new Date(Date.now()-3600000).toISOString() },
];

/* ============================================================
   4. GERENCIAMENTO DE SESSÃO COM TIMEOUT
   Em produção: usar JWT httpOnly cookie com validação no servidor.
   ============================================================ */
const SESSION_TIMEOUT_MS = 15 * 60 * 1000; // 15 minutos
let sessionTimer = null;
let sessionExpiry = null;
let sessionWarned = false;

function createSession(user) {
  const session = {
    userId: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    createdAt: Date.now(),
    expiresAt: Date.now() + SESSION_TIMEOUT_MS,
  };
  try {
    localStorage.setItem('session', JSON.stringify(session));
  } catch (e) { /* localStorage indisponível */ }
  sessionExpiry = session.expiresAt;
  return session;
}

function getSession() {
  try {
    const raw = localStorage.getItem('session');
    if (!raw) return null;
    const session = JSON.parse(raw);
    if (!session || !session.expiresAt) return null;
    if (Date.now() > session.expiresAt) {
      destroySession();
      return null;
    }
    return session;
  } catch (e) { return null; }
}

function destroySession() {
  try { localStorage.removeItem('session'); } catch (e) {}
  sessionExpiry = null;
  if (sessionTimer) { clearInterval(sessionTimer); sessionTimer = null; }
}

function renewSession() {
  const session = getSession();
  if (!session) return;
  session.expiresAt = Date.now() + SESSION_TIMEOUT_MS;
  sessionExpiry = session.expiresAt;
  sessionWarned = false;
  try { localStorage.setItem('session', JSON.stringify(session)); } catch (e) {}
}

function startSessionTimer() {
  if (sessionTimer) clearInterval(sessionTimer);
  sessionWarned = false;
  sessionTimer = setInterval(() => {
    const session = getSession();
    if (!session) {
      clearInterval(sessionTimer);
      showLoginView();
      return;
    }
    const remaining = session.expiresAt - Date.now();
    const timerEl = document.getElementById('sessionTimerDisplay');
    if (timerEl) {
      const mins = Math.floor(remaining / 60000);
      const secs = Math.floor((remaining % 60000) / 1000);
      timerEl.textContent = `Sessão: ${String(mins).padStart(2,'0')}:${String(secs).padStart(2,'0')}`;
      if (remaining < 60000) {
        timerEl.classList.add('warning');
        if (!sessionWarned) {
          sessionWarned = true;
          alert('⚠️ Sua sessão expirará em 1 minuto. Qualquer ação a renovará.');
        }
      } else {
        timerEl.classList.remove('warning');
      }
    }
    if (remaining <= 0) {
      destroySession();
      alert('⏱️ Sessão expirada por inatividade. Faça login novamente.');
      showLoginView();
    }
  }, 1000);
}

/* Renova sessão em qualquer interação */
document.addEventListener('click', () => { if (getSession()) renewSession(); });
document.addEventListener('keydown', () => { if (getSession()) renewSession(); });

/* ============================================================
   5. CONTROLE DE TENTATIVAS DE LOGIN (lockout)
   Em produção: implementar no servidor com rate limiting.
   ============================================================ */
const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_MS = 2 * 60 * 1000; // 2 minutos

function getLoginAttempts() {
  try {
    const raw = localStorage.getItem('loginAttempts');
    return raw ? JSON.parse(raw) : { count: 0, lockedUntil: 0 };
  } catch { return { count: 0, lockedUntil: 0 }; }
}
function setLoginAttempts(data) {
  try { localStorage.setItem('loginAttempts', JSON.stringify(data)); } catch {}
}
function resetLoginAttempts() {
  try { localStorage.removeItem('loginAttempts'); } catch {}
}

/* ============================================================
   6. SANITIZAÇÃO XSS
   Converte HTML especial em entidades para evitar injeção de scripts.
   Em produção: sanitizar também no servidor.
   ============================================================ */
function sanitizeHTML(str) {
  if (typeof str !== 'string') return '';
  const el = document.createElement('div');
  el.textContent = str;
  return el.innerHTML;
}

/* ============================================================
   7. ARMAZENAMENTO DE DADOS
   ============================================================ */
function loadOccurrences() {
  try {
    const raw = localStorage.getItem('occurrences');
    if (!raw) {
      saveOccurrences(INITIAL_DATA);
      return [...INITIAL_DATA];
    }
    return JSON.parse(raw);
  } catch { return [...INITIAL_DATA]; }
}

function saveOccurrences(data) {
  try { localStorage.setItem('occurrences', JSON.stringify(data)); } catch {}
}

function loadLogs() {
  try {
    const raw = localStorage.getItem('auditLogs');
    return raw ? JSON.parse(raw) : [];
  } catch { return []; }
}

function saveLogs(logs) {
  try { localStorage.setItem('auditLogs', JSON.stringify(logs)); } catch {}
}

/* ============================================================
   8. LOGS DE AUDITORIA (sem dados pessoais extensos)
   Registra apenas matrícula e ID — sem CPF, descrição completa, etc.
   Em produção: logs devem ser append-only no servidor.
   ============================================================ */
function addLog(action, details) {
  if (!hasPermission('canViewOccurrences')) return;
  const session = getSession();
  const logs = loadLogs();
  const entry = {
    ts: new Date().toISOString(),
    user: session ? session.email : 'desconhecido',
    role: session ? session.role : '—',
    action,
    details, // apenas matrícula e ID, nunca dados pessoais completos
  };
  logs.unshift(entry);
  if (logs.length > 500) logs.splice(500); // limitar tamanho
  saveLogs(logs);
}

/* ============================================================
   9. UTILITÁRIOS
   ============================================================ */
function genId() {
  return Date.now().toString(36) + Math.random().toString(36).substring(2, 8);
}

function showEl(id) { const el = document.getElementById(id); if (el) el.style.display = ''; }
function hideEl(id) { const el = document.getElementById(id); if (el) el.style.display = 'none'; }
function showAlert(id, msg) { const el = document.getElementById(id); if (el) { el.textContent = msg; el.style.display = ''; } }
function hideAlert(id) { const el = document.getElementById(id); if (el) el.style.display = 'none'; }

/* ============================================================
   10. LOGIN
   ============================================================ */
function handleLogin() {
  const emailRaw = document.getElementById('inputEmail').value.trim();
  const passwordRaw = document.getElementById('inputPassword').value;
  hideAlert('loginAlert');
  hideAlert('loginLockAlert');

  // Verifica lockout
  const attempts = getLoginAttempts();
  if (attempts.lockedUntil > Date.now()) {
    const remaining = Math.ceil((attempts.lockedUntil - Date.now()) / 1000);
    showAlert('loginLockAlert', `⛔ Muitas tentativas falhas. Aguarde ${remaining} segundos.`);
    return;
  }

  // Validação básica de entrada
  if (!emailRaw || !passwordRaw) {
    showAlert('loginAlert', 'Preencha e-mail e senha.');
    return;
  }

  const user = USERS.find(u => u.email === emailRaw);
  const inputHash = hashDemoPassword(passwordRaw);
  const valid = user && user.passwordHash === inputHash;

  if (!valid) {
    attempts.count = (attempts.count || 0) + 1;
    if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
      attempts.lockedUntil = Date.now() + LOCKOUT_MS;
      setLoginAttempts(attempts);
      showAlert('loginLockAlert', `⛔ Conta bloqueada por ${LOCKOUT_MS / 60000} minutos após ${MAX_LOGIN_ATTEMPTS} tentativas.`);
    } else {
      setLoginAttempts(attempts);
      // Mensagem genérica — não revela qual campo está errado
      showAlert('loginAlert', `Credenciais inválidas. Tentativa ${attempts.count} de ${MAX_LOGIN_ATTEMPTS}.`);
    }
    return;
  }

  // Login bem-sucedido
  resetLoginAttempts();
  createSession(user);
  addLog('LOGIN', `Acesso realizado`);
  showDashboard(user);
}

/* Permitir Enter no campo senha */
document.addEventListener('DOMContentLoaded', () => {
  const passField = document.getElementById('inputPassword');
  if (passField) passField.addEventListener('keydown', e => { if (e.key === 'Enter') handleLogin(); });
  const emailField = document.getElementById('inputEmail');
  if (emailField) emailField.addEventListener('keydown', e => { if (e.key === 'Enter') handleLogin(); });

  // Verificar sessão existente ao carregar
  const session = getSession();
  if (session) {
    const user = USERS.find(u => u.id === session.userId);
    if (user) { showDashboard(user); return; }
  }
  showLoginView();
});

/* ============================================================
   11. EXIBIÇÃO DE VIEWS
   ============================================================ */
function showLoginView() {
  hideEl('sectionDashboard');
  hideEl('headerSession');
  showEl('sectionLogin');
  document.getElementById('inputEmail').value = '';
  document.getElementById('inputPassword').value = '';
  hideAlert('loginAlert');
  hideAlert('loginLockAlert');
}

function showDashboard(user) {
  hideEl('sectionLogin');
  showEl('sectionDashboard');
  showEl('headerSession');

  // Renderizar info do usuário
  document.getElementById('displayUserName').textContent = sanitizeHTML(user.name);
  document.getElementById('displayUserEmail').textContent = sanitizeHTML(user.email);
  const roleEl = document.getElementById('displayUserRole');
  roleEl.textContent = `Perfil: ${user.role}`;
  roleEl.className = `badge badge-role-${user.role}`;

  // Controle de visibilidade por perfil (RBAC)
  setIfPermission('btnExport', 'canExport');
  setIfPermission('btnClearLogs', 'canClearLogs');
  setIfPermission('btnRestore', 'canRestore');
  setIfPermission('sectionNewOccurrence', 'canCreateOccurrence');
  setIfPermission('sectionLogs', 'canViewLogs');
  setIfPermission('adminObsGroup', 'canViewInternalObs');

  // Mostrar/ocultar "Nenhuma ação disponível"
  const hasActions = hasPermission('canExport') || hasPermission('canClearLogs') || hasPermission('canRestore');
  document.getElementById('noActionsMsg').style.display = hasActions ? 'none' : '';

  startSessionTimer();
  renderOccurrences();
  if (hasPermission('canViewLogs')) renderLogs();
}

function setIfPermission(elId, permission) {
  const el = document.getElementById(elId);
  if (el) el.style.display = hasPermission(permission) ? '' : 'none';
}

/* ============================================================
   12. LOGOUT
   ============================================================ */
function logout() {
  addLog('LOGOUT', 'Sessão encerrada pelo usuário');
  destroySession();
  showLoginView();
}

/* ============================================================
   13. OCORRÊNCIAS — SALVAR
   ============================================================ */
function saveOccurrence() {
  if (!hasPermission('canCreateOccurrence')) {
    alert('Você não tem permissão para cadastrar ocorrências.');
    return;
  }

  hideAlert('occurrenceAlert');

  const aluno = document.getElementById('occAluno').value.trim();
  const matricula = document.getElementById('occMatricula').value.trim();
  const tipo = document.getElementById('occTipo').value;
  const prioridade = document.getElementById('occPrioridade').value;
  const descricao = document.getElementById('occDescricao').value.trim();
  const obsInterna = hasPermission('canViewInternalObs') ? document.getElementById('occObsInterna').value.trim() : '';
  const consentimento = document.getElementById('occConsentimento').checked;

  // Validação obrigatória
  if (!aluno || !matricula || !tipo || !prioridade || !descricao) {
    showAlert('occurrenceAlert', 'Preencha todos os campos obrigatórios.');
    return;
  }
  if (!consentimento) {
    showAlert('occurrenceAlert', 'Confirme o termo de uso de dados fictícios.');
    return;
  }
  if (!/^[A-Za-z0-9\-]+$/.test(matricula)) {
    showAlert('occurrenceAlert', 'Matrícula deve conter apenas letras, números e hifens.');
    return;
  }

  const session = getSession();
  const occ = {
    id: genId(),
    aluno: aluno.substring(0, 100),
    matricula: matricula.substring(0, 20),
    tipo,
    prioridade,
    status: 'Aberto',
    descricao: descricao.substring(0, 1000),
    obsInterna: obsInterna.substring(0, 500),
    criadoPor: session ? session.userId : 'desconhecido',
    criadoEm: new Date().toISOString(),
  };

  const data = loadOccurrences();
  data.push(occ);
  saveOccurrences(data);

  // Log sem dados pessoais extensos
  addLog('CRIAR_OCORRENCIA', `Matrícula: ${sanitizeHTML(matricula)} | ID: ${occ.id}`);

  // Limpar formulário
  ['occAluno','occMatricula','occDescricao','occObsInterna'].forEach(id => {
    const el = document.getElementById(id); if (el) el.value = '';
  });
  document.getElementById('occTipo').value = '';
  document.getElementById('occPrioridade').value = '';
  document.getElementById('occConsentimento').checked = false;

  renderOccurrences();
  if (hasPermission('canViewLogs')) renderLogs();
  showAlert('occurrenceAlert', '✅ Ocorrência registrada com sucesso.');
  document.getElementById('occurrenceAlert').className = 'alert alert-success';
  setTimeout(() => hideAlert('occurrenceAlert'), 3000);
}

/* ============================================================
   14. OCORRÊNCIAS — RENDERIZAR
   Alunos veem apenas as próprias ocorrências por matrícula simulada.
   ============================================================ */
function renderOccurrences() {
  const session = getSession();
  if (!session) return;

  const data = loadOccurrences();
  const search = (document.getElementById('searchInput')?.value || '').toLowerCase().trim();

  // Filtro de perfil: aluno vê apenas ocorrências de sua matrícula simulada
  // (na demo, aluno não tem matrícula real; apenas exibe mensagem informativa)
  let filtered = data;
  if (!hasPermission('canViewAllOccurrences')) {
    filtered = []; // Aluno não vê ocorrências de outros
  }

  // Filtro de busca (apenas nome e matrícula — sem expor CPF ou e-mail)
  if (search) {
    filtered = filtered.filter(o =>
      o.aluno.toLowerCase().includes(search) ||
      o.matricula.toLowerCase().includes(search)
    );
  }

  // Estatísticas
  document.getElementById('statTotal').textContent = filtered.length;
  document.getElementById('statCritical').textContent = filtered.filter(o => o.prioridade === 'Crítica').length;

  const container = document.getElementById('occurrencesList');

  if (!session || !hasPermission('canViewOccurrences')) {
    container.innerHTML = '<p class="text-muted text-center">Sem permissão para visualizar registros.</p>';
    return;
  }

  if (filtered.length === 0) {
    container.innerHTML = '<p class="text-muted text-center">Nenhuma ocorrência encontrada.</p>';
    return;
  }

  // Construir tabela (sanitizando todos os dados antes de renderizar)
  let html = `<div style="overflow-x:auto"><table class="occ-table">
    <thead><tr>
      <th>Aluno</th><th>Matrícula</th><th>Tipo</th>
      <th>Prioridade</th><th>Status</th><th>Descrição</th>
      ${hasPermission('canViewInternalObs') ? '<th>Obs. interna</th>' : ''}
      ${hasPermission('canEditStatus') || hasPermission('canDeleteOccurrence') ? '<th>Ações</th>' : ''}
    </tr></thead><tbody>`;

  filtered.forEach(o => {
    const actions = [];
    if (hasPermission('canEditStatus')) {
      actions.push(`<select class="status-select" onchange="changeStatus('${sanitizeHTML(o.id)}', this.value)">
        <option ${o.status==='Aberto'?'selected':''}>Aberto</option>
        <option ${o.status==='Em análise'?'selected':''}>Em análise</option>
        <option ${o.status==='Resolvido'?'selected':''}>Resolvido</option>
        <option ${o.status==='Arquivado'?'selected':''}>Arquivado</option>
      </select>`);
    }
    if (hasPermission('canDeleteOccurrence')) {
      actions.push(`<button class="btn-icon" title="Excluir" onclick="deleteOccurrence('${sanitizeHTML(o.id)}')">🗑️</button>`);
    }

    html += `<tr>
      <td>${sanitizeHTML(o.aluno)}</td>
      <td><code>${sanitizeHTML(o.matricula)}</code></td>
      <td>${sanitizeHTML(o.tipo)}</td>
      <td><span class="priority-badge priority-${sanitizeHTML(o.prioridade)}">${sanitizeHTML(o.prioridade)}</span></td>
      <td>${sanitizeHTML(o.status)}</td>
      <td style="max-width:200px;word-break:break-word">${sanitizeHTML(o.descricao)}</td>
      ${hasPermission('canViewInternalObs') ? `<td class="obs-interna-cell">${sanitizeHTML(o.obsInterna || '—')}</td>` : ''}
      ${actions.length ? `<td><div class="inline-status">${actions.join('')}</div></td>` : ''}
    </tr>`;
  });

  html += '</tbody></table></div>';
  container.innerHTML = html;
}

/* ============================================================
   15. ALTERAR STATUS
   ============================================================ */
function changeStatus(id, newStatus) {
  if (!hasPermission('canEditStatus')) { alert('Sem permissão.'); return; }
  const data = loadOccurrences();
  const occ = data.find(o => o.id === id);
  if (!occ) return;
  const oldStatus = occ.status;
  occ.status = newStatus;
  saveOccurrences(data);
  addLog('ALTERAR_STATUS', `ID: ${id} | ${oldStatus} → ${newStatus}`);
  renderOccurrences();
  if (hasPermission('canViewLogs')) renderLogs();
}

/* ============================================================
   16. EXCLUIR OCORRÊNCIA (apenas admin, com confirmação)
   ============================================================ */
function deleteOccurrence(id) {
  if (!hasPermission('canDeleteOccurrence')) { alert('Sem permissão.'); return; }
  if (!confirm('⚠️ Confirma a exclusão desta ocorrência? Esta ação não pode ser desfeita.')) return;
  const data = loadOccurrences().filter(o => o.id !== id);
  saveOccurrences(data);
  addLog('EXCLUIR_OCORRENCIA', `ID: ${id}`);
  renderOccurrences();
  if (hasPermission('canViewLogs')) renderLogs();
}

/* ============================================================
   17. EXPORTAÇÃO SEGURA (sem senhas, tokens ou localStorage completo)
   ============================================================ */
function exportData() {
  if (!hasPermission('canExport')) { alert('Sem permissão para exportar.'); return; }
  if (!confirm('Exportar ocorrências? O arquivo conterá apenas os registros de ocorrências (sem senhas ou dados sensíveis).')) return;

  const data = loadOccurrences();
  // Exportar apenas os campos de ocorrência — sem senhas, tokens ou localStorage
  const exportObj = {
    exportedAt: new Date().toISOString(),
    exportedBy: getSession()?.email || '—',
    notice: 'Protótipo didático — dados fictícios',
    occurrences: data.map(o => ({
      id: o.id,
      aluno: o.aluno,
      matricula: o.matricula,
      tipo: o.tipo,
      prioridade: o.prioridade,
      status: o.status,
      descricao: o.descricao,
      criadoEm: o.criadoEm,
      // obsInterna incluída apenas para admin (quem pode exportar é admin)
      obsInterna: o.obsInterna || '',
    })),
  };

  const blob = new Blob([JSON.stringify(exportObj, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `ocorrencias_${new Date().toISOString().slice(0,10)}.json`;
  a.click();
  URL.revokeObjectURL(url);

  addLog('EXPORTAR', `${data.length} ocorrências exportadas`);
  if (hasPermission('canViewLogs')) renderLogs();
}

/* ============================================================
   18. LOGS — RENDERIZAR
   ============================================================ */
function renderLogs() {
  if (!hasPermission('canViewLogs')) return;
  const logs = loadLogs();
  const container = document.getElementById('logsList');
  if (!logs.length) {
    container.innerHTML = '<p class="text-muted">Nenhum log registrado.</p>';
    return;
  }
  container.innerHTML = logs.map(l =>
    `<div class="log-entry">[${sanitizeHTML(l.ts)}] <strong>${sanitizeHTML(l.role)}</strong> (${sanitizeHTML(l.user)}) — ${sanitizeHTML(l.action)}: ${sanitizeHTML(l.details)}</div>`
  ).join('');
}

/* ============================================================
   19. LIMPAR LOGS (apenas admin, com confirmação e registro)
   ============================================================ */
function clearLogs() {
  if (!hasPermission('canClearLogs')) { alert('Sem permissão.'); return; }
  if (!confirm('⚠️ Limpar todos os logs de auditoria? Esta ação será registrada e não pode ser desfeita.')) return;
  const session = getSession();
  const clearEntry = {
    ts: new Date().toISOString(),
    user: session?.email || '—',
    role: session?.role || '—',
    action: 'LIMPAR_LOGS',
    details: 'Log anterior apagado pelo administrador',
  };
  saveLogs([clearEntry]); // mantém apenas o registro da limpeza
  renderLogs();
}

/* ============================================================
   20. RESTAURAR DADOS INICIAIS (apenas admin, com confirmação)
   ============================================================ */
function restoreData() {
  if (!hasPermission('canRestore')) { alert('Sem permissão.'); return; }
  if (!confirm('⚠️ Restaurar dados iniciais? Todas as ocorrências atuais serão perdidas.')) return;
  saveOccurrences(JSON.parse(JSON.stringify(INITIAL_DATA)));
  addLog('RESTAURAR_DADOS', 'Dados restaurados para o estado inicial pelo administrador');
  renderOccurrences();
  if (hasPermission('canViewLogs')) renderLogs();
}

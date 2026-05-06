// ============================================================
// SISTEMA DE OCORRÊNCIAS ACADÊMICAS — VERSÃO COM MELHORIAS DE SEGURANÇA
// ============================================================
// AVISO: Este é um protótipo front-end. Todas as proteções aqui
// são simulações didáticas. Em produção, autenticação, autorização,
// sessão, logs e persistência DEVEM estar no back-end/servidor.
// ============================================================

"use strict";

// --- CONFIGURAÇÃO DE USUÁRIOS ---
// MELHORIA: Senhas mais fortes (simulação). Em produção, senhas
// NUNCA devem estar no código-fonte; devem ser hashes no servidor.
const USERS = [
  {
    id: 1,
    name: "Ana Souza",
    email: "aluno@faculdade.local",
    password: "Demo@2026",
    role: "ALUNO",
    studentId: "202400001"
  },
  {
    id: 2,
    name: "Prof. Carlos Lima",
    email: "professor@faculdade.local",
    password: "Demo@2026",
    role: "PROFESSOR",
    classes: ["5A", "5B"]
  },
  {
    id: 3,
    name: "Administrador Geral",
    email: "admin@faculdade.local",
    password: "Admin@2026",
    role: "ADMIN"
  }
];

// MELHORIA: Token secreto removido do código exposto.
// Em produção, tokens são gerenciados pelo servidor e nunca ficam no front-end.

const STORAGE_KEYS = {
  session: "ocorrencias_sessao",
  occurrences: "ocorrencias_registros",
  audit: "ocorrencias_logs"
};

// MELHORIA: Configuração de sessão com timeout
const SESSION_CONFIG = {
  timeoutMinutes: 15,
  maxLoginAttempts: 5,
  lockoutMinutes: 2
};

// Controle de tentativas de login
let loginAttempts = 0;
let lockoutUntil = null;
let sessionTimerInterval = null;
let lastActivity = null;

// --- DADOS INICIAIS ---
// MELHORIA: Removidos CPF, e-mail pessoal e telefone dos dados iniciais
// (minimização de dados conforme LGPD)
const INITIAL_OCCURRENCES = [
  {
    id: "OC-1001",
    studentName: "Marina Alves",
    studentId: "202300145",
    category: "Nota",
    priority: "Média",
    description: "Solicitação de revisão de nota da avaliação bimestral.",
    internalNote: "Verificar com a coordenação antes de responder.",
    status: "Aberta",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:40:00.000Z"
  },
  {
    id: "OC-1002",
    studentName: "Rafael Martins",
    studentId: "202200771",
    category: "Frequência",
    priority: "Alta",
    description: "Aluno contesta lançamento de falta em aula prática.",
    internalNote: "Conferir chamada manual.",
    status: "Em análise",
    createdBy: "professor@faculdade.local",
    createdAt: "2026-05-05T18:50:00.000Z"
  },
  {
    id: "OC-1003",
    studentName: "Beatriz Costa",
    studentId: "202100441",
    category: "Solicitação administrativa",
    priority: "Crítica",
    description: "Solicitação envolvendo documentação acadêmica e prazo de matrícula.",
    internalNote: "Priorizar atendimento.",
    status: "Aberta",
    createdBy: "admin@faculdade.local",
    createdAt: "2026-05-05T19:00:00.000Z"
  }
];

// --- PERMISSÕES POR PERFIL (RBAC simulado) ---
const PERMISSIONS = {
  ALUNO: {
    canCreateOccurrence: false,
    canViewAllOccurrences: false,
    canViewOwnOccurrences: true,
    canDeleteOccurrence: false,
    canChangeStatus: false,
    canExport: false,
    canViewLogs: false,
    canClearLogs: false,
    canReset: false,
    canViewInternalNotes: false
  },
  PROFESSOR: {
    canCreateOccurrence: true,
    canViewAllOccurrences: true,
    canViewOwnOccurrences: true,
    canDeleteOccurrence: false,
    canChangeStatus: true,
    canExport: false,
    canViewLogs: false,
    canClearLogs: false,
    canReset: false,
    canViewInternalNotes: false
  },
  ADMIN: {
    canCreateOccurrence: true,
    canViewAllOccurrences: true,
    canViewOwnOccurrences: true,
    canDeleteOccurrence: true,
    canChangeStatus: true,
    canExport: true,
    canViewLogs: true,
    canClearLogs: true,
    canReset: true,
    canViewInternalNotes: true
  }
};

// --- REFERÊNCIAS DO DOM ---
const loginView = document.querySelector("#loginView");
const appView = document.querySelector("#appView");
const loginForm = document.querySelector("#loginForm");
const occurrenceForm = document.querySelector("#occurrenceForm");
const logoutBtn = document.querySelector("#logoutBtn");
const exportBtn = document.querySelector("#exportBtn");
const clearLogsBtn = document.querySelector("#clearLogsBtn");
const resetBtn = document.querySelector("#resetBtn");
const searchInput = document.querySelector("#search");
const loginError = document.querySelector("#loginError");
const loginLockout = document.querySelector("#loginLockout");

const sessionBadge = document.querySelector("#sessionBadge");
const sessionTimer = document.querySelector("#sessionTimer");
const currentUserName = document.querySelector("#currentUserName");
const currentUserDetails = document.querySelector("#currentUserDetails");
const currentRoleDisplay = document.querySelector("#currentRoleDisplay");
const occurrencesTable = document.querySelector("#occurrencesTable");
const auditLog = document.querySelector("#auditLog");
const totalOccurrences = document.querySelector("#totalOccurrences");
const criticalOccurrences = document.querySelector("#criticalOccurrences");
const lastUpdate = document.querySelector("#lastUpdate");

// --- FUNÇÕES UTILITÁRIAS DE SEGURANÇA ---

// MELHORIA: Sanitização de strings para prevenir XSS
function sanitizeHTML(str) {
  if (typeof str !== "string") return "";
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

// MELHORIA: Validação de e-mail
function isValidEmail(email) {
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return re.test(email);
}

// MELHORIA: Validação de matrícula (somente números, 6-12 dígitos)
function isValidStudentId(id) {
  return /^[0-9]{6,12}$/.test(id);
}

// MELHORIA: Verificação de permissão centralizada
function hasPermission(permissionName) {
  const session = getSession();
  if (!session || !session.role) return false;
  const perms = PERMISSIONS[session.role];
  return perms ? perms[permissionName] === true : false;
}

// --- FUNÇÕES DE PERSISTÊNCIA (localStorage) ---

function getOccurrences() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.occurrences) || "[]");
  } catch {
    return [];
  }
}

function saveOccurrences(occurrences) {
  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(occurrences));
}

function getAuditLogs() {
  try {
    return JSON.parse(localStorage.getItem(STORAGE_KEYS.audit) || "[]");
  } catch {
    return [];
  }
}

function saveAuditLogs(logs) {
  localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify(logs));
}

function getSession() {
  try {
    const session = JSON.parse(localStorage.getItem(STORAGE_KEYS.session) || "null");
    if (session && session.expiresAt) {
      if (new Date(session.expiresAt) < new Date()) {
        // Sessão expirada
        localStorage.removeItem(STORAGE_KEYS.session);
        return null;
      }
    }
    return session;
  } catch {
    return null;
  }
}

function saveSession(user) {
  // MELHORIA: Sessão com expiração
  const sessionData = {
    id: user.id,
    name: user.name,
    email: user.email,
    role: user.role,
    // NÃO armazenamos a senha na sessão
    loginAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + SESSION_CONFIG.timeoutMinutes * 60 * 1000).toISOString()
  };
  localStorage.setItem(STORAGE_KEYS.session, JSON.stringify(sessionData));
  lastActivity = Date.now();
}

// --- LOGS DE AUDITORIA ---

function writeLog(action, detail) {
  const session = getSession();
  const logs = getAuditLogs();

  // MELHORIA: Log não inclui dados pessoais sensíveis (CPF, e-mail pessoal)
  logs.unshift({
    when: new Date().toISOString(),
    user: session ? session.email : "anonimo",
    role: session ? session.role : "SEM_SESSAO",
    action,
    detail: typeof detail === "string" ? detail.substring(0, 500) : ""
  });

  // MELHORIA: Limitar tamanho do log (máximo 500 entradas)
  if (logs.length > 500) {
    logs.length = 500;
  }

  saveAuditLogs(logs);
}

// --- CONTROLE DE SESSÃO E TIMER ---

function startSessionTimer() {
  clearInterval(sessionTimerInterval);
  sessionTimer.classList.remove("hidden");

  sessionTimerInterval = setInterval(() => {
    const session = getSession();
    if (!session || !session.expiresAt) {
      clearInterval(sessionTimerInterval);
      sessionTimer.classList.add("hidden");
      return;
    }

    const remaining = new Date(session.expiresAt) - new Date();
    if (remaining <= 0) {
      clearInterval(sessionTimerInterval);
      writeLog("SESSAO_EXPIRADA", "Sessão encerrada automaticamente por inatividade.");
      logout();
      alert("Sua sessão expirou. Faça login novamente.");
      return;
    }

    const mins = Math.floor(remaining / 60000);
    const secs = Math.floor((remaining % 60000) / 1000);
    sessionTimer.textContent = `⏱ ${mins}:${secs.toString().padStart(2, "0")}`;

    // Aviso quando restam 2 minutos
    if (remaining < 120000) {
      sessionTimer.style.color = "var(--danger)";
    } else {
      sessionTimer.style.color = "";
    }
  }, 1000);
}

// MELHORIA: Renovar sessão a cada interação
function renewSession() {
  const session = getSession();
  if (session) {
    session.expiresAt = new Date(Date.now() + SESSION_CONFIG.timeoutMinutes * 60 * 1000).toISOString();
    localStorage.setItem(STORAGE_KEYS.session, JSON.stringify(session));
    lastActivity = Date.now();
  }
}

// Listener para renovar sessão em ações do usuário
document.addEventListener("click", renewSession);
document.addEventListener("keydown", renewSession);

// --- VIEWS ---

function showLogin() {
  loginView.classList.remove("hidden");
  appView.classList.add("hidden");
  logoutBtn.classList.add("hidden");
  sessionTimer.classList.add("hidden");
  sessionBadge.textContent = "Sessão não iniciada";
  sessionBadge.classList.add("muted");
  clearInterval(sessionTimerInterval);

  // Limpar campos do formulário de login
  document.querySelector("#email").value = "";
  document.querySelector("#password").value = "";
  loginError.classList.add("hidden");
}

function showApp(user) {
  loginView.classList.add("hidden");
  appView.classList.remove("hidden");
  logoutBtn.classList.remove("hidden");

  sessionBadge.textContent = `${sanitizeHTML(user.name)} — ${sanitizeHTML(user.role)}`;
  sessionBadge.classList.remove("muted");

  currentUserName.textContent = user.name;
  currentUserDetails.textContent = user.email;
  currentRoleDisplay.textContent = translateRole(user.role);

  // MELHORIA: Aplicar RBAC — exibir/ocultar seções conforme perfil
  applyPermissions(user.role);

  startSessionTimer();
  render();
}

function translateRole(role) {
  const roles = { ALUNO: "Aluno", PROFESSOR: "Professor", ADMIN: "Administrador" };
  return roles[role] || role;
}

// MELHORIA: Controle de acesso baseado em perfil (RBAC)
function applyPermissions(role) {
  const perms = PERMISSIONS[role] || {};

  // Formulário de ocorrência
  const occurrenceSection = document.querySelector("#occurrenceSection");
  if (perms.canCreateOccurrence) {
    occurrenceSection.classList.remove("hidden");
  } else {
    occurrenceSection.classList.add("hidden");
  }

  // Botões de ação
  exportBtn.classList.toggle("hidden", !perms.canExport);
  clearLogsBtn.classList.toggle("hidden", !perms.canClearLogs);
  resetBtn.classList.toggle("hidden", !perms.canReset);

  // Mensagem quando não há ações
  const noActionsMsg = document.querySelector("#noActionsMsg");
  if (!perms.canExport && !perms.canClearLogs && !perms.canReset) {
    noActionsMsg.classList.remove("hidden");
  } else {
    noActionsMsg.classList.add("hidden");
  }

  // Observação interna (só admin)
  const internalNoteLabel = document.querySelector("#internalNoteLabel");
  if (perms.canViewInternalNotes) {
    internalNoteLabel.classList.remove("hidden");
  } else {
    internalNoteLabel.classList.add("hidden");
  }

  // Tabela de ocorrências
  const tableSection = document.querySelector("#tableSection");
  if (perms.canViewAllOccurrences || perms.canViewOwnOccurrences) {
    tableSection.classList.remove("hidden");
  } else {
    tableSection.classList.add("hidden");
  }

  // Coluna de ações na tabela
  const actionsHeader = document.querySelector("#actionsHeader");
  if (perms.canChangeStatus || perms.canDeleteOccurrence) {
    actionsHeader.classList.remove("hidden");
  } else {
    actionsHeader.classList.add("hidden");
  }

  // Logs (só admin)
  const logsSection = document.querySelector("#logsSection");
  if (perms.canViewLogs) {
    logsSection.classList.remove("hidden");
  } else {
    logsSection.classList.add("hidden");
  }
}

// --- AUTENTICAÇÃO ---

function login(email, password) {
  // MELHORIA: Verificar lockout
  if (lockoutUntil && new Date() < lockoutUntil) {
    const remaining = Math.ceil((lockoutUntil - new Date()) / 1000);
    loginLockout.textContent = `Muitas tentativas. Aguarde ${remaining} segundos.`;
    loginLockout.classList.remove("hidden");
    return;
  }

  loginLockout.classList.add("hidden");

  // MELHORIA: Validação de entrada
  if (!email || !isValidEmail(email)) {
    loginError.textContent = "Informe um e-mail válido.";
    loginError.classList.remove("hidden");
    return;
  }

  if (!password || password.length < 4) {
    loginError.textContent = "Informe a senha.";
    loginError.classList.remove("hidden");
    return;
  }

  const user = USERS.find((item) => item.email === email && item.password === password);

  if (!user) {
    loginAttempts++;
    // MELHORIA: Mensagem genérica (não revela se é o e-mail ou a senha que está errado)
    loginError.textContent = "Credenciais inválidas.";
    loginError.classList.remove("hidden");

    writeLog("LOGIN_FALHOU", `Tentativa ${loginAttempts} de login falhou.`);

    // MELHORIA: Bloqueio após tentativas excessivas
    if (loginAttempts >= SESSION_CONFIG.maxLoginAttempts) {
      lockoutUntil = new Date(Date.now() + SESSION_CONFIG.lockoutMinutes * 60 * 1000);
      loginLockout.textContent = `Conta bloqueada por ${SESSION_CONFIG.lockoutMinutes} minutos por excesso de tentativas.`;
      loginLockout.classList.remove("hidden");
      loginError.classList.add("hidden");
      writeLog("LOGIN_BLOQUEADO", `Bloqueio por ${SESSION_CONFIG.lockoutMinutes} min após ${loginAttempts} tentativas.`);
      loginAttempts = 0;
    }
    return;
  }

  // Login bem-sucedido
  loginAttempts = 0;
  lockoutUntil = null;
  loginError.classList.add("hidden");

  saveSession(user);
  writeLog("LOGIN_OK", `Usuário ${user.email} entrou no sistema com perfil ${user.role}.`);
  showApp(getSession());
}

function logout() {
  const session = getSession();
  writeLog("LOGOUT", session ? `${session.email} saiu do sistema.` : "Sessão encerrada.");
  localStorage.removeItem(STORAGE_KEYS.session);
  clearInterval(sessionTimerInterval);
  showLogin();
}

// --- OCORRÊNCIAS ---

function createOccurrence(event) {
  event.preventDefault();

  // MELHORIA: Verificar permissão
  if (!hasPermission("canCreateOccurrence")) {
    alert("Você não tem permissão para criar ocorrências.");
    writeLog("ACESSO_NEGADO", "Tentativa de criar ocorrência sem permissão.");
    return;
  }

  const session = getSession();
  if (!session) {
    alert("Sessão expirada. Faça login novamente.");
    showLogin();
    return;
  }

  // MELHORIA: Validação de campos obrigatórios
  const studentName = document.querySelector("#studentName").value.trim();
  const studentId = document.querySelector("#studentId").value.trim();
  const category = document.querySelector("#category").value;
  const priority = document.querySelector("#priority").value;
  const description = document.querySelector("#description").value.trim();
  const privacyAck = document.querySelector("#privacyAck").checked;

  if (!studentName) {
    alert("Informe o nome do aluno.");
    return;
  }

  if (!isValidStudentId(studentId)) {
    alert("Matrícula inválida. Use entre 6 e 12 dígitos numéricos.");
    return;
  }

  if (!category) {
    alert("Selecione o tipo de ocorrência.");
    return;
  }

  if (!priority) {
    alert("Selecione a prioridade.");
    return;
  }

  if (!description) {
    alert("Informe a descrição da ocorrência.");
    return;
  }

  if (!privacyAck) {
    alert("Você precisa confirmar o checkbox de consentimento.");
    return;
  }

  const internalNote = hasPermission("canViewInternalNotes")
    ? (document.querySelector("#internalNote").value.trim() || "")
    : "";

  // MELHORIA: ID sequencial em vez de aleatório (evita colisão)
  const occurrences = getOccurrences();
  const maxId = occurrences.reduce((max, oc) => {
    const num = parseInt(oc.id.replace("OC-", ""), 10);
    return num > max ? num : max;
  }, 1000);

  const occurrence = {
    id: `OC-${maxId + 1}`,
    studentName: sanitizeHTML(studentName),
    studentId: sanitizeHTML(studentId),
    category: sanitizeHTML(category),
    priority: sanitizeHTML(priority),
    description: sanitizeHTML(description),
    internalNote: sanitizeHTML(internalNote),
    status: "Aberta",
    createdBy: session.email,
    createdAt: new Date().toISOString()
  };

  occurrences.unshift(occurrence);
  saveOccurrences(occurrences);

  // MELHORIA: Log não expõe dados pessoais completos
  writeLog("OCORRENCIA_CRIADA", `Ocorrência ${occurrence.id} criada para aluno matrícula ${occurrence.studentId}.`);

  occurrenceForm.reset();
  render();
}

function deleteOccurrence(id) {
  // MELHORIA: Verificar permissão
  if (!hasPermission("canDeleteOccurrence")) {
    alert("Você não tem permissão para excluir ocorrências.");
    writeLog("ACESSO_NEGADO", `Tentativa de excluir ocorrência ${sanitizeHTML(id)} sem permissão.`);
    return;
  }

  // MELHORIA: Confirmação antes de excluir
  if (!confirm(`Tem certeza que deseja excluir a ocorrência ${id}? Esta ação não pode ser desfeita.`)) {
    return;
  }

  const occurrences = getOccurrences();
  const updated = occurrences.filter((item) => item.id !== id);

  saveOccurrences(updated);
  // MELHORIA: Log não inclui o JSON completo do registro
  writeLog("OCORRENCIA_EXCLUIDA", `Ocorrência ${sanitizeHTML(id)} excluída.`);
  render();
}

function changeStatus(id, status) {
  // MELHORIA: Verificar permissão
  if (!hasPermission("canChangeStatus")) {
    alert("Você não tem permissão para alterar o status de ocorrências.");
    writeLog("ACESSO_NEGADO", `Tentativa de alterar status de ${sanitizeHTML(id)} sem permissão.`);
    return;
  }

  const occurrences = getOccurrences();
  const occurrence = occurrences.find((item) => item.id === id);

  if (!occurrence) return;

  occurrence.status = status;
  occurrence.updatedAt = new Date().toISOString();
  occurrence.updatedBy = getSession() ? getSession().email : "desconhecido";

  saveOccurrences(occurrences);
  writeLog("STATUS_ALTERADO", `Ocorrência ${sanitizeHTML(id)} alterada para ${sanitizeHTML(status)}.`);
  render();
}

// --- EXPORTAÇÃO ---

function exportData() {
  // MELHORIA: Verificar permissão
  if (!hasPermission("canExport")) {
    alert("Você não tem permissão para exportar dados.");
    writeLog("ACESSO_NEGADO", "Tentativa de exportação sem permissão.");
    return;
  }

  // MELHORIA: Exportar apenas ocorrências (sem senhas, tokens, localStorage completo)
  const payload = {
    exportedAt: new Date().toISOString(),
    exportedBy: getSession() ? getSession().email : "desconhecido",
    occurrences: getOccurrences()
    // NÃO exporta: USERS (senhas), FAKE_API_TOKEN, localStorage completo, logs
  };

  const blob = new Blob([JSON.stringify(payload, null, 2)], {
    type: "application/json"
  });

  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = `ocorrencias-export-${new Date().toISOString().slice(0, 10)}.json`;
  anchor.click();
  URL.revokeObjectURL(url);

  writeLog("EXPORTACAO", "Usuário exportou as ocorrências do sistema.");
}

function clearLogs() {
  if (!hasPermission("canClearLogs")) {
    alert("Você não tem permissão para limpar logs.");
    return;
  }

  if (!confirm("Tem certeza que deseja limpar todos os logs? Esta ação será registrada.")) {
    return;
  }

  writeLog("LOGS_LIMPOS", "Usuário limpou os logs de auditoria.");
  saveAuditLogs([{
    when: new Date().toISOString(),
    user: getSession() ? getSession().email : "desconhecido",
    role: getSession() ? getSession().role : "SEM_SESSAO",
    action: "LOGS_LIMPOS",
    detail: "Histórico de logs limpo. Este é o registro da limpeza."
  }]);
  render();
}

function resetData() {
  if (!hasPermission("canReset")) {
    alert("Você não tem permissão para restaurar dados.");
    return;
  }

  if (!confirm("Restaurar todos os dados para o estado inicial? Todos os registros serão perdidos.")) {
    return;
  }

  localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(INITIAL_OCCURRENCES));
  localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify([]));
  writeLog("RESET_DADOS", "Dados restaurados ao estado inicial.");
  render();
}

// --- RENDERIZAÇÃO ---

function render() {
  const session = getSession();
  if (!session) return;

  const term = searchInput ? searchInput.value.toLowerCase().trim() : "";
  const occurrences = getOccurrences();
  const perms = PERMISSIONS[session.role] || {};

  // MELHORIA: Filtrar ocorrências conforme perfil
  let visibleOccurrences = occurrences;
  if (!perms.canViewAllOccurrences && perms.canViewOwnOccurrences) {
    // Aluno: vê apenas ocorrências relacionadas à própria matrícula
    const user = USERS.find(u => u.email === session.email);
    if (user && user.studentId) {
      visibleOccurrences = occurrences.filter(oc => oc.studentId === user.studentId);
    } else {
      visibleOccurrences = [];
    }
  }

  // Aplicar busca (sem expor CPF, e-mail pessoal, telefone na busca)
  const filtered = visibleOccurrences.filter((item) => {
    if (!term) return true;
    const searchable = [
      item.studentName,
      item.studentId,
      item.category,
      item.priority,
      item.status,
      item.description
    ].join(" ").toLowerCase();
    return searchable.includes(term);
  });

  totalOccurrences.textContent = visibleOccurrences.length;
  criticalOccurrences.textContent = visibleOccurrences.filter((item) => item.priority === "Crítica").length;
  lastUpdate.textContent = `Atualizado em ${new Date().toLocaleTimeString("pt-BR")}`;

  // MELHORIA: Renderização com sanitização e controle de colunas conforme perfil
  occurrencesTable.innerHTML = filtered.map((item) => {
    let actionsCol = "";
    if (perms.canChangeStatus || perms.canDeleteOccurrence) {
      actionsCol = `<td><div class="row-actions">`;
      if (perms.canChangeStatus) {
        actionsCol += `
          <button class="btn secondary" onclick="changeStatus('${sanitizeHTML(item.id)}', 'Em análise')">Em análise</button>
          <button class="btn secondary" onclick="changeStatus('${sanitizeHTML(item.id)}', 'Resolvida')">Resolver</button>
        `;
      }
      if (perms.canDeleteOccurrence) {
        actionsCol += `<button class="btn danger" onclick="deleteOccurrence('${sanitizeHTML(item.id)}')">Excluir</button>`;
      }
      actionsCol += `</div></td>`;
    }

    // MELHORIA: Observação interna só aparece para admin
    const internalNoteHTML = perms.canViewInternalNotes && item.internalNote
      ? `<br/><em class="muted-text">Obs. interna: ${sanitizeHTML(item.internalNote)}</em>`
      : "";

    return `
      <tr>
        <td><strong>${sanitizeHTML(item.studentName)}</strong></td>
        <td>${sanitizeHTML(item.studentId)}</td>
        <td>${sanitizeHTML(item.category)}</td>
        <td><span class="priority ${sanitizeHTML(item.priority)}">${sanitizeHTML(item.priority)}</span></td>
        <td>${sanitizeHTML(item.status)}</td>
        <td>${sanitizeHTML(item.description)}${internalNoteHTML}</td>
        ${actionsCol}
      </tr>
    `;
  }).join("");

  // Renderizar logs (apenas se admin)
  if (perms.canViewLogs) {
    const logs = getAuditLogs();
    if (logs.length === 0) {
      auditLog.innerHTML = `<div class="notice">Nenhum log registrado.</div>`;
    } else {
      auditLog.innerHTML = logs.map((log) => `
        <div class="log-item">
          <strong>${sanitizeHTML(log.when)}</strong><br />
          usuário=${sanitizeHTML(log.user || "—")} | perfil=${sanitizeHTML(log.role || "—")} | ação=${sanitizeHTML(log.action)}<br />
          detalhe=${sanitizeHTML(log.detail)}
        </div>
      `).join("");
    }
  }
}

// --- INICIALIZAÇÃO ---

function boot() {
  if (!localStorage.getItem(STORAGE_KEYS.occurrences)) {
    localStorage.setItem(STORAGE_KEYS.occurrences, JSON.stringify(INITIAL_OCCURRENCES));
  }

  if (!localStorage.getItem(STORAGE_KEYS.audit)) {
    localStorage.setItem(STORAGE_KEYS.audit, JSON.stringify([{
      when: new Date().toISOString(),
      user: "sistema",
      role: "SISTEMA",
      action: "BASE_INICIAL_CRIADA",
      detail: "Dados fictícios carregados no localStorage."
    }]));
  }

  const session = getSession();
  if (session) {
    showApp(session);
  } else {
    showLogin();
  }
}

// --- EVENT LISTENERS ---

loginForm.addEventListener("submit", (event) => {
  event.preventDefault();
  login(
    document.querySelector("#email").value.trim(),
    document.querySelector("#password").value
  );
});

occurrenceForm.addEventListener("submit", createOccurrence);
logoutBtn.addEventListener("click", logout);
exportBtn.addEventListener("click", exportData);
clearLogsBtn.addEventListener("click", clearLogs);
resetBtn.addEventListener("click", resetData);
if (searchInput) searchInput.addEventListener("input", render);

// MELHORIA: Removido roleSelect change listener (perfil não pode ser alterado pelo usuário)

// Expor funções para onclick nos botões da tabela
window.deleteOccurrence = deleteOccurrence;
window.changeStatus = changeStatus;

// Iniciar
boot();

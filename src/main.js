import * as kdbxweb from 'kdbxweb';
import {
  createIcons,
  Shield,
  ShieldCheck,
  Lock,
  Unlock,
  Key,
  FileKey,
  Eye,
  EyeOff,
  Copy,
  Check,
  Search,
  Folder,
  FolderOpen,
  ExternalLink,
  Clock,
  Settings,
  Download,
  UploadCloud,
  RefreshCw,
  Sliders,
  Star,
  Trash2,
  AlertCircle,
  X,
  ChevronRight,
  Info,
  FileText,
  Sparkles,
  Globe,
  User,
  Terminal,
  HelpCircle,
  FileUp,
  Database
} from 'lucide';

import { initKdbxCrypto } from './crypto-init.js';
import { generateTOTP } from './totp.js';
import { evaluatePassword } from './password-meter.js';
import { generatePassword } from './generator.js';

// Register Argon2 for KDBX v4 support
initKdbxCrypto();

const ICONS = {
  Shield,
  ShieldCheck,
  Lock,
  Unlock,
  Key,
  FileKey,
  Eye,
  EyeOff,
  Copy,
  Check,
  Search,
  Folder,
  FolderOpen,
  ExternalLink,
  Clock,
  Settings,
  Download,
  UploadCloud,
  RefreshCw,
  Sliders,
  Star,
  Trash2,
  AlertCircle,
  X,
  ChevronRight,
  Info,
  FileText,
  Sparkles,
  Globe,
  User,
  Terminal,
  HelpCircle,
  FileUp,
  Database
};

// Application State
const state = {
  db: null,
  fileBuffer: null,
  fileName: '',
  fileSize: 0,
  keyFileBuffer: null,
  keyFileName: '',
  useKeyFile: false,
  masterPassword: '',
  showPasswordUnlock: false,
  isUnlocking: false,
  unlockError: '',
  selectedGroupId: 'all',
  selectedEntryId: null,
  searchQuery: '',
  sortBy: 'title-asc',
  favorites: new Set(JSON.parse(localStorage.getItem('keepass_favs') || '[]')),
  revealedPasswords: new Set(),
  autoLockMinutes: 10,
  autoLockRemainingSeconds: 600,
  lastActivity: Date.now(),
  showGeneratorModal: false,
  generatorConfig: {
    length: 20,
    uppercase: true,
    lowercase: true,
    numbers: true,
    symbols: true,
    avoidAmbiguous: true,
    generated: ''
  },
  totpTimer: null,
  activeTotpData: null
};

// DOM References
const app = document.getElementById('app');

function renderIcons() {
  createIcons({ icons: ICONS });
}

function showToast(message, type = 'success') {
  const container = document.getElementById('toast-container');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast ${type === 'success' ? 'toast-success' : 'alert-error'}`;
  toast.innerHTML = `
    <i data-lucide="${type === 'success' ? 'check' : 'alert-circle'}" style="width: 18px; height: 18px;"></i>
    <span>${escapeHtml(message)}</span>
  `;
  container.appendChild(toast);
  renderIcons();

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateY(10px)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 3200);
}

// Copy to clipboard helper with visual notification
async function copyToClipboard(text, description = 'Texto') {
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    showToast(`${description} copiado para a área de transferência!`);
  } catch (err) {
    // Fallback for clipboard
    const textarea = document.createElement('textarea');
    textarea.value = text;
    document.body.appendChild(textarea);
    textarea.select();
    document.execCommand('copy');
    textarea.remove();
    showToast(`${description} copiado para a área de transferência!`);
  }
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function formatBytes(bytes) {
  if (!bytes) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${(bytes / Math.pow(k, i)).toFixed(1)} ${sizes[i]}`;
}

function formatDate(date) {
  if (!date) return '-';
  try {
    return new Intl.DateTimeFormat('pt-BR', {
      dateStyle: 'medium',
      timeStyle: 'short'
    }).format(new Date(date));
  } catch {
    return '-';
  }
}

function getFieldValue(val) {
  if (!val) return '';
  return typeof val.getText === 'function' ? val.getText() : String(val);
}

// Extract flat entries list from group hierarchy
function extractAllEntries(group, path = '') {
  const result = [];
  const currentPath = path ? `${path} / ${group.name}` : group.name;

  if (group.entries && group.entries.length) {
    for (const entry of group.entries) {
      result.push({
        id: entry.uuid.id,
        rawEntry: entry,
        groupName: group.name,
        groupPath: currentPath,
        groupId: group.uuid.id,
        title: getFieldValue(entry.fields.get('Title')) || '(Sem título)',
        username: getFieldValue(entry.fields.get('UserName')) || '',
        password: getFieldValue(entry.fields.get('Password')) || '',
        url: getFieldValue(entry.fields.get('URL')) || '',
        notes: getFieldValue(entry.fields.get('Notes')) || '',
        created: entry.times?.creationTime,
        modified: entry.times?.lastModificationTime,
        customFields: Array.from(entry.fields.entries())
          .filter(([key]) => !['Title', 'UserName', 'Password', 'URL', 'Notes'].includes(key))
          .map(([key, value]) => ({ key, value: getFieldValue(value) })),
        totpKey: getFieldValue(entry.fields.get('otp')) ||
                 getFieldValue(entry.fields.get('TOTP Seed')) ||
                 getFieldValue(entry.fields.get('totp')) ||
                 ''
      });
    }
  }

  if (group.groups && group.groups.length) {
    for (const subGroup of group.groups) {
      result.push(...extractAllEntries(subGroup, currentPath));
    }
  }

  return result;
}

// Extract groups tree
function extractGroupsTree(group) {
  const isRecycle = group.name.toLowerCase().includes('recycle') || group.name.toLowerCase().includes('lixeira');
  return {
    id: group.uuid.id,
    name: group.name,
    isRecycle,
    entriesCount: group.entries ? group.entries.length : 0,
    children: (group.groups || []).map(g => extractGroupsTree(g))
  };
}

// ==========================================================
// UNLOCK ACTIONS
// ==========================================================
async function unlockDatabase() {
  if (!state.fileBuffer) {
    state.unlockError = 'Por favor, selecione ou arraste um arquivo de cofre (.kdbx).';
    render();
    return;
  }

  if (!state.masterPassword && !state.keyFileBuffer) {
    state.unlockError = 'Informe a senha mestra ou forneça um arquivo chave.';
    render();
    return;
  }

  state.isUnlocking = true;
  state.unlockError = '';
  render();

  try {
    let passwordVal = null;
    if (state.masterPassword) {
      passwordVal = kdbxweb.ProtectedValue.fromString(state.masterPassword);
    }

    const credentials = new kdbxweb.Credentials(passwordVal, state.keyFileBuffer || undefined);
    
    // Load KDBX database
    const db = await kdbxweb.Kdbx.load(state.fileBuffer, credentials);

    state.db = db;
    state.isUnlocking = false;
    state.masterPassword = ''; // Clear memory
    state.autoLockRemainingSeconds = state.autoLockMinutes * 60;
    state.lastActivity = Date.now();

    showToast('Cofre desbloqueado com sucesso!');
    render();
    startActivityWatcher();
  } catch (err) {
    console.error('Failed to unlock database:', err);
    state.isUnlocking = false;
    if (err && err.code === 'InvalidKey') {
      state.unlockError = 'Senha mestra ou arquivo chave incorretos.';
    } else if (err && err.code === 'FileCorrupt') {
      state.unlockError = 'Arquivo .kdbx corrompido ou formato incompatível.';
    } else {
      state.unlockError = `Erro ao abrir cofre: ${err.message || 'Chave inválida'}`;
    }
    render();
  }
}

// Load demo vault directly
async function loadDemoVault() {
  state.isUnlocking = true;
  state.unlockError = '';
  render();

  try {
    const res = await fetch('/exemplo_cofre.kdbx');
    if (!res.ok) throw new Error('Não foi possível carregar o arquivo de exemplo.');
    const arrayBuf = await res.arrayBuffer();
    
    state.fileBuffer = arrayBuf;
    state.fileName = 'exemplo_cofre.kdbx';
    state.fileSize = arrayBuf.byteLength;
    state.masterPassword = 'senha123';
    
    // Auto-unlock demo
    await unlockDatabase();
  } catch (err) {
    state.isUnlocking = false;
    state.unlockError = `Erro ao carregar cofre de teste: ${err.message}`;
    render();
  }
}

function lockVault() {
  if (state.totpTimer) {
    clearInterval(state.totpTimer);
    state.totpTimer = null;
  }
  state.db = null;
  state.masterPassword = '';
  state.revealedPasswords.clear();
  state.selectedEntryId = null;
  state.searchQuery = '';
  showToast('Cofre bloqueado.');
  render();
}

// Activity watcher for auto-lock
let activityInterval = null;
function startActivityWatcher() {
  if (activityInterval) clearInterval(activityInterval);

  const resetActivity = () => {
    state.lastActivity = Date.now();
  };

  window.addEventListener('mousemove', resetActivity, { passive: true });
  window.addEventListener('keydown', resetActivity, { passive: true });
  window.addEventListener('click', resetActivity, { passive: true });

  activityInterval = setInterval(() => {
    if (!state.db) {
      clearInterval(activityInterval);
      return;
    }
    const inactiveSeconds = Math.floor((Date.now() - state.lastActivity) / 1000);
    const totalAllowed = state.autoLockMinutes * 60;
    state.autoLockRemainingSeconds = Math.max(0, totalAllowed - inactiveSeconds);

    const timerChip = document.getElementById('lock-timer-text');
    if (timerChip) {
      const mins = Math.floor(state.autoLockRemainingSeconds / 60);
      const secs = state.autoLockRemainingSeconds % 60;
      timerChip.textContent = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
      
      const chipParent = timerChip.closest('.lock-timer-chip');
      if (chipParent) {
        if (state.autoLockRemainingSeconds <= 60) {
          chipParent.classList.add('warning');
        } else {
          chipParent.classList.remove('warning');
        }
      }
    }

    if (state.autoLockRemainingSeconds <= 0) {
      lockVault();
    }
  }, 1000);
}

// TOTP Live Refresh
function updateActiveTotp(secretKey) {
  if (state.totpTimer) {
    clearInterval(state.totpTimer);
    state.totpTimer = null;
  }

  if (!secretKey) {
    state.activeTotpData = null;
    return;
  }

  const refresh = async () => {
    const data = await generateTOTP(secretKey);
    state.activeTotpData = data;
    
    const codeEl = document.getElementById('totp-display-code');
    const timeEl = document.getElementById('totp-remaining-seconds');
    const ringEl = document.getElementById('totp-ring-fill');

    if (codeEl && data) {
      codeEl.textContent = data.formattedCode;
    }
    if (timeEl && data) {
      timeEl.textContent = `${data.remainingSeconds}s`;
    }
    if (ringEl && data) {
      const pct = (data.remainingSeconds / data.period) * 100;
      ringEl.style.width = `${pct}%`;
    }
  };

  refresh();
  state.totpTimer = setInterval(refresh, 1000);
}

// ==========================================================
// RENDER UNLOCK SCREEN
// ==========================================================
function renderUnlockScreen() {
  return `
    <header class="app-header">
      <div class="brand-section">
        <div class="brand-logo-icon">
          <i data-lucide="shield-check" style="width: 22px; height: 22px;"></i>
        </div>
        <div class="brand-title">
          <span>KeePass Web Vault</span>
          <span class="brand-badge">Seguro & Offline</span>
        </div>
      </div>
      <div class="header-actions">
        <button class="btn btn-secondary" id="btn-open-generator-top">
          <i data-lucide="sparkles" style="width: 16px; height: 16px;"></i>
          <span>Gerador de Senhas</span>
        </button>
      </div>
    </header>

    <div class="unlock-wrapper">
      <div class="unlock-card glass-panel">
        <div class="unlock-header">
          <div class="unlock-icon-shield">
            <i data-lucide="shield" style="width: 32px; height: 32px;"></i>
          </div>
          <h1 class="unlock-title">Desbloquear Cofre</h1>
          <p class="unlock-subtitle">Seus dados nunca saem deste dispositivo. Descriptografia 100% no navegador.</p>
        </div>

        <!-- Quick Demo Banner -->
        <div class="demo-banner">
          <div class="demo-banner-text">
            <strong>Dica rápida:</strong> Quer testar sem ter um cofre em mãos?
          </div>
          <button class="btn btn-demo" id="btn-load-demo">
            <i data-lucide="sparkles" style="width: 14px; height: 14px;"></i>
            <span>Testar Exemplo</span>
          </button>
        </div>

        ${state.unlockError ? `
          <div class="alert-error">
            <i data-lucide="alert-circle" style="width: 18px; height: 18px; flex-shrink: 0;"></i>
            <div>${escapeHtml(state.unlockError)}</div>
          </div>
        ` : ''}

        <!-- Dropzone or loaded file chip -->
        ${state.fileName ? `
          <div class="file-loaded-chip">
            <div class="file-loaded-info">
              <i data-lucide="database" style="color: var(--accent-cyan); width: 22px; height: 22px;"></i>
              <div>
                <div class="file-loaded-name">${escapeHtml(state.fileName)}</div>
                <div class="file-loaded-size">${formatBytes(state.fileSize)} • Pronto para descriptografar</div>
              </div>
            </div>
            <button class="btn-icon" id="btn-remove-file" title="Trocar arquivo">
              <i data-lucide="x" style="width: 16px; height: 16px;"></i>
            </button>
          </div>
        ` : `
          <div class="dropzone" id="kdbx-dropzone">
            <input type="file" id="kdbx-file-input" accept=".kdbx" style="display: none;" />
            <div class="dropzone-icon">
              <i data-lucide="upload-cloud" style="width: 36px; height: 36px;"></i>
            </div>
            <div class="dropzone-title">Arraste seu arquivo .kdbx aqui</div>
            <div class="dropzone-hint">ou clique para selecionar do computador</div>
          </div>
        `}

        <form id="unlock-form">
          <!-- Password Input -->
          <div class="form-group">
            <label class="form-label" for="master-password-input">Senha Mestra</label>
            <div class="input-password-wrapper">
              <input
                type="${state.showPasswordUnlock ? 'text' : 'password'}"
                id="master-password-input"
                class="form-input"
                placeholder="Digite a senha mestra do cofre..."
                value="${escapeHtml(state.masterPassword)}"
                autocomplete="current-password"
                ${state.isUnlocking ? 'disabled' : ''}
              />
              <button type="button" class="input-icon-btn" id="btn-toggle-unlock-pwd">
                <i data-lucide="${state.showPasswordUnlock ? 'eye-off' : 'eye'}" style="width: 18px; height: 18px;"></i>
              </button>
            </div>
            <div id="caps-lock-warning" class="caps-warning" style="display: none;">
              <i data-lucide="alert-circle" style="width: 14px; height: 14px;"></i>
              <span>Caps Lock ativado</span>
            </div>
          </div>

          <!-- Key file toggle -->
          <div class="keyfile-toggle-row">
            <label class="keyfile-checkbox-label">
              <input type="checkbox" id="checkbox-use-keyfile" ${state.useKeyFile ? 'checked' : ''} />
              <span>Usar arquivo de chave (.key)</span>
            </label>
          </div>

          ${state.useKeyFile ? `
            <div class="form-group" style="margin-top: -0.5rem; margin-bottom: 1.5rem;">
              <label class="form-label">Arquivo de Chave</label>
              <div style="display: flex; gap: 0.5rem;">
                <input type="file" id="key-file-input" style="display: none;" />
                <button type="button" class="btn btn-secondary" id="btn-pick-keyfile" style="flex: 1;">
                  <i data-lucide="file-key" style="width: 16px; height: 16px;"></i>
                  <span>${state.keyFileName ? escapeHtml(state.keyFileName) : 'Selecionar arquivo chave...'}</span>
                </button>
                ${state.keyFileName ? `
                  <button type="button" class="btn-icon" id="btn-remove-keyfile">
                    <i data-lucide="x" style="width: 16px; height: 16px;"></i>
                  </button>
                ` : ''}
              </div>
            </div>
          ` : ''}

          <button
            type="submit"
            class="btn btn-primary"
            style="width: 100%; padding: 0.85rem;"
            ${state.isUnlocking ? 'disabled' : ''}
          >
            ${state.isUnlocking ? `
              <div class="spinner"></div>
              <span>Descriptografando cofre...</span>
            ` : `
              <i data-lucide="unlock" style="width: 18px; height: 18px;"></i>
              <span>Desbloquear Cofre</span>
            `}
          </button>
        </form>

        <div class="security-footer">
          <i data-lucide="shield-check" style="width: 14px; height: 14px; color: var(--accent-emerald);"></i>
          <span>Compatível com KeePass 2.x, KeePassXC, Argon2 & AES-KDF</span>
        </div>
      </div>
    </div>
  `;
}

// ==========================================================
// RENDER MAIN VAULT DASHBOARD
// ==========================================================
function renderVaultDashboard() {
  const root = state.db.getDefaultGroup();
  const allEntries = extractAllEntries(root);
  const groupsTree = extractGroupsTree(root);

  // Filter entries
  let filteredEntries = allEntries;

  // Filter by group or favorites
  if (state.selectedGroupId === 'favorites') {
    filteredEntries = filteredEntries.filter(e => state.favorites.has(e.id));
  } else if (state.selectedGroupId !== 'all') {
    filteredEntries = filteredEntries.filter(e => e.groupId === state.selectedGroupId);
  }

  // Filter by search query
  if (state.searchQuery.trim()) {
    const q = state.searchQuery.toLowerCase();
    filteredEntries = filteredEntries.filter(e =>
      e.title.toLowerCase().includes(q) ||
      e.username.toLowerCase().includes(q) ||
      e.url.toLowerCase().includes(q) ||
      e.notes.toLowerCase().includes(q) ||
      e.groupName.toLowerCase().includes(q)
    );
  }

  // Sort entries
  filteredEntries.sort((a, b) => {
    if (state.sortBy === 'title-asc') return a.title.localeCompare(b.title);
    if (state.sortBy === 'title-desc') return b.title.localeCompare(a.title);
    if (state.sortBy === 'user') return a.username.localeCompare(b.username);
    if (state.sortBy === 'modified') {
      const tA = a.modified ? new Date(a.modified).getTime() : 0;
      const tB = b.modified ? new Date(b.modified).getTime() : 0;
      return tB - tA;
    }
    return 0;
  });

  const selectedEntry = allEntries.find(e => e.id === state.selectedEntryId) || null;
  const dbName = state.db.meta?.name || state.fileName || 'Meu Cofre KeePass';

  const mins = Math.floor(state.autoLockRemainingSeconds / 60);
  const secs = state.autoLockRemainingSeconds % 60;
  const timerStr = `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;

  return `
    <header class="app-header">
      <div class="brand-section">
        <div class="brand-logo-icon">
          <i data-lucide="shield-check" style="width: 22px; height: 22px;"></i>
        </div>
        <div class="brand-title">
          <span>${escapeHtml(dbName)}</span>
          <span class="brand-badge">${state.db.header.version ? `KDBX ${state.db.header.version.major}` : 'KDBX'}</span>
        </div>
      </div>

      <div class="header-center">
        <div class="search-container">
          <i data-lucide="search" class="search-icon-left" style="width: 16px; height: 16px;"></i>
          <input
            type="text"
            class="search-input"
            id="global-search-input"
            placeholder="Pesquisar senhas, logins, sites, notas (Ctrl + K)..."
            value="${escapeHtml(state.searchQuery)}"
          />
          <div class="search-kbd-hint">Ctrl K</div>
        </div>
      </div>

      <div class="header-actions">
        <div class="lock-timer-chip" title="Tempo restante antes do bloqueio automático">
          <i data-lucide="clock" style="width: 14px; height: 14px;"></i>
          <span id="lock-timer-text">${timerStr}</span>
        </div>

        <button class="btn btn-secondary" id="btn-open-generator">
          <i data-lucide="sparkles" style="width: 16px; height: 16px;"></i>
          <span>Gerador</span>
        </button>

        <button class="btn btn-secondary" id="btn-open-export">
          <i data-lucide="download" style="width: 16px; height: 16px;"></i>
          <span>Exportar</span>
        </button>

        <button class="btn btn-danger" id="btn-lock-vault">
          <i data-lucide="lock" style="width: 16px; height: 16px;"></i>
          <span>Bloquear</span>
        </button>
      </div>
    </header>

    <div class="app-layout">
      <!-- SIDEBAR -->
      <aside class="sidebar">
        <div>
          <div class="sidebar-section-title">Navegação</div>
          <div class="nav-item ${state.selectedGroupId === 'all' ? 'active' : ''}" data-group-id="all">
            <div class="nav-item-left">
              <i data-lucide="database" style="width: 18px; height: 18px;"></i>
              <span>Todas as Entradas</span>
            </div>
            <span class="nav-badge">${allEntries.length}</span>
          </div>

          <div class="nav-item ${state.selectedGroupId === 'favorites' ? 'active' : ''}" data-group-id="favorites">
            <div class="nav-item-left">
              <i data-lucide="star" style="width: 18px; height: 18px; color: ${state.favorites.size > 0 ? 'var(--accent-amber)' : 'inherit'};"></i>
              <span>Favoritos</span>
            </div>
            <span class="nav-badge">${state.favorites.size}</span>
          </div>

          <div class="sidebar-section-title" style="margin-top: 1.5rem;">Grupos & Pastas</div>
          <div class="group-tree">
            ${renderGroupsNav([groupsTree], state.selectedGroupId)}
          </div>
        </div>

        <div class="sidebar-footer">
          <div style="font-size: 0.75rem; color: var(--text-muted); display: flex; align-items: center; justify-content: space-between; padding: 0 0.5rem;">
            <span>${allEntries.length} credenciais no total</span>
            <span>AES-256</span>
          </div>
        </div>
      </aside>

      <!-- MAIN CONTENT -->
      <main class="main-content">
        <div class="content-header">
          <div class="content-title-area">
            <div class="content-title">
              <i data-lucide="${state.selectedGroupId === 'favorites' ? 'star' : 'folder-open'}" style="width: 20px; height: 20px; color: var(--accent-cyan);"></i>
              <span>${getGroupTitle(state.selectedGroupId, groupsTree)}</span>
            </div>
            <div class="content-subtitle">
              Mostrando ${filteredEntries.length} de ${allEntries.length} itens ${state.searchQuery ? `para "${escapeHtml(state.searchQuery)}"` : ''}
            </div>
          </div>

          <div class="content-controls">
            <select class="sort-select" id="sort-select">
              <option value="title-asc" ${state.sortBy === 'title-asc' ? 'selected' : ''}>Título (A - Z)</option>
              <option value="title-desc" ${state.sortBy === 'title-desc' ? 'selected' : ''}>Título (Z - A)</option>
              <option value="user" ${state.sortBy === 'user' ? 'selected' : ''}>Usuário</option>
              <option value="modified" ${state.sortBy === 'modified' ? 'selected' : ''}>Última Modificação</option>
            </select>
          </div>
        </div>

        <!-- Entries List / Grid -->
        <div class="entries-container">
          ${filteredEntries.length === 0 ? `
            <div class="empty-state">
              <div class="empty-state-icon">
                <i data-lucide="search" style="width: 28px; height: 28px;"></i>
              </div>
              <div>
                <h3 style="font-size: 1.1rem; color: var(--text-primary); margin-bottom: 0.25rem;">Nenhuma senha encontrada</h3>
                <p>Tente ajustar sua busca ou selecione outro grupo na barra lateral.</p>
              </div>
            </div>
          ` : `
            <div class="entries-grid">
              ${filteredEntries.map(entry => renderEntryCard(entry)).join('')}
            </div>
          `}
        </div>
      </main>

      <!-- DETAIL DRAWER -->
      <aside class="detail-drawer ${selectedEntry ? 'open' : ''}" id="detail-drawer">
        ${selectedEntry ? renderEntryDetail(selectedEntry) : ''}
      </aside>
    </div>
  `;
}

function getGroupTitle(groupId, tree) {
  if (groupId === 'all') return 'Todas as Entradas';
  if (groupId === 'favorites') return 'Senhas Favoritas';
  
  function findName(node) {
    if (node.id === groupId) return node.name;
    for (const child of node.children) {
      const found = findName(child);
      if (found) return found;
    }
    return null;
  }
  return findName(tree) || 'Grupo';
}

function renderGroupsNav(nodes, selectedId, level = 0) {
  return nodes.map(node => `
    <div
      class="nav-item ${selectedId === node.id ? 'active' : ''} ${level > 0 ? 'group-item-nested' : ''}"
      data-group-id="${escapeHtml(node.id)}"
      style="padding-left: ${0.85 + level * 0.85}rem;"
    >
      <div class="nav-item-left">
        <i data-lucide="${node.isRecycle ? 'trash-2' : (selectedId === node.id ? 'folder-open' : 'folder')}" style="width: 16px; height: 16px;"></i>
        <span>${escapeHtml(node.name)}</span>
      </div>
      <span class="nav-badge">${node.entriesCount}</span>
    </div>
    ${node.children.length ? renderGroupsNav(node.children, selectedId, level + 1) : ''}
  `).join('');
}

function renderEntryCard(entry) {
  const isFav = state.favorites.has(entry.id);
  const isSelected = state.selectedEntryId === entry.id;
  const isRevealed = state.revealedPasswords.has(entry.id);

  let domain = '';
  if (entry.url) {
    try {
      const u = new URL(entry.url.startsWith('http') ? entry.url : `https://${entry.url}`);
      domain = u.hostname;
    } catch {
      domain = entry.url;
    }
  }

  return `
    <div class="entry-card ${isSelected ? 'selected' : ''}" data-entry-id="${entry.id}">
      <div class="entry-card-header">
        <div class="entry-header-left">
          <div class="entry-icon-box">
            <i data-lucide="${entry.totpKey ? 'shield-check' : 'key'}" style="width: 18px; height: 18px;"></i>
          </div>
          <div>
            <div class="entry-title">${escapeHtml(entry.title)}</div>
            <div class="entry-group-name">${escapeHtml(entry.groupName)} ${domain ? `• ${escapeHtml(domain)}` : ''}</div>
          </div>
        </div>

        <button class="btn-icon entry-favorite-btn ${isFav ? 'active' : ''}" data-action="toggle-fav" data-entry-id="${entry.id}" title="${isFav ? 'Remover dos favoritos' : 'Adicionar aos favoritos'}">
          <i data-lucide="star" style="width: 16px; height: 16px; ${isFav ? 'fill: currentColor;' : ''}"></i>
        </button>
      </div>

      <div class="entry-card-body">
        ${entry.username ? `
          <div class="entry-row">
            <i data-lucide="user" style="width: 14px; height: 14px; color: var(--text-muted);"></i>
            <span class="entry-row-value">${escapeHtml(entry.username)}</span>
          </div>
        ` : ''}

        <div class="entry-row">
          <i data-lucide="lock" style="width: 14px; height: 14px; color: var(--text-muted);"></i>
          <span class="entry-row-value">${isRevealed ? escapeHtml(entry.password) : '••••••••••••'}</span>
        </div>
      </div>

      <div class="entry-card-actions">
        ${entry.username ? `
          <button class="btn-icon" data-action="copy-user" data-entry-id="${entry.id}" title="Copiar Usuário">
            <i data-lucide="user" style="width: 14px; height: 14px;"></i>
          </button>
        ` : ''}

        <button class="btn-icon" data-action="toggle-reveal-card" data-entry-id="${entry.id}" title="${isRevealed ? 'Ocultar Senha' : 'Ver Senha'}">
          <i data-lucide="${isRevealed ? 'eye-off' : 'eye'}" style="width: 14px; height: 14px;"></i>
        </button>

        <button class="btn-icon" data-action="copy-pwd" data-entry-id="${entry.id}" title="Copiar Senha">
          <i data-lucide="copy" style="width: 14px; height: 14px;"></i>
        </button>

        <button class="btn-icon" data-action="view-detail" data-entry-id="${entry.id}" title="Ver Detalhes">
          <i data-lucide="chevron-right" style="width: 16px; height: 16px;"></i>
        </button>
      </div>
    </div>
  `;
}

function renderEntryDetail(entry) {
  const isFav = state.favorites.has(entry.id);
  const isRevealed = state.revealedPasswords.has(entry.id);
  const strength = evaluatePassword(entry.password);

  return `
    <div class="drawer-header">
      <div class="drawer-title-box">
        <div class="entry-icon-box">
          <i data-lucide="key" style="width: 20px; height: 20px;"></i>
        </div>
        <div>
          <h2 style="font-size: 1.15rem; font-weight: 700;">${escapeHtml(entry.title)}</h2>
          <div style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(entry.groupPath)}</div>
        </div>
      </div>
      <div style="display: flex; gap: 0.4rem;">
        <button class="btn-icon entry-favorite-btn ${isFav ? 'active' : ''}" data-action="toggle-fav" data-entry-id="${entry.id}">
          <i data-lucide="star" style="width: 16px; height: 16px; ${isFav ? 'fill: currentColor;' : ''}"></i>
        </button>
        <button class="btn-icon" id="btn-close-drawer">
          <i data-lucide="x" style="width: 18px; height: 18px;"></i>
        </button>
      </div>
    </div>

    <div class="drawer-content">
      <!-- Username -->
      <div class="detail-field">
        <label class="detail-field-label">Usuário / Login</label>
        <div class="detail-field-box">
          <span class="detail-mono-val">${escapeHtml(entry.username) || '<span style="color: var(--text-muted);">(Não informado)</span>'}</span>
          ${entry.username ? `
            <div class="detail-field-actions">
              <button class="btn-icon" data-action="copy-user" data-entry-id="${entry.id}" title="Copiar Usuário">
                <i data-lucide="copy" style="width: 16px; height: 16px;"></i>
              </button>
            </div>
          ` : ''}
        </div>
      </div>

      <!-- Password -->
      <div class="detail-field">
        <div class="detail-field-label">
          <span>Senha</span>
          <span style="color: ${strength.color}; font-weight: 600;">${strength.label} (${strength.entropy} bits)</span>
        </div>
        <div class="detail-field-box">
          <span class="detail-mono-val">${isRevealed ? escapeHtml(entry.password) : '••••••••••••••••'}</span>
          <div class="detail-field-actions">
            <button class="btn-icon" data-action="toggle-reveal-card" data-entry-id="${entry.id}" title="${isRevealed ? 'Ocultar Senha' : 'Ver Senha'}">
              <i data-lucide="${isRevealed ? 'eye-off' : 'eye'}" style="width: 16px; height: 16px;"></i>
            </button>
            <button class="btn-icon" data-action="copy-pwd" data-entry-id="${entry.id}" title="Copiar Senha">
              <i data-lucide="copy" style="width: 16px; height: 16px;"></i>
            </button>
          </div>
        </div>

        <!-- Strength bar -->
        <div class="strength-bar-container">
          <div class="strength-step" style="background-color: ${strength.score >= 1 ? strength.color : 'transparent'};"></div>
          <div class="strength-step" style="background-color: ${strength.score >= 2 ? strength.color : 'transparent'};"></div>
          <div class="strength-step" style="background-color: ${strength.score >= 3 ? strength.color : 'transparent'};"></div>
          <div class="strength-step" style="background-color: ${strength.score >= 4 ? strength.color : 'transparent'};"></div>
        </div>
        <div class="strength-info">
          <span>Comprimento: ${strength.length} caracteres</span>
          <span>${strength.hasUpper ? 'A-Z ' : ''}${strength.hasLower ? 'a-z ' : ''}${strength.hasNumber ? '0-9 ' : ''}${strength.hasSymbol ? '#$&' : ''}</span>
        </div>
      </div>

      <!-- TOTP / 2FA -->
      ${entry.totpKey ? `
        <div class="detail-field">
          <div class="detail-field-label">
            <span>Autenticação 2 Fatores (TOTP)</span>
            <span id="totp-remaining-seconds" style="color: var(--accent-cyan); font-weight: 600;">30s</span>
          </div>
          <div class="totp-box">
            <div id="totp-display-code" class="totp-code">--- ---</div>
            <div style="display: flex; align-items: center; gap: 0.5rem;">
              <button class="btn-icon" id="btn-copy-totp" title="Copiar Código 2FA">
                <i data-lucide="copy" style="width: 16px; height: 16px;"></i>
              </button>
            </div>
          </div>
          <div style="height: 3px; background: rgba(255,255,255,0.1); border-radius: 4px; overflow: hidden; margin-top: 0.4rem;">
            <div id="totp-ring-fill" style="height: 100%; width: 100%; background: var(--accent-cyan); transition: width 1s linear;"></div>
          </div>
        </div>
      ` : ''}

      <!-- URL -->
      ${entry.url ? `
        <div class="detail-field">
          <label class="detail-field-label">URL / Website</label>
          <div class="detail-field-box">
            <span class="detail-mono-val" style="font-size: 0.85rem;">${escapeHtml(entry.url)}</span>
            <div class="detail-field-actions">
              <a href="${escapeHtml(entry.url.startsWith('http') ? entry.url : `https://${entry.url}`)}" target="_blank" rel="noopener noreferrer" class="btn-icon" title="Abrir link seguro">
                <i data-lucide="external-link" style="width: 16px; height: 16px;"></i>
              </a>
              <button class="btn-icon" data-action="copy-text" data-text="${escapeHtml(entry.url)}" data-desc="URL" title="Copiar URL">
                <i data-lucide="copy" style="width: 16px; height: 16px;"></i>
              </button>
            </div>
          </div>
        </div>
      ` : ''}

      <!-- Notes -->
      ${entry.notes ? `
        <div class="detail-field">
          <div class="detail-field-label">
            <span>Observações / Notas</span>
            <button class="btn-icon" style="width: 24px; height: 24px;" data-action="copy-text" data-text="${escapeHtml(entry.notes)}" data-desc="Notas" title="Copiar Notas">
              <i data-lucide="copy" style="width: 12px; height: 12px;"></i>
            </button>
          </div>
          <div class="notes-container">${escapeHtml(entry.notes)}</div>
        </div>
      ` : ''}

      <!-- Custom Fields -->
      ${entry.customFields && entry.customFields.length ? `
        <div class="detail-field">
          <label class="detail-field-label">Campos Personalizados</label>
          <div style="display: flex; flex-direction: column; gap: 0.5rem;">
            ${entry.customFields.map(f => `
              <div class="detail-field-box">
                <div style="display: flex; flex-direction: column;">
                  <span style="font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(f.key)}</span>
                  <span class="detail-mono-val" style="font-size: 0.85rem;">${escapeHtml(f.value)}</span>
                </div>
                <button class="btn-icon" data-action="copy-text" data-text="${escapeHtml(f.value)}" data-desc="${escapeHtml(f.key)}" title="Copiar campo">
                  <i data-lucide="copy" style="width: 14px; height: 14px;"></i>
                </button>
              </div>
            `).join('')}
          </div>
        </div>
      ` : ''}

      <!-- Metadata -->
      <div style="margin-top: 1rem; padding-top: 1rem; border-top: 1px solid var(--border-subtle); display: flex; flex-direction: column; gap: 0.35rem; font-size: 0.75rem; color: var(--text-muted);">
        <div>Criado em: ${formatDate(entry.created)}</div>
        <div>Modificado em: ${formatDate(entry.modified)}</div>
      </div>
    </div>
  `;
}

// ==========================================================
// RENDER MODALS
// ==========================================================
function renderModals() {
  if (!state.generatorConfig.generated) {
    state.generatorConfig.generated = generatePassword(state.generatorConfig);
  }

  const pwd = state.generatorConfig.generated;
  const strength = evaluatePassword(pwd);

  return `
    <!-- Generator Modal -->
    <div class="modal-overlay ${state.showGeneratorModal ? 'open' : ''}" id="generator-modal">
      <div class="modal-card">
        <div class="modal-header">
          <div class="modal-title">
            <i data-lucide="sparkles" style="width: 20px; height: 20px; color: var(--accent-cyan);"></i>
            <span>Gerador de Senhas Seguras</span>
          </div>
          <button class="btn-icon" id="btn-close-generator">
            <i data-lucide="x" style="width: 18px; height: 18px;"></i>
          </button>
        </div>

        <div class="modal-body">
          <div class="generator-result">
            <span>${escapeHtml(pwd)}</span>
            <div style="display: flex; gap: 0.4rem;">
              <button class="btn-icon" id="btn-regen-pwd" title="Gerar nova senha">
                <i data-lucide="refresh-cw" style="width: 16px; height: 16px;"></i>
              </button>
              <button class="btn-icon" id="btn-copy-generated" title="Copiar Senha">
                <i data-lucide="copy" style="width: 16px; height: 16px;"></i>
              </button>
            </div>
          </div>

          <!-- Password strength in modal -->
          <div style="margin-bottom: 1.25rem;">
            <div class="strength-bar-container">
              <div class="strength-step" style="background-color: ${strength.score >= 1 ? strength.color : 'transparent'};"></div>
              <div class="strength-step" style="background-color: ${strength.score >= 2 ? strength.color : 'transparent'};"></div>
              <div class="strength-step" style="background-color: ${strength.score >= 3 ? strength.color : 'transparent'};"></div>
              <div class="strength-step" style="background-color: ${strength.score >= 4 ? strength.color : 'transparent'};"></div>
            </div>
            <div class="strength-info">
              <span style="color: ${strength.color}; font-weight: 600;">${strength.label} (${strength.entropy} bits de entropia)</span>
              <span>${state.generatorConfig.length} caracteres</span>
            </div>
          </div>

          <div class="slider-row">
            <label class="form-label" style="margin-bottom: 0;">Comprimento da Senha</label>
            <span style="font-family: var(--font-mono); font-weight: 700; color: var(--accent-cyan);" id="slider-len-val">${state.generatorConfig.length}</span>
          </div>
          <input
            type="range"
            min="8"
            max="64"
            value="${state.generatorConfig.length}"
            class="range-slider"
            id="generator-len-slider"
          />

          <div class="checkbox-grid">
            <label class="checkbox-item">
              <input type="checkbox" id="gen-opt-upper" ${state.generatorConfig.uppercase ? 'checked' : ''} />
              <span>Maiúsculas (A-Z)</span>
            </label>
            <label class="checkbox-item">
              <input type="checkbox" id="gen-opt-lower" ${state.generatorConfig.lowercase ? 'checked' : ''} />
              <span>Minúsculas (a-z)</span>
            </label>
            <label class="checkbox-item">
              <input type="checkbox" id="gen-opt-num" ${state.generatorConfig.numbers ? 'checked' : ''} />
              <span>Números (0-9)</span>
            </label>
            <label class="checkbox-item">
              <input type="checkbox" id="gen-opt-sym" ${state.generatorConfig.symbols ? 'checked' : ''} />
              <span>Símbolos (!@#$)</span>
            </label>
            <label class="checkbox-item" style="grid-column: span 2;">
              <input type="checkbox" id="gen-opt-ambig" ${state.generatorConfig.avoidAmbiguous ? 'checked' : ''} />
              <span>Evitar caracteres ambíguos (l, 1, O, 0)</span>
            </label>
          </div>
        </div>

        <div class="modal-footer">
          <button class="btn btn-secondary" id="btn-close-generator-footer">Fechar</button>
          <button class="btn btn-primary" id="btn-copy-and-close-gen">
            <i data-lucide="check" style="width: 16px; height: 16px;"></i>
            <span>Copiar e Fechar</span>
          </button>
        </div>
      </div>
    </div>

    <!-- Export Modal -->
    <div class="modal-overlay ${state.showExportModal ? 'open' : ''}" id="export-modal">
      <div class="modal-card">
        <div class="modal-header">
          <div class="modal-title">
            <i data-lucide="download" style="width: 20px; height: 20px; color: var(--accent-cyan);"></i>
            <span>Exportar Credenciais</span>
          </div>
          <button class="btn-icon" id="btn-close-export">
            <i data-lucide="x" style="width: 18px; height: 18px;"></i>
          </button>
        </div>

        <div class="modal-body">
          <div class="alert-error" style="background: rgba(245, 158, 11, 0.15); border-color: rgba(245, 158, 11, 0.35); color: #fef3c7; margin-bottom: 1.25rem;">
            <i data-lucide="alert-circle" style="width: 20px; height: 20px; flex-shrink: 0; color: var(--accent-amber);"></i>
            <div>
              <strong>Atenção de Segurança:</strong> O arquivo exportado conterá suas senhas em texto puro desprotegido. Armazene-o em local seguro ou delete após o uso.
            </div>
          </div>

          <p style="font-size: 0.9rem; color: var(--text-secondary); margin-bottom: 1.5rem;">
            Escolha o formato desejado para salvar todas as credenciais do cofre:
          </p>

          <div style="display: flex; gap: 1rem;">
            <button class="btn btn-secondary" id="btn-export-csv" style="flex: 1; padding: 1rem; flex-direction: column; gap: 0.5rem;">
              <i data-lucide="file-text" style="width: 28px; height: 28px; color: var(--accent-emerald);"></i>
              <span style="font-weight: 600;">Planilha (CSV)</span>
              <span style="font-size: 0.75rem; color: var(--text-muted);">Compatível com Excel, Bitwarden, etc.</span>
            </button>

            <button class="btn btn-secondary" id="btn-export-json" style="flex: 1; padding: 1rem; flex-direction: column; gap: 0.5rem;">
              <i data-lucide="database" style="width: 28px; height: 28px; color: var(--accent-cyan);"></i>
              <span style="font-weight: 600;">Arquivo JSON</span>
              <span style="font-size: 0.75rem; color: var(--text-muted);">Estrutura completa com grupos</span>
            </button>
          </div>
        </div>

        <div class="modal-footer">
          <button class="btn btn-secondary" id="btn-close-export-footer">Cancelar</button>
        </div>
      </div>
    </div>
  `;
}

// Export CSV / JSON implementation
function exportAsCsv() {
  if (!state.db) return;
  const entries = extractAllEntries(state.db.getDefaultGroup());
  
  const headers = ['Grupo', 'Título', 'Usuário', 'Senha', 'URL', 'Notas'];
  const rows = entries.map(e => [
    `"${(e.groupPath || '').replace(/"/g, '""')}"`,
    `"${(e.title || '').replace(/"/g, '""')}"`,
    `"${(e.username || '').replace(/"/g, '""')}"`,
    `"${(e.password || '').replace(/"/g, '""')}"`,
    `"${(e.url || '').replace(/"/g, '""')}"`,
    `"${(e.notes || '').replace(/"/g, '""')}"`
  ]);

  const csvContent = '\uFEFF' + [headers.join(','), ...rows.map(r => r.join(','))].join('\r\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  downloadBlob(blob, 'keepass_export.csv');
  showToast('Exportação CSV concluída com sucesso!');
  state.showExportModal = false;
  render();
}

function exportAsJson() {
  if (!state.db) return;
  const entries = extractAllEntries(state.db.getDefaultGroup());
  const data = entries.map(e => ({
    group: e.groupPath,
    title: e.title,
    username: e.username,
    password: e.password,
    url: e.url,
    notes: e.notes,
    customFields: e.customFields
  }));

  const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
  downloadBlob(blob, 'keepass_export.json');
  showToast('Exportação JSON concluída com sucesso!');
  state.showExportModal = false;
  render();
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
}

// ==========================================================
// MAIN RENDER & EVENT BINDINGS
// ==========================================================
function render() {
  if (!state.db) {
    app.innerHTML = renderUnlockScreen() + renderModals();
  } else {
    app.innerHTML = renderVaultDashboard() + renderModals();
  }
  renderIcons();
  bindEvents();
}

function bindEvents() {
  // Global keyboard shortcuts
  window.onkeydown = (e) => {
    // Ctrl + K or Ctrl + F to focus search
    if ((e.ctrlKey || e.metaKey) && (e.key === 'k' || e.key === 'f')) {
      const searchInput = document.getElementById('global-search-input');
      if (searchInput) {
        e.preventDefault();
        searchInput.focus();
        searchInput.select();
      }
    }
    // Escape to close drawers and modals
    if (e.key === 'Escape') {
      if (state.showGeneratorModal) {
        state.showGeneratorModal = false;
        render();
      } else if (state.showExportModal) {
        state.showExportModal = false;
        render();
      } else if (state.selectedEntryId) {
        state.selectedEntryId = null;
        render();
      }
    }
  };

  // UNLOCK SCREEN EVENTS
  const dropzone = document.getElementById('kdbx-dropzone');
  const fileInput = document.getElementById('kdbx-file-input');
  
  if (dropzone && fileInput) {
    dropzone.onclick = () => fileInput.click();
    fileInput.onchange = (e) => {
      const file = e.target.files[0];
      if (file) handleKdbxFile(file);
    };

    dropzone.ondragover = (e) => {
      e.preventDefault();
      dropzone.classList.add('drag-active');
    };
    dropzone.ondragleave = () => {
      dropzone.classList.remove('drag-active');
    };
    dropzone.ondrop = (e) => {
      e.preventDefault();
      dropzone.classList.remove('drag-active');
      const file = e.dataTransfer.files[0];
      if (file) handleKdbxFile(file);
    };
  }

  const btnRemoveFile = document.getElementById('btn-remove-file');
  if (btnRemoveFile) {
    btnRemoveFile.onclick = () => {
      state.fileBuffer = null;
      state.fileName = '';
      state.fileSize = 0;
      state.unlockError = '';
      render();
    };
  }

  const btnLoadDemo = document.getElementById('btn-load-demo');
  if (btnLoadDemo) {
    btnLoadDemo.onclick = () => loadDemoVault();
  }

  const pwdInput = document.getElementById('master-password-input');
  const capsWarning = document.getElementById('caps-lock-warning');
  if (pwdInput) {
    pwdInput.oninput = (e) => {
      state.masterPassword = e.target.value;
    };
    pwdInput.onkeyup = (e) => {
      if (capsWarning) {
        capsWarning.style.display = e.getModifierState('CapsLock') ? 'flex' : 'none';
      }
    };
  }

  const btnTogglePwd = document.getElementById('btn-toggle-unlock-pwd');
  if (btnTogglePwd) {
    btnTogglePwd.onclick = () => {
      state.showPasswordUnlock = !state.showPasswordUnlock;
      render();
      const input = document.getElementById('master-password-input');
      if (input) input.focus();
    };
  }

  const chkUseKeyfile = document.getElementById('checkbox-use-keyfile');
  if (chkUseKeyfile) {
    chkUseKeyfile.onchange = (e) => {
      state.useKeyFile = e.target.checked;
      render();
    };
  }

  const btnPickKeyfile = document.getElementById('btn-pick-keyfile');
  const keyFileInput = document.getElementById('key-file-input');
  if (btnPickKeyfile && keyFileInput) {
    btnPickKeyfile.onclick = () => keyFileInput.click();
    keyFileInput.onchange = async (e) => {
      const file = e.target.files[0];
      if (file) {
        state.keyFileName = file.name;
        state.keyFileBuffer = await file.arrayBuffer();
        render();
      }
    };
  }

  const btnRemoveKeyfile = document.getElementById('btn-remove-keyfile');
  if (btnRemoveKeyfile) {
    btnRemoveKeyfile.onclick = () => {
      state.keyFileName = '';
      state.keyFileBuffer = null;
      render();
    };
  }

  const unlockForm = document.getElementById('unlock-form');
  if (unlockForm) {
    unlockForm.onsubmit = (e) => {
      e.preventDefault();
      unlockDatabase();
    };
  }

  // DASHBOARD EVENTS
  const searchInput = document.getElementById('global-search-input');
  if (searchInput) {
    searchInput.oninput = (e) => {
      state.searchQuery = e.target.value;
      render();
      const input = document.getElementById('global-search-input');
      if (input) {
        input.focus();
        input.selectionStart = input.selectionEnd = input.value.length;
      }
    };
  }

  const sortSelect = document.getElementById('sort-select');
  if (sortSelect) {
    sortSelect.onchange = (e) => {
      state.sortBy = e.target.value;
      render();
    };
  }

  const btnLockVault = document.getElementById('btn-lock-vault');
  if (btnLockVault) {
    btnLockVault.onclick = () => lockVault();
  }

  // Sidebar Group clicks
  const navItems = document.querySelectorAll('.nav-item[data-group-id]');
  navItems.forEach(item => {
    item.onclick = () => {
      state.selectedGroupId = item.getAttribute('data-group-id');
      render();
    };
  });

  // Entry card interactions
  const entryCards = document.querySelectorAll('.entry-card[data-entry-id]');
  entryCards.forEach(card => {
    card.onclick = (e) => {
      // Ignore if clicking a button inside the card
      if (e.target.closest('button')) return;
      const id = card.getAttribute('data-entry-id');
      state.selectedEntryId = (state.selectedEntryId === id) ? null : id;
      render();

      if (state.selectedEntryId) {
        const allEntries = extractAllEntries(state.db.getDefaultGroup());
        const selected = allEntries.find(entry => entry.id === state.selectedEntryId);
        if (selected && selected.totpKey) {
          updateActiveTotp(selected.totpKey);
        }
      }
    };
  });

  // Action Buttons
  document.querySelectorAll('[data-action]').forEach(btn => {
    btn.onclick = (e) => {
      e.stopPropagation();
      const action = btn.getAttribute('data-action');
      const entryId = btn.getAttribute('data-entry-id');
      const allEntries = state.db ? extractAllEntries(state.db.getDefaultGroup()) : [];
      const entry = allEntries.find(en => en.id === entryId);

      if (action === 'toggle-fav') {
        if (state.favorites.has(entryId)) {
          state.favorites.delete(entryId);
        } else {
          state.favorites.add(entryId);
        }
        localStorage.setItem('keepass_favs', JSON.stringify(Array.from(state.favorites)));
        render();
      } else if (action === 'copy-user' && entry) {
        copyToClipboard(entry.username, 'Nome de usuário');
      } else if (action === 'copy-pwd' && entry) {
        copyToClipboard(entry.password, 'Senha');
      } else if (action === 'toggle-reveal-card') {
        if (state.revealedPasswords.has(entryId)) {
          state.revealedPasswords.delete(entryId);
        } else {
          state.revealedPasswords.add(entryId);
        }
        render();
      } else if (action === 'view-detail') {
        state.selectedEntryId = entryId;
        render();
        if (entry && entry.totpKey) {
          updateActiveTotp(entry.totpKey);
        }
      } else if (action === 'copy-text') {
        const text = btn.getAttribute('data-text');
        const desc = btn.getAttribute('data-desc') || 'Texto';
        copyToClipboard(text, desc);
      }
    };
  });

  // Drawer Close
  const btnCloseDrawer = document.getElementById('btn-close-drawer');
  if (btnCloseDrawer) {
    btnCloseDrawer.onclick = () => {
      state.selectedEntryId = null;
      if (state.totpTimer) clearInterval(state.totpTimer);
      render();
    };
  }

  // TOTP Copy
  const btnCopyTotp = document.getElementById('btn-copy-totp');
  if (btnCopyTotp && state.activeTotpData) {
    btnCopyTotp.onclick = () => {
      copyToClipboard(state.activeTotpData.code, 'Código TOTP');
    };
  }

  // GENERATOR MODAL EVENTS
  const openGenBtns = [
    document.getElementById('btn-open-generator'),
    document.getElementById('btn-open-generator-top')
  ].filter(Boolean);

  openGenBtns.forEach(b => {
    b.onclick = () => {
      state.showGeneratorModal = true;
      state.generatorConfig.generated = generatePassword(state.generatorConfig);
      render();
    };
  });

  const closeGenBtns = [
    document.getElementById('btn-close-generator'),
    document.getElementById('btn-close-generator-footer')
  ].filter(Boolean);

  closeGenBtns.forEach(b => {
    b.onclick = () => {
      state.showGeneratorModal = false;
      render();
    };
  });

  const btnRegenPwd = document.getElementById('btn-regen-pwd');
  if (btnRegenPwd) {
    btnRegenPwd.onclick = () => {
      state.generatorConfig.generated = generatePassword(state.generatorConfig);
      render();
    };
  }

  const btnCopyGen = document.getElementById('btn-copy-generated');
  if (btnCopyGen) {
    btnCopyGen.onclick = () => {
      copyToClipboard(state.generatorConfig.generated, 'Senha gerada');
    };
  }

  const btnCopyCloseGen = document.getElementById('btn-copy-and-close-gen');
  if (btnCopyCloseGen) {
    btnCopyCloseGen.onclick = () => {
      copyToClipboard(state.generatorConfig.generated, 'Senha gerada');
      state.showGeneratorModal = false;
      render();
    };
  }

  const lenSlider = document.getElementById('generator-len-slider');
  if (lenSlider) {
    lenSlider.oninput = (e) => {
      state.generatorConfig.length = parseInt(e.target.value, 10);
      state.generatorConfig.generated = generatePassword(state.generatorConfig);
      render();
    };
  }

  const chkUpper = document.getElementById('gen-opt-upper');
  const chkLower = document.getElementById('gen-opt-lower');
  const chkNum = document.getElementById('gen-opt-num');
  const chkSym = document.getElementById('gen-opt-sym');
  const chkAmbig = document.getElementById('gen-opt-ambig');

  if (chkUpper) chkUpper.onchange = (e) => { state.generatorConfig.uppercase = e.target.checked; state.generatorConfig.generated = generatePassword(state.generatorConfig); render(); };
  if (chkLower) chkLower.onchange = (e) => { state.generatorConfig.lowercase = e.target.checked; state.generatorConfig.generated = generatePassword(state.generatorConfig); render(); };
  if (chkNum) chkNum.onchange = (e) => { state.generatorConfig.numbers = e.target.checked; state.generatorConfig.generated = generatePassword(state.generatorConfig); render(); };
  if (chkSym) chkSym.onchange = (e) => { state.generatorConfig.symbols = e.target.checked; state.generatorConfig.generated = generatePassword(state.generatorConfig); render(); };
  if (chkAmbig) chkAmbig.onchange = (e) => { state.generatorConfig.avoidAmbiguous = e.target.checked; state.generatorConfig.generated = generatePassword(state.generatorConfig); render(); };

  // EXPORT MODAL EVENTS
  const btnOpenExport = document.getElementById('btn-open-export');
  if (btnOpenExport) {
    btnOpenExport.onclick = () => {
      state.showExportModal = true;
      render();
    };
  }

  const closeExportBtns = [
    document.getElementById('btn-close-export'),
    document.getElementById('btn-close-export-footer')
  ].filter(Boolean);

  closeExportBtns.forEach(b => {
    b.onclick = () => {
      state.showExportModal = false;
      render();
    };
  });

  const btnExportCsv = document.getElementById('btn-export-csv');
  if (btnExportCsv) {
    btnExportCsv.onclick = () => exportAsCsv();
  }

  const btnExportJson = document.getElementById('btn-export-json');
  if (btnExportJson) {
    btnExportJson.onclick = () => exportAsJson();
  }
}

async function handleKdbxFile(file) {
  if (!file.name.toLowerCase().endsWith('.kdbx')) {
    state.unlockError = 'Por favor, selecione um arquivo válido com extensão .kdbx.';
    render();
    return;
  }

  state.fileName = file.name;
  state.fileSize = file.size;
  state.fileBuffer = await file.arrayBuffer();
  state.unlockError = '';
  render();

  const pwdInput = document.getElementById('master-password-input');
  if (pwdInput) pwdInput.focus();
}

// Initial render
render();

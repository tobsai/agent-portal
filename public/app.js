// State
let tasks = [];
let eventSource = null;
let draggedTask = null;
let touchStartY = 0;
let touchStartX = 0;
let draggedElement = null;
let placeholder = null;

// DOM elements
const columns = {
  'todo': document.getElementById('todo-cards'),
  'in-progress': document.getElementById('in-progress-cards'),
  'done': document.getElementById('done-cards')
};

const counts = {
  'todo': document.getElementById('todo-count'),
  'in-progress': document.getElementById('in-progress-count'),
  'done': document.getElementById('done-count')
};

const connectionStatus = document.getElementById('connection-status');
const modal = document.getElementById('task-modal');

// Initialize
async function init() {
  setupDropZones();
  await loadTasks();
  connectSSE();
}

// Load all tasks
async function loadTasks() {
  try {
    const res = await fetch('/api/tasks');
    tasks = await res.json();
    renderAll();
  } catch (err) {
    console.error('Failed to load tasks:', err);
  }
}

// Connect to SSE for real-time updates
function connectSSE() {
  eventSource = new EventSource('/api/events');
  
  eventSource.onopen = () => {
    connectionStatus.className = 'connection-status connected';
    connectionStatus.querySelector('.status-text').textContent = 'Live';
  };
  
  eventSource.onerror = () => {
    connectionStatus.className = 'connection-status disconnected';
    connectionStatus.querySelector('.status-text').textContent = 'Disconnected';
    
    // Reconnect after 3 seconds
    setTimeout(() => {
      if (eventSource.readyState === EventSource.CLOSED) {
        connectSSE();
      }
    }, 3000);
  };
  
  eventSource.addEventListener('task-created', (e) => {
    const task = JSON.parse(e.data);
    tasks.push(task);
    renderTask(task, true);
    updateCounts();
  });
  
  eventSource.addEventListener('task-updated', (e) => {
    const updatedTask = JSON.parse(e.data);
    const idx = tasks.findIndex(t => t.id === updatedTask.id);
    
    if (idx !== -1) {
      const oldStatus = tasks[idx].status;
      tasks[idx] = updatedTask;
      
      // Re-render if status changed, otherwise just update in place
      if (oldStatus !== updatedTask.status) {
        removeTaskCard(updatedTask.id);
        renderTask(updatedTask, true);
      } else {
        updateTaskCard(updatedTask);
      }
      updateCounts();
    }
  });
  
  eventSource.addEventListener('task-deleted', (e) => {
    const { id } = JSON.parse(e.data);
    tasks = tasks.filter(t => t.id !== id);
    removeTaskCard(id);
    updateCounts();
  });
}

// Render all tasks
function renderAll() {
  // Clear columns
  Object.values(columns).forEach(col => col.innerHTML = '');
  
  // Render each task
  tasks.forEach(task => renderTask(task, false));
  updateCounts();
  
  // Add empty states
  Object.entries(columns).forEach(([status, col]) => {
    if (col.children.length === 0) {
      col.innerHTML = '<div class="empty-state">No tasks</div>';
    }
  });
}

// Render single task
function renderTask(task, isNew) {
  const column = columns[task.status];
  if (!column) return;
  
  // Remove empty state if present
  const emptyState = column.querySelector('.empty-state');
  if (emptyState) emptyState.remove();
  
  const card = document.createElement('div');
  card.className = 'card' + (isNew ? ' new' : '');
  card.dataset.id = task.id;
  card.dataset.status = task.status;
  card.draggable = true;
  
  // Desktop drag events
  card.ondragstart = (e) => handleDragStart(e, task);
  card.ondragend = handleDragEnd;
  
  // Touch events for mobile
  card.ontouchstart = (e) => handleTouchStart(e, task, card);
  card.ontouchmove = (e) => handleTouchMove(e, card);
  card.ontouchend = (e) => handleTouchEnd(e, task);
  
  // Click for modal (only if not dragging)
  card.onclick = (e) => {
    if (!card.classList.contains('dragging')) {
      showTaskModal(task);
    }
  };
  
  const updated = formatTime(task.updated_at);
  const preview = task.notes ? getLastLine(task.notes) : '';
  
  card.innerHTML = `
    <div class="card-title">${escapeHtml(task.name)}</div>
    <div class="card-meta">Updated ${updated}</div>
    ${preview ? `<div class="card-preview">${escapeHtml(preview)}</div>` : ''}
  `;
  
  column.prepend(card);
}

// Update existing task card
function updateTaskCard(task) {
  const card = document.querySelector(`.card[data-id="${task.id}"]`);
  if (!card) return;
  
  const updated = formatTime(task.updated_at);
  const preview = task.notes ? getLastLine(task.notes) : '';
  
  card.innerHTML = `
    <div class="card-title">${escapeHtml(task.name)}</div>
    <div class="card-meta">Updated ${updated}</div>
    ${preview ? `<div class="card-preview">${escapeHtml(preview)}</div>` : ''}
  `;
  
  card.onclick = () => showTaskModal(task);
  
  // Flash effect
  card.classList.add('new');
  setTimeout(() => card.classList.remove('new'), 300);
}

// Remove task card
function removeTaskCard(id) {
  const card = document.querySelector(`.card[data-id="${id}"]`);
  if (card) card.remove();
}

// Update column counts
function updateCounts() {
  const taskCounts = {
    'todo': tasks.filter(t => t.status === 'todo').length,
    'in-progress': tasks.filter(t => t.status === 'in-progress').length,
    'done': tasks.filter(t => t.status === 'done').length
  };
  
  Object.entries(counts).forEach(([status, el]) => {
    el.textContent = taskCounts[status];
  });
}

// Show task modal
function showTaskModal(task) {
  document.getElementById('modal-title').textContent = task.name;
  
  const statusEl = document.getElementById('modal-status');
  statusEl.textContent = formatStatus(task.status);
  statusEl.className = `status-badge ${task.status}`;
  
  document.getElementById('modal-created').textContent = formatDateTime(task.created_at);
  document.getElementById('modal-updated').textContent = formatDateTime(task.updated_at);
  document.getElementById('modal-notes').textContent = task.notes || '(no notes)';
  
  modal.classList.add('active');
}

// Close modal
function closeModal() {
  modal.classList.remove('active');
}

// Close modal on backdrop click
modal.onclick = (e) => {
  if (e.target === modal) closeModal();
};

// Close modal on Escape
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal();
});

// Drag and Drop Handlers (Desktop)
function handleDragStart(e, task) {
  draggedTask = task;
  e.target.classList.add('dragging');
  e.dataTransfer.effectAllowed = 'move';
  e.dataTransfer.setData('text/plain', task.id);
}

function handleDragEnd(e) {
  e.target.classList.remove('dragging');
  draggedTask = null;
  document.querySelectorAll('.column').forEach(col => col.classList.remove('drag-over'));
}

function handleDragOver(e) {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'move';
  e.currentTarget.classList.add('drag-over');
}

function handleDragLeave(e) {
  e.currentTarget.classList.remove('drag-over');
}

async function handleDrop(e, newStatus) {
  e.preventDefault();
  e.currentTarget.classList.remove('drag-over');
  
  if (draggedTask && draggedTask.status !== newStatus) {
    await updateTaskStatus(draggedTask.id, newStatus);
  }
}

// Touch Handlers (Mobile)
function handleTouchStart(e, task, card) {
  const touch = e.touches[0];
  touchStartX = touch.clientX;
  touchStartY = touch.clientY;
  draggedTask = task;
  draggedElement = card;
  
  // Long press to initiate drag
  card.touchTimeout = setTimeout(() => {
    card.classList.add('dragging');
    createPlaceholder(card);
    
    // Vibrate if supported
    if (navigator.vibrate) navigator.vibrate(50);
  }, 200);
}

function handleTouchMove(e, card) {
  if (!card.classList.contains('dragging')) {
    // If moved before long press, cancel drag initiation
    const touch = e.touches[0];
    const dx = Math.abs(touch.clientX - touchStartX);
    const dy = Math.abs(touch.clientY - touchStartY);
    if (dx > 10 || dy > 10) {
      clearTimeout(card.touchTimeout);
    }
    return;
  }
  
  e.preventDefault();
  const touch = e.touches[0];
  
  // Move the card with finger
  card.style.position = 'fixed';
  card.style.left = (touch.clientX - card.offsetWidth / 2) + 'px';
  card.style.top = (touch.clientY - card.offsetHeight / 2) + 'px';
  card.style.zIndex = '1000';
  card.style.width = card.offsetWidth + 'px';
  card.style.pointerEvents = 'none';
  
  // Highlight column under finger
  const elementBelow = document.elementFromPoint(touch.clientX, touch.clientY);
  const columnBelow = elementBelow?.closest('.column');
  
  document.querySelectorAll('.column').forEach(col => col.classList.remove('drag-over'));
  if (columnBelow) columnBelow.classList.add('drag-over');
}

async function handleTouchEnd(e, task) {
  clearTimeout(draggedElement?.touchTimeout);
  
  if (!draggedElement?.classList.contains('dragging')) {
    draggedTask = null;
    draggedElement = null;
    return;
  }
  
  const touch = e.changedTouches[0];
  const elementBelow = document.elementFromPoint(touch.clientX, touch.clientY);
  const columnBelow = elementBelow?.closest('.column');
  
  // Reset card position
  if (draggedElement) {
    draggedElement.style.position = '';
    draggedElement.style.left = '';
    draggedElement.style.top = '';
    draggedElement.style.zIndex = '';
    draggedElement.style.width = '';
    draggedElement.style.pointerEvents = '';
    draggedElement.classList.remove('dragging');
  }
  
  removePlaceholder();
  document.querySelectorAll('.column').forEach(col => col.classList.remove('drag-over'));
  
  // Update status if dropped on different column
  if (columnBelow && task) {
    const newStatus = columnBelow.dataset.status;
    if (newStatus && newStatus !== task.status) {
      await updateTaskStatus(task.id, newStatus);
    }
  }
  
  draggedTask = null;
  draggedElement = null;
}

function createPlaceholder(card) {
  placeholder = document.createElement('div');
  placeholder.className = 'card placeholder';
  placeholder.style.height = card.offsetHeight + 'px';
  card.parentNode.insertBefore(placeholder, card);
}

function removePlaceholder() {
  if (placeholder) {
    placeholder.remove();
    placeholder = null;
  }
}

// API call to update task status
async function updateTaskStatus(taskId, newStatus) {
  const apiKey = localStorage.getItem('portalApiKey');
  if (!apiKey) {
    alert('No API key stored. Cannot move tasks without authentication.');
    return;
  }
  
  try {
    const res = await fetch(`/api/tasks/${taskId}`, {
      method: 'PATCH',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${apiKey}`
      },
      body: JSON.stringify({ status: newStatus })
    });
    
    if (!res.ok) {
      const err = await res.json();
      alert('Failed to move task: ' + (err.error || 'Unknown error'));
    }
    // SSE will handle the UI update
  } catch (err) {
    console.error('Failed to update task:', err);
    alert('Network error moving task');
  }
}

// Setup column drop zones
function setupDropZones() {
  document.querySelectorAll('.column').forEach(column => {
    const status = column.dataset.status;
    column.ondragover = handleDragOver;
    column.ondragleave = handleDragLeave;
    column.ondrop = (e) => handleDrop(e, status);
  });
}

// Helpers
function formatTime(isoString) {
  const date = new Date(isoString);
  const now = new Date();
  const diff = now - date;
  
  if (diff < 60000) return 'just now';
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`;
  return date.toLocaleDateString();
}

function formatDateTime(isoString) {
  return new Date(isoString).toLocaleString();
}

function formatStatus(status) {
  return status.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ');
}

function getLastLine(text) {
  const lines = text.trim().split('\n');
  return lines[lines.length - 1];
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Settings
function showSettings() {
  const modal = document.getElementById('settings-modal');
  const input = document.getElementById('api-key-input');
  input.value = localStorage.getItem('portalApiKey') || '';
  modal.classList.add('active');
}

function closeSettings() {
  document.getElementById('settings-modal').classList.remove('active');
}

function saveSettings() {
  const input = document.getElementById('api-key-input');
  const status = document.getElementById('settings-status');
  
  if (input.value.trim()) {
    localStorage.setItem('portalApiKey', input.value.trim());
    status.textContent = '✓ Saved';
    status.style.color = '#10b981';
  } else {
    localStorage.removeItem('portalApiKey');
    status.textContent = '✓ Cleared';
    status.style.color = '#f59e0b';
  }
  
  setTimeout(() => {
    status.textContent = '';
    closeSettings();
  }, 1000);
}

// Close settings on backdrop click
document.getElementById('settings-modal')?.addEventListener('click', (e) => {
  if (e.target.id === 'settings-modal') closeSettings();
});

// Start
init();

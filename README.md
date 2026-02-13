# Agent Portal - Kanban Task Board

A lightweight Kanban board for agents to push task status updates in real-time.

![Status](https://img.shields.io/badge/status-functional-green)

## Quick Start

```bash
cd /Users/talos/.openclaw/workspace/projects/agent-portal
npm install
npm start
```

Open **http://localhost:3847** to view the board.

On first run, an API key is generated and printed to the console:
```
🔑 Generated new API key: ak_xxxxxxxxxxxxxxxxxxxxxxxxxxxx
```

**Save this key!** You'll need it to push updates.

---

## API Reference

All write endpoints require the API key in the `Authorization` header:
```
Authorization: Bearer ak_your_api_key_here
```

### Get All Tasks
```bash
GET /api/tasks
```

Response:
```json
[
  {
    "id": "uuid",
    "name": "Task name",
    "status": "todo",
    "notes": "Log entries...",
    "created_at": "2024-01-15T10:30:00.000Z",
    "updated_at": "2024-01-15T11:45:00.000Z"
  }
]
```

### Create Task
```bash
POST /api/tasks
Authorization: Bearer ak_your_api_key

{
  "name": "Build feature X",
  "status": "todo",       # optional: todo, in-progress, done
  "notes": "Initial note" # optional
}
```

### Update Task
```bash
PATCH /api/tasks/:id
Authorization: Bearer ak_your_api_key

{
  "name": "New name",      # optional
  "status": "in-progress", # optional
  "notes": "Replace notes" # optional
}
```

### Append to Task Log
Adds a timestamped entry to the task's notes:
```bash
POST /api/tasks/:id/log
Authorization: Bearer ak_your_api_key

{
  "message": "Completed step 1"
}
```

Result in notes:
```
[1/15/2024, 10:30:00 AM] Started work
[1/15/2024, 11:45:00 AM] Completed step 1
```

### Delete Task
```bash
DELETE /api/tasks/:id
Authorization: Bearer ak_your_api_key
```

### Health Check
```bash
GET /api/health
```

---

## Example: Agent Workflow

```bash
API_KEY="ak_your_key_here"
BASE_URL="http://localhost:3847"

# Create a new task
TASK=$(curl -s -X POST "$BASE_URL/api/tasks" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name": "Process user request", "status": "todo"}')

TASK_ID=$(echo $TASK | jq -r '.id')

# Move to in-progress
curl -X PATCH "$BASE_URL/api/tasks/$TASK_ID" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"status": "in-progress"}'

# Log progress
curl -X POST "$BASE_URL/api/tasks/$TASK_ID/log" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"message": "Analyzing request..."}'

curl -X POST "$BASE_URL/api/tasks/$TASK_ID/log" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"message": "Generated response"}'

# Mark done
curl -X PATCH "$BASE_URL/api/tasks/$TASK_ID" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"status": "done"}'
```

---

## Status Values

| Status | Description |
|--------|-------------|
| `todo` | Task queued, not started |
| `in-progress` | Currently being worked on |
| `done` | Completed |

---

## Real-Time Updates

The board uses Server-Sent Events (SSE) for live updates. Any changes pushed via the API appear instantly on connected browsers.

SSE endpoint (for custom clients):
```
GET /api/events
```

Events:
- `task-created` - New task added
- `task-updated` - Task modified
- `task-deleted` - Task removed

---

## Data Storage

Data is stored in `data/portal.db` (SQLite). The API key is also stored here.

To reset everything:
```bash
rm -rf data/
npm start  # New API key will be generated
```

---

## Configuration

| Env Var | Default | Description |
|---------|---------|-------------|
| `PORT` | 3847 | Server port |

---

## File Structure

```
agent-portal/
├── server.js        # Express backend
├── package.json
├── README.md
├── data/
│   └── portal.db    # SQLite database (created on first run)
└── public/
    ├── index.html   # Kanban board UI
    ├── style.css
    └── app.js
```
# Preview Environment: preview-activity.mtree.io

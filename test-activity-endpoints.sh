#!/bin/bash

# Test script for activity dashboard endpoints
# Run this after starting the agent portal server

API_KEY="ak_e83ddf5617724e41b80419e19037c2d0"
BASE_URL="http://localhost:3847"
# BASE_URL="https://talos.mtree.io"  # Uncomment for production

AGENT_ID="689681ce-db81-4943-82f6-355e566c2603"

echo "🧪 Testing Activity Dashboard Endpoints"
echo "========================================"
echo ""

# Test 1: Tool Usage
echo "📊 Test 1: POST /api/tool-usage"
curl -X POST "$BASE_URL/api/tool-usage" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"agentId\": \"$AGENT_ID\",
    \"tool\": \"exec\",
    \"category\": \"development\",
    \"description\": \"Running test script\",
    \"model\": \"claude-sonnet-4-5\",
    \"tokensUsed\": 850,
    \"duration\": 234
  }" | jq .

echo ""
echo "📊 Test 2: GET /api/tool-usage"
curl -X GET "$BASE_URL/api/tool-usage?hours=24" \
  -H "Authorization: Bearer $API_KEY" | jq .stats

echo ""
echo ""

# Test 3: Sub-Agent Activity
echo "🤖 Test 3: POST /api/subagent-activity (spawned)"
curl -X POST "$BASE_URL/api/subagent-activity" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"agentId\": \"$AGENT_ID\",
    \"subagentLabel\": \"test-subagent\",
    \"sessionKey\": \"subagent:test:$(date +%s)\",
    \"status\": \"running\",
    \"task\": \"Testing sub-agent activity tracking\",
    \"model\": \"claude-sonnet-4-5\"
  }" | jq .

echo ""
echo "🤖 Test 4: GET /api/subagent-activity"
curl -X GET "$BASE_URL/api/subagent-activity?hours=24" \
  -H "Authorization: Bearer $API_KEY" | jq .stats

echo ""
echo ""

# Test 5: Thread Activity
echo "📋 Test 5: POST /api/thread-activity (new thread)"
curl -X POST "$BASE_URL/api/thread-activity" \
  -H "Authorization: Bearer $API_KEY" \
  -H "Content-Type: application/json" \
  -d "{
    \"agentId\": \"$AGENT_ID\",
    \"threadId\": \"test-thread-$(date +%s)\",
    \"title\": \"Test thread for activity tracking\",
    \"status\": \"in-progress\",
    \"category\": \"project\",
    \"nextAction\": \"Continue testing\"
  }" | jq .

echo ""
echo "📋 Test 6: POST /api/thread-activity (update thread)"
THREAD_ID=$(curl -s -X GET "$BASE_URL/api/thread-activity" \
  -H "Authorization: Bearer $API_KEY" | jq -r '.threads[0].thread_id')

if [ "$THREAD_ID" != "null" ]; then
  curl -X POST "$BASE_URL/api/thread-activity" \
    -H "Authorization: Bearer $API_KEY" \
    -H "Content-Type: application/json" \
    -d "{
      \"agentId\": \"$AGENT_ID\",
      \"threadId\": \"$THREAD_ID\",
      \"title\": \"Updated thread title\",
      \"status\": \"blocked\",
      \"category\": \"project\",
      \"blockedOn\": \"Waiting for API response\",
      \"nextAction\": \"Follow up tomorrow\"
    }" | jq .
  
  echo ""
  echo "📋 Test 7: GET /api/thread-activity"
  curl -X GET "$BASE_URL/api/thread-activity" \
    -H "Authorization: Bearer $API_KEY" | jq .stats
else
  echo "No threads found to update"
fi

echo ""
echo ""
echo "✅ All tests complete!"
echo ""
echo "🌐 Open dashboard: $BASE_URL/dashboard"
echo "   View real-time updates as new data arrives"

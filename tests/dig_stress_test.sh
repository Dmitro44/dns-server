#!/bin/bash
# Real DNS Stress Test using 'dig' for throughput measurement
# This script sends 100 parallel queries to verify multi-threading performance.

SERVER="127.0.0.1"
PORT="8053"
QUERY_COUNT=100

# Detect base directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
BINARY="$PROJECT_ROOT/build/dns-server"

echo "Starting Performance Test (Parallel dig queries)..."
echo "Target: $SERVER:$PORT, Queries: $QUERY_COUNT"

# Launch server in background if not already running
if ! lsof -i :$PORT >/dev/null 2>&1; then
    echo "Server not detected on port $PORT. Starting server..."
    if [ -f "$BINARY" ]; then
        cd "$PROJECT_ROOT"
        ./build/dns-server >server_test.log 2>&1 &
        SERVER_PID=$!
        sleep 2
        if ! ps -p $SERVER_PID >/dev/null; then
            echo "Error: Server failed to start. Check server_test.log"
            exit 1
        fi
        echo "Server started with PID $SERVER_PID"
    else
        echo "Error: dns-server binary not found at $BINARY"
        exit 1
    fi
fi

START_TIME=$(date +%s%N)

for i in $(seq 1 $QUERY_COUNT); do
    # 50% hits on example.test, 50% unique random subdomains
    if [ $((i % 2)) -eq 0 ]; then
        dig @$SERVER -p $PORT "rand-$i.example.test" A +short >/dev/null 2>&1 &
    else
        dig @$SERVER -p $PORT example.test A +short >/dev/null 2>&1 &
    fi
done

# Wait ONLY for 'dig' processes
# We filter out the server PID from the list of background jobs
ALL_PIDS=$(jobs -p)
DIG_PIDS=$(echo "$ALL_PIDS" | grep -v "${SERVER_PID:-none}")

if [ ! -z "$DIG_PIDS" ]; then
    wait $DIG_PIDS 2>/dev/null
fi

END_TIME=$(date +%s%N)

# Stop server if we started it
if [ ! -z "$SERVER_PID" ]; then
    echo "Stopping test server (PID $SERVER_PID)..."
    kill $SERVER_PID
    wait $SERVER_PID 2>/dev/null
fi

DURATION_NS=$((END_TIME - START_TIME))
DURATION_MS=$((DURATION_NS / 1000000))

echo "--------------------------------------"
echo "Test Finished."
echo "Total Time: $DURATION_MS ms"

if [ $DURATION_MS -gt 0 ]; then
    RPS=$((QUERY_COUNT * 1000 / DURATION_MS))
    echo "Throughput: $RPS requests per second"
else
    echo "Throughput: Ultra-fast (under 1ms)"
fi
echo "--------------------------------------"

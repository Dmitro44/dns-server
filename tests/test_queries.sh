#!/bin/bash
# DNS Test Queries Script for port 8053

SERVER="127.0.0.1"
PORT="8053"

echo "=== [1. A RECORD QUERY] ==="
dig @$SERVER -p $PORT example.test A

echo "=== [2. AAAA RECORD QUERY] ==="
dig @$SERVER -p $PORT www.example.test AAAA

echo "=== [3. PURE CNAME RECORD QUERY] ==="
dig @$SERVER -p $PORT blog.example.test CNAME

echo "=== [4. CNAME CHAIN (A query) - First attempt (MISS)] ==="
dig @$SERVER -p $PORT blog.example.test A

echo "=== [5. CNAME CHAIN (A query) - Second attempt (HIT)] ==="
dig @$SERVER -p $PORT blog.example.test A

echo "=== [6. NEGATIVE CACHING TEST] ==="
echo "--- Attempt 1: Cache hit ---"
# Using a fixed name for the second part to ensure match
dig @$SERVER -p $PORT missing.example.test A
dig @$SERVER -p $PORT missing.example.test A

echo ""
echo "=== [7. MALFORMED QUERY (Too short)] ==="
# Sending a random short byte string using nc
echo "DNS-FAIL" | nc -u -w 1 $SERVER $PORT
echo "Sent 'DNS-FAIL' to trigger parse error"

echo ""
echo "=== [8. MALFORMED QUERY (Invalid pointers)] ==="
# Sending a 12-byte header + some garbage to trigger name parsing error
# (Header: ID=0x1234, Flags=0x0100, QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0)
# Then garbage name
echo -ne '\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\xff\xff\x00\x01\x00\x01' | nc -u -w 1 $SERVER $PORT
echo "Sent invalid DNS packet to trigger parse error"

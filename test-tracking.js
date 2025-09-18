#!/usr/bin/env node

// Test script to simulate MCP tool calls and test query tracking
const BASE_URL = 'http://localhost:8787';
const ADMIN_KEY = 'admin-tracking-key-2024';  // Default admin key

async function testTracking() {
  console.log('🧪 Testing Query Tracking System with Authentication...\n');

  // Test 1: Try to access stats without authentication (should fail)
  console.log('1️⃣ Testing unauthorized access (should fail)...');
  try {
    const statsResponse = await fetch(`${BASE_URL}/tracking/stats`);
    if (statsResponse.status === 401) {
      console.log('✅ Unauthorized access correctly blocked');
    } else {
      console.log('❌ Unauthorized access should have been blocked');
    }
  } catch (error) {
    console.log('✅ Unauthorized access blocked:', error.message);
  }

  // Test 2: Check initial stats with authentication
  console.log('\n2️⃣ Checking initial stats with admin auth...');
  try {
    const statsResponse = await fetch(`${BASE_URL}/tracking/stats`, {
      headers: {
        'Authorization': `Bearer ${ADMIN_KEY}`
      }
    });
    const stats = await statsResponse.json();
    console.log('📊 Initial Stats:', JSON.stringify(stats, null, 2));
  } catch (error) {
    console.error('❌ Error fetching stats:', error.message);
  }

  // Test 3: Simulate tracking a query
  console.log('\n3️⃣ Simulating a query...');
  try {
    const trackResponse = await fetch(`${BASE_URL}/tracking/track`, {
      method: 'POST',
      headers: { 
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${ADMIN_KEY}`
      },
      body: JSON.stringify({
        userId: 'test-user-123',
        query: 'Send message from +1234567890 to +0987654321: Hello from authenticated test!',
        toolName: 'send-message',
        success: true,
        responseTime: 1250,
        metadata: {
          userAgent: 'Test-Script/1.0',
          clientType: 'test'
        }
      })
    });
    
    if (trackResponse.ok) {
      const result = await trackResponse.json();
      console.log('✅ Query tracked successfully:', result);
    } else {
      console.log('❌ Failed to track query:', trackResponse.status);
    }
  } catch (error) {
    console.error('❌ Error tracking query:', error.message);
  }

  // Test 4: Check updated stats
  console.log('\n4️⃣ Checking updated stats...');
  try {
    const statsResponse = await fetch(`${BASE_URL}/tracking/stats`, {
      headers: {
        'Authorization': `Bearer ${ADMIN_KEY}`
      }
    });
    const stats = await statsResponse.json();
    console.log('📊 Updated Stats:', JSON.stringify(stats, null, 2));
  } catch (error) {
    console.error('❌ Error fetching updated stats:', error.message);
  }

  // Test 5: Get query history
  console.log('\n5️⃣ Getting query history...');
  try {
    const queriesResponse = await fetch(`${BASE_URL}/tracking/queries`, {
      headers: {
        'Authorization': `Bearer ${ADMIN_KEY}`
      }
    });
    const queries = await queriesResponse.json();
    console.log('📝 Query History:', JSON.stringify(queries, null, 2));
  } catch (error) {
    console.error('❌ Error fetching queries:', error.message);
  }

  console.log('\n🎉 Authentication testing complete!');
  console.log('\n🔑 Admin Key:', ADMIN_KEY);
  console.log('📖 Usage: curl -H "Authorization: Bearer ' + ADMIN_KEY + '" http://localhost:8787/tracking/stats');
}

// Run the test
testTracking().catch(console.error);

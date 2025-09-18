#!/usr/bin/env node

// Test script to verify MCP tool integration with tracking
const BASE_URL = 'http://localhost:63978';
const ADMIN_KEY = 'admin-tracking-key-2024';

async function testMCPIntegration() {
  console.log('🧪 Testing MCP Tool Integration with Query Tracking...\n');

  // Test 1: Clear existing tracking data
  console.log('1️⃣ Clearing existing tracking data...');
  try {
    const clearResponse = await fetch(`${BASE_URL}/tracking/clear`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${ADMIN_KEY}`
      }
    });
    const clearResult = await clearResponse.json();
    console.log('✅ Cleared:', clearResult.message);
  } catch (error) {
    console.error('❌ Error clearing data:', error.message);
  }

  // Test 2: Try to call an MCP tool that should trigger tracking
  console.log('\n2️⃣ Testing MCP SSE endpoint (this should trigger tracking)...');
  try {
    const sseResponse = await fetch(`${BASE_URL}/sse`, {
      method: 'GET',
      headers: {
        'Accept': 'text/event-stream',
        'User-Agent': 'Test-MCP-Client/1.0'
      }
    });

    if (sseResponse.ok) {
      console.log('✅ SSE endpoint responding:', sseResponse.status);
      // Just check if we get a response, don't try to parse SSE stream
    } else {
      console.log('❌ SSE endpoint failed:', sseResponse.status);
    }
  } catch (error) {
    console.log('⚠️ SSE test expected (not a failure):', error.message);
  }

  // Test 3: Check if any tracking data was recorded
  console.log('\n3️⃣ Checking for any tracked queries...');
  await new Promise(resolve => setTimeout(resolve, 1000)); // Wait a bit

  try {
    const statsResponse = await fetch(`${BASE_URL}/tracking/stats`, {
      headers: {
        'Authorization': `Bearer ${ADMIN_KEY}`
      }
    });
    const stats = await statsResponse.json();
    console.log('📊 Current Stats:', JSON.stringify(stats, null, 2));

    if (stats.totalQueries > 0) {
      console.log('✅ Tracking integration working! Found', stats.totalQueries, 'queries');
    } else {
      console.log('⚠️ No queries tracked yet - MCP tools may not have been called');
    }
  } catch (error) {
    console.error('❌ Error fetching stats:', error.message);
  }

  // Test 4: Simulate a direct tool call via POST (if the endpoint exists)
  console.log('\n4️⃣ Testing direct tool simulation...');
  try {
    // This might not work depending on how the MCP server is set up
    const toolResponse = await fetch(`${BASE_URL}/tools/send-message`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'User-Agent': 'Test-Direct-Call/1.0'
      },
      body: JSON.stringify({
        to: '+1234567890',
        message: 'Test tracking integration'
      })
    });

    console.log('Tool call response status:', toolResponse.status);
  } catch (error) {
    console.log('⚠️ Direct tool call not available (expected):', error.message);
  }

  // Final check
  console.log('\n5️⃣ Final tracking stats check...');
  try {
    const finalStatsResponse = await fetch(`${BASE_URL}/tracking/stats`, {
      headers: {
        'Authorization': `Bearer ${ADMIN_KEY}`
      }
    });
    const finalStats = await finalStatsResponse.json();
    console.log('📊 Final Stats:', JSON.stringify(finalStats, null, 2));
  } catch (error) {
    console.error('❌ Error fetching final stats:', error.message);
  }

  console.log('\n🎉 MCP Integration testing complete!');
  console.log('\n💡 Note: To fully test, connect via MCP Inspector or Claude Desktop');
}

// Run the test
testMCPIntegration().catch(console.error);
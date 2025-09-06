#!/usr/bin/env node

/**
 * Simple API Test Script
 * Tests the resource server endpoints with generated JWT tokens
 */

const http = require('http');

// Configuration
const BASE_URL = 'http://localhost:3000';
const { TestJWTGenerator } = require('./test-jwt.js');

/**
 * Makes HTTP request and returns promise
 */
function makeRequest(path, options = {}) {
  return new Promise((resolve, reject) => {
    const requestOptions = {
      hostname: 'localhost',
      port: 3000,
      path: path,
      method: options.method || 'GET',
      headers: {
        'Content-Type': 'application/json',
        ...options.headers
      }
    };

    const req = http.request(requestOptions, (res) => {
      let data = '';
      res.on('data', (chunk) => {
        data += chunk;
      });

      res.on('end', () => {
        try {
          const jsonData = JSON.parse(data);
          resolve({ status: res.statusCode, data: jsonData, headers: res.headers });
        } catch (e) {
          resolve({ status: res.statusCode, data: data, headers: res.headers });
        }
      });
    });

    req.on('error', (error) => {
      reject(error);
    });

    if (options.body) {
      req.write(JSON.stringify(options.body));
    }

    req.end();
  });
}

/**
 * Test runner
 */
async function runTests() {
  console.log('🧪 Starting API Tests...\n');

  try {
    // Test 1: Health endpoint (should work without token)
    console.log('1. Testing health endpoint...');
    const healthResponse = await makeRequest('/health');
    console.log(`   Status: ${healthResponse.status}`);
    console.log(`   Response: ${JSON.stringify(healthResponse.data, null, 2)}\n`);

    // Test 2: Notes without token (should return 401)
    console.log('2. Testing /notes without token...');
    const noTokenResponse = await makeRequest('/notes');
    console.log(`   Status: ${noTokenResponse.status}`);
    console.log(`   Response: ${JSON.stringify(noTokenResponse.data, null, 2)}\n`);

    // Test 3: Generate valid token and test
    console.log('3. Testing /notes with valid token...');
    const token = TestJWTGenerator.generateAccessToken('alice', ['notes:read']);
    console.log(`   Generated token: ${token.substring(0, 50)}...`);
    
    const validTokenResponse = await makeRequest('/notes', {
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });
    console.log(`   Status: ${validTokenResponse.status}`);
    console.log(`   Response: ${JSON.stringify(validTokenResponse.data, null, 2)}\n`);

    // Test 4: Test with write scope
    console.log('4. Testing POST /notes with write token...');
    const writeToken = TestJWTGenerator.generateAccessToken('bob', ['notes:write']);
    const postResponse = await makeRequest('/notes', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${writeToken}`
      },
      body: {
        title: 'Test Note',
        content: 'This is a test note created via API'
      }
    });
    console.log(`   Status: ${postResponse.status}`);
    console.log(`   Response: ${JSON.stringify(postResponse.data, null, 2)}\n`);

    // Test 5: Test with insufficient scope (read token for write operation)
    console.log('5. Testing POST /notes with read-only token (should fail)...');
    const readOnlyToken = TestJWTGenerator.generateAccessToken('charlie', ['notes:read']);
    const insufficientScopeResponse = await makeRequest('/notes', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${readOnlyToken}`
      },
      body: {
        title: 'Should Fail',
        content: 'This should fail due to insufficient scope'
      }
    });
    console.log(`   Status: ${insufficientScopeResponse.status}`);
    console.log(`   Response: ${JSON.stringify(insufficientScopeResponse.data, null, 2)}\n`);

    console.log('✅ API tests completed!');

  } catch (error) {
    console.error('❌ Test failed:', error);
  }
}

// Run tests if called directly
if (require.main === module) {
  runTests();
}

module.exports = { makeRequest, runTests };
#!/usr/bin/env node

/**
 * Comprehensive Resource Server Test Suite
 * 
 * Tests all key OAuth 2.0 scenarios:
 * - Authentication (valid/invalid tokens)
 * - Authorization (scope-based access control) 
 * - Error handling (expired tokens, wrong issuer/audience)
 * - CRUD operations with proper user isolation
 */

const { makeRequest } = require('./test-api.js');
const { TestJWTGenerator, TestScenarios } = require('./test-jwt.js');

// Test results tracking
let testsPassed = 0;
let testsFailed = 0;

/**
 * Test helper function
 */
async function runTest(testName, testFunction) {
  try {
    console.log(`\n🧪 ${testName}`);
    await testFunction();
    console.log(`   ✅ PASSED`);
    testsPassed++;
  } catch (error) {
    console.log(`   ❌ FAILED: ${error.message}`);
    testsFailed++;
  }
}

/**
 * Assert helper function
 */
function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

/**
 * Main test suite
 */
async function runComprehensiveTests() {
  console.log('🚀 Comprehensive Resource Server Test Suite');
  console.log('============================================\n');

  // Generate test tokens
  const basicTokens = TestScenarios.basicCRUDTokens();
  const errorTokens = TestScenarios.errorTestingTokens();

  // Test 1: Health Endpoint (Unauthenticated)
  await runTest('Health endpoint should work without authentication', async () => {
    const response = await makeRequest('/health');
    assert(response.status === 200, `Expected 200, got ${response.status}`);
    assert(response.data.status === 'healthy', 'Health status should be healthy');
    assert(response.data.service === 'notes-resource-server', 'Service name should match');
  });

  // Test 2: Authentication Required
  await runTest('Notes endpoint should require authentication', async () => {
    const response = await makeRequest('/notes');
    assert(response.status === 401, `Expected 401, got ${response.status}`);
    assert(response.data.error === 'invalid_request', 'Should return invalid_request error');
  });

  // Test 3: Valid Token Authentication
  await runTest('Valid token should allow access', async () => {
    const response = await makeRequest('/notes', {
      headers: { 'Authorization': `Bearer ${basicTokens.readOnlyToken}` }
    });
    assert(response.status === 200, `Expected 200, got ${response.status}`);
    assert(Array.isArray(response.data.data), 'Should return data array');
  });

  // Test 4: Scope Authorization - Read Access
  await runTest('Read token should allow GET /notes', async () => {
    const response = await makeRequest('/notes', {
      headers: { 'Authorization': `Bearer ${basicTokens.readOnlyToken}` }
    });
    assert(response.status === 200, `Expected 200, got ${response.status}`);
  });

  // Test 5: Scope Authorization - Write Denial
  await runTest('Read token should deny POST /notes', async () => {
    const response = await makeRequest('/notes', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${basicTokens.readOnlyToken}` },
      body: { title: 'Test', content: 'Should fail' }
    });
    assert(response.status === 403, `Expected 403, got ${response.status}`);
    assert(response.data.error === 'insufficient_scope', 'Should return insufficient_scope error');
  });

  // Test 6: Scope Authorization - Write Access
  await runTest('Write token should allow POST /notes', async () => {
    const response = await makeRequest('/notes', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${basicTokens.writeOnlyToken}` },
      body: { title: 'Test Note', content: 'Created by write token' }
    });
    assert(response.status === 201, `Expected 201, got ${response.status}`);
    assert(response.data.data.title === 'Test Note', 'Should return created note');
    assert(response.data.data.userId === 'bob', 'Should be associated with correct user');
  });

  // Test 7: Full Access Token
  await runTest('Full access token should allow all operations', async () => {
    // Create a note
    const createResponse = await makeRequest('/notes', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${basicTokens.fullAccessToken}` },
      body: { title: 'Admin Note', content: 'Created by admin' }
    });
    assert(createResponse.status === 201, 'Should create note');
    
    const noteId = createResponse.data.data.id;
    
    // Read the note
    const readResponse = await makeRequest(`/notes/${noteId}`, {
      headers: { 'Authorization': `Bearer ${basicTokens.fullAccessToken}` }
    });
    assert(readResponse.status === 200, 'Should read note');
    assert(readResponse.data.data.title === 'Admin Note', 'Should return correct note');
  });

  // Test 8: User Isolation and Scope Validation
  await runTest('Write-only token should not be able to read notes', async () => {
    // Get notes for alice (read token user) - should work
    const aliceResponse = await makeRequest('/notes', {
      headers: { 'Authorization': `Bearer ${basicTokens.readOnlyToken}` }
    });
    
    // Get notes for bob (write token user) - should fail (no notes:read scope)
    const bobResponse = await makeRequest('/notes', {
      headers: { 'Authorization': `Bearer ${basicTokens.writeOnlyToken}` }
    });
    
    // Alice should be able to read (has notes:read scope)
    assert(aliceResponse.status === 200, 'Alice should be able to read notes');
    
    // Bob should be denied (only has notes:write, needs notes:read for GET)
    assert(bobResponse.status === 403, `Expected 403, got ${bobResponse.status}`);
    assert(bobResponse.data.error === 'insufficient_scope', 'Should return insufficient_scope error');
  });

  // Test 9: No Scopes Token
  await runTest('Token with no scopes should be denied access', async () => {
    const response = await makeRequest('/notes', {
      headers: { 'Authorization': `Bearer ${basicTokens.noScopesToken}` }
    });
    assert(response.status === 403, `Expected 403, got ${response.status}`);
    assert(response.data.error === 'insufficient_scope', 'Should return insufficient_scope error');
  });

  // Test 10: Expired Token
  await runTest('Expired token should be rejected', async () => {
    const response = await makeRequest('/notes', {
      headers: { 'Authorization': `Bearer ${errorTokens.expiredToken}` }
    });
    assert(response.status === 401, `Expected 401, got ${response.status}`);
    assert(response.data.error === 'invalid_token', 'Should return invalid_token error');
    assert(response.data.error_description.includes('expired'), 'Should mention token is expired');
  });

  // Test 11: Invalid Signature
  await runTest('Token with invalid signature should be rejected', async () => {
    const response = await makeRequest('/notes', {
      headers: { 'Authorization': `Bearer ${errorTokens.invalidSignatureToken}` }
    });
    assert(response.status === 401, `Expected 401, got ${response.status}`);
    assert(response.data.error === 'invalid_token', 'Should return invalid_token error');
  });

  // Test 12: Wrong Issuer
  await runTest('Token with wrong issuer should be rejected', async () => {
    const response = await makeRequest('/notes', {
      headers: { 'Authorization': `Bearer ${errorTokens.wrongIssuerToken}` }
    });
    assert(response.status === 401, `Expected 401, got ${response.status}`);
    assert(response.data.error === 'invalid_token', 'Should return invalid_token error');
  });

  // Test 13: Wrong Audience
  await runTest('Token with wrong audience should be rejected', async () => {
    const response = await makeRequest('/notes', {
      headers: { 'Authorization': `Bearer ${errorTokens.wrongAudienceToken}` }
    });
    assert(response.status === 401, `Expected 401, got ${response.status}`);
    assert(response.data.error === 'invalid_token', 'Should return invalid_token error');
  });

  // Test 14: Malformed Authorization Header
  await runTest('Malformed Authorization header should be rejected', async () => {
    const response = await makeRequest('/notes', {
      headers: { 'Authorization': 'NotBearer token' }
    });
    assert(response.status === 401, `Expected 401, got ${response.status}`);
    assert(response.data.error === 'invalid_request', 'Should return invalid_request error');
  });

  // Test 15: CRUD Operations
  await runTest('Full CRUD operations should work with proper scopes', async () => {
    const fullToken = basicTokens.fullAccessToken;
    
    // CREATE
    const createResponse = await makeRequest('/notes', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${fullToken}` },
      body: { title: 'CRUD Test', content: 'Testing CRUD operations' }
    });
    assert(createResponse.status === 201, 'Should create note');
    const noteId = createResponse.data.data.id;
    
    // READ
    const readResponse = await makeRequest(`/notes/${noteId}`, {
      headers: { 'Authorization': `Bearer ${fullToken}` }
    });
    assert(readResponse.status === 200, 'Should read note');
    assert(readResponse.data.data.title === 'CRUD Test', 'Should return correct note');
    
    // UPDATE
    const updateResponse = await makeRequest(`/notes/${noteId}`, {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${fullToken}` },
      body: { title: 'CRUD Test Updated', content: 'Updated content' }
    });
    assert(updateResponse.status === 200, 'Should update note');
    assert(updateResponse.data.data.title === 'CRUD Test Updated', 'Should return updated note');
    
    // DELETE
    const deleteResponse = await makeRequest(`/notes/${noteId}`, {
      method: 'DELETE',
      headers: { 'Authorization': `Bearer ${fullToken}` }
    });
    assert(deleteResponse.status === 204, 'Should delete note with 204 No Content');
    
    // Verify deletion
    const verifyResponse = await makeRequest(`/notes/${noteId}`, {
      headers: { 'Authorization': `Bearer ${fullToken}` }
    });
    assert(verifyResponse.status === 404, 'Note should not be found after deletion');
  });

  // Print results
  console.log('\n===========================================');
  console.log('📊 TEST RESULTS');
  console.log('===========================================');
  console.log(`✅ Passed: ${testsPassed}`);
  console.log(`❌ Failed: ${testsFailed}`);
  console.log(`📈 Success Rate: ${Math.round((testsPassed / (testsPassed + testsFailed)) * 100)}%`);
  
  if (testsFailed === 0) {
    console.log('\n🎉 All tests passed! Resource server is working correctly.');
    console.log('\n✅ OAuth 2.0 Implementation Validated:');
    console.log('   • JWT Bearer token authentication ✓');
    console.log('   • Scope-based authorization ✓');
    console.log('   • User isolation ✓');
    console.log('   • Error handling ✓');
    console.log('   • CRUD operations ✓');
    console.log('   • Security validations ✓');
  } else {
    console.log(`\n⚠️  ${testsFailed} test(s) failed. Please review the failures above.`);
    process.exit(1);
  }
}

// Run tests if called directly
if (require.main === module) {
  runComprehensiveTests();
}

module.exports = { runComprehensiveTests };
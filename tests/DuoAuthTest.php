<?php
/**
 * Duo Auth Plugin Tests
 * 
 * Includes:
 * - Basic plugin tests
 * - Security tests for back-button bypass vulnerability (CVE-2025-XXXXX)
 */

use PHPUnit\Framework\TestCase;

class DuoAuthTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();
        DuoAuthTestHelper::reset();
    }
    
    protected function tearDown(): void
    {
        DuoAuthTestHelper::reset();
        parent::tearDown();
    }
    
    // =========================================================================
    // BASIC PLUGIN TESTS
    // =========================================================================
    
    public function testPluginClassExists()
    {
        $this->assertTrue(class_exists('duo_auth'));
    }

    public function testPluginInitialization()
    {
        $api = rcube::get_instance();
        $plugin = new duo_auth($api);

        $this->assertInstanceOf('duo_auth', $plugin);
        $this->assertInstanceOf('rcube_plugin', $plugin);
    }
    
    public function testRequiredMethodsExist()
    {
        $required_methods = ['init', 'login_after', 'startup', 'logout_after', 'callback_handler'];
        
        foreach ($required_methods as $method) {
            $this->assertTrue(
                method_exists('duo_auth', $method),
                "Missing required method: $method"
            );
        }
    }
    
    // =========================================================================
    // BACK-BUTTON BYPASS SECURITY TESTS (CVE-2025-XXXXX)
    // =========================================================================
    
    /**
     * @test
     * Scenario: User redirected to Duo, presses back button without completing 2FA
     * Expected: Session killed, redirected to login with error
     */
    public function testBackButtonBypassIsBlocked()
    {
        // Setup: Simulate state after login_after redirected to Duo
        $rc = DuoAuthTestHelper::configure([
            'task' => 'mail',
            'action' => '',
            'session' => [
                'duo_state' => 'abc123state',
                'duo_user' => 'julia',
                'duo_ip' => '192.168.1.100',
                'duo_timestamp' => time(),
                // NOTE: duo_authenticated is NOT set - this is the vulnerability!
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        // Execute: Call startup (simulating back button navigation)
        try {
            $plugin->startup(['task' => 'mail']);
            $this->fail('Expected redirect exception was not thrown');
        } catch (DuoAuthTestRedirectException $e) {
            // Verify redirect to login
            $this->assertIsArray($rc->output->redirected_to);
            $this->assertEquals('login', $rc->output->redirected_to['_task']);
        }
        
        // Verify session was killed
        $this->assertTrue($rc->killed_session);
        
        // Verify error message was shown
        $messages = $rc->output->messages;
        $this->assertNotEmpty($messages);
        $this->assertEquals('error', $messages[0]['type']);
        $this->assertStringContainsString('not completed', $messages[0]['message']);
    }
    
    /**
     * @test
     * Scenario: User properly completed Duo authentication
     * Expected: Normal access allowed, no redirect
     */
    public function testCompletedDuoAuthAllowsAccess()
    {
        $rc = DuoAuthTestHelper::configure([
            'task' => 'mail',
            'action' => '',
            'session' => [
                'duo_authenticated' => [
                    'username' => 'julia',
                    'method' => 'duo_push',
                    'timestamp' => time(),
                    'ip' => '192.168.1.100'
                ],
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        // Should NOT throw redirect exception
        $result = $plugin->startup(['task' => 'mail']);
        
        // Should pass through normally
        $this->assertIsArray($result);
        $this->assertFalse($rc->killed_session);
    }
    
    /**
     * @test
     * Scenario: Duo callback action in progress
     * Expected: Not blocked, callback should be able to complete
     */
    public function testDuoCallbackIsNotBlocked()
    {
        $rc = DuoAuthTestHelper::configure([
            'task' => 'login',
            'action' => 'plugin.duo_callback',
            'session' => [
                // Pending state - would normally be blocked
                'duo_state' => 'abc123state',
                'duo_user' => 'julia',
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        // Should NOT throw redirect exception
        $result = $plugin->startup(['task' => 'login', 'action' => 'plugin.duo_callback']);
        
        $this->assertIsArray($result);
        $this->assertFalse($rc->killed_session);
    }
    
    /**
     * @test
     * Scenario: Login page itself
     * Expected: Always accessible
     */
    public function testLoginPageIsAccessible()
    {
        $rc = DuoAuthTestHelper::configure([
            'task' => 'login',
            'action' => '',
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        $result = $plugin->startup(['task' => 'login']);
        
        $this->assertIsArray($result);
        $this->assertFalse($rc->killed_session);
    }
    
    /**
     * @test
     * Scenario: User in global bypass list presses back button
     * Expected: Allowed through (they don't need Duo anyway)
     */
    public function testBypassUserNotBlockedOnBackButton()
    {
        $rc = DuoAuthTestHelper::configure([
            'task' => 'mail',
            'action' => '',
            'user' => ['id' => 1, 'username' => 'julia'],
            'config' => [
                'duo_bypass_users' => ['julia'],
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        // Should pass through - user is bypassed
        $result = $plugin->startup(['task' => 'mail']);
        
        $this->assertIsArray($result);
        $this->assertFalse($rc->killed_session);
    }
    
    /**
     * @test
     * Scenario: IP in global bypass list
     * Expected: Allowed through
     */
    public function testBypassIpNotBlockedOnBackButton()
    {
        $rc = DuoAuthTestHelper::configure([
            'task' => 'mail',
            'action' => '',
            'user' => ['id' => 1, 'username' => 'testuser'],
            'remote_addr' => '10.0.0.50',
            'config' => [
                'duo_bypass_ips' => ['10.0.0.0/24'],
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        $result = $plugin->startup(['task' => 'mail']);
        
        $this->assertIsArray($result);
        $this->assertFalse($rc->killed_session);
    }
    
    /**
     * @test
     * Scenario: Conditional bypass (user + IP combination)
     * Expected: Allowed through
     */
    public function testConditionalBypassAllowsAccess()
    {
        $rc = DuoAuthTestHelper::configure([
            'task' => 'mail',
            'action' => '',
            'user' => ['id' => 1, 'username' => 'admin'],
            'remote_addr' => '192.168.1.1',
            'config' => [
                'duo_bypass_rules' => [
                    'admin' => ['192.168.1.0/24'],
                ],
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        $result = $plugin->startup(['task' => 'mail']);
        
        $this->assertIsArray($result);
        $this->assertFalse($rc->killed_session);
    }
    
    /**
     * @test
     * Scenario: Duo disabled globally
     * Expected: No enforcement at all
     */
    public function testDuoDisabledAllowsAccess()
    {
        $rc = DuoAuthTestHelper::configure([
            'task' => 'mail',
            'action' => '',
            'user' => ['id' => 1, 'username' => 'testuser'],
            'config' => [
                'duo_enabled' => false,
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        $result = $plugin->startup(['task' => 'mail']);
        
        $this->assertIsArray($result);
        $this->assertFalse($rc->killed_session);
    }
    
    /**
     * @test
     * Scenario: Expired Duo session (timeout)
     * Expected: Treated as not authenticated, must re-auth
     */
    public function testExpiredDuoSessionRequiresReauth()
    {
        $rc = DuoAuthTestHelper::configure([
            'task' => 'mail',
            'action' => '',
            'user' => ['id' => 1, 'username' => 'testuser'],
            'session' => [
                'duo_authenticated' => [
                    'username' => 'testuser',
                    'method' => 'duo_push',
                    'timestamp' => time() - 1000, // Expired (default timeout is 900)
                    'ip' => '192.168.1.100'
                ],
            ],
            'config' => [
                'duo_session_timeout' => 900,
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        // Session is expired, so user should be blocked
        try {
            $plugin->startup(['task' => 'mail']);
            $this->fail('Expected redirect exception for expired session');
        } catch (DuoAuthTestRedirectException $e) {
            $this->assertEquals('login', $rc->output->redirected_to['_task']);
        }
        
        $this->assertTrue($rc->killed_session);
    }
    
    // =========================================================================
    // HELPER METHOD TESTS
    // =========================================================================
    
    /**
     * @test
     * is_duo_auth_pending() returns true when state exists but not authenticated
     */
    public function testIsDuoAuthPendingReturnsTrueWhenPending()
    {
        $rc = DuoAuthTestHelper::configure([
            'session' => [
                'duo_state' => 'some_state',
                'duo_user' => 'testuser',
                // duo_authenticated NOT set
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        $reflection = new ReflectionClass($plugin);
        $method = $reflection->getMethod('is_duo_auth_pending');
        $method->setAccessible(true);
        
        $this->assertTrue($method->invoke($plugin));
    }
    
    /**
     * @test
     * is_duo_auth_pending() returns false when authenticated
     */
    public function testIsDuoAuthPendingReturnsFalseWhenAuthenticated()
    {
        $rc = DuoAuthTestHelper::configure([
            'session' => [
                'duo_state' => 'some_state',
                'duo_user' => 'testuser',
                'duo_authenticated' => [
                    'username' => 'testuser',
                    'method' => 'duo_push',
                    'timestamp' => time()
                ],
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        $reflection = new ReflectionClass($plugin);
        $method = $reflection->getMethod('is_duo_auth_pending');
        $method->setAccessible(true);
        
        $this->assertFalse($method->invoke($plugin));
    }
    
    /**
     * @test
     * is_duo_auth_pending() returns false when no state exists
     */
    public function testIsDuoAuthPendingReturnsFalseWhenNoState()
    {
        $rc = DuoAuthTestHelper::configure([
            'session' => [], // Empty session
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        $reflection = new ReflectionClass($plugin);
        $method = $reflection->getMethod('is_duo_auth_pending');
        $method->setAccessible(true);
        
        $this->assertFalse($method->invoke($plugin));
    }
    
    /**
     * @test
     * Verify cleanup_duo_session removes all pending state
     */
    public function testCleanupDuoSessionRemovesAllState()
    {
        $rc = DuoAuthTestHelper::configure([
            'session' => [
                'duo_state' => 'test_state',
                'duo_user' => 'testuser',
                'duo_ip' => '192.168.1.100',
                'duo_timestamp' => time(),
            ],
        ]);
        
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        $reflection = new ReflectionClass($plugin);
        $method = $reflection->getMethod('cleanup_duo_session');
        $method->setAccessible(true);
        $method->invoke($plugin);
        
        $this->assertArrayNotHasKey('duo_state', $_SESSION);
        $this->assertArrayNotHasKey('duo_user', $_SESSION);
        $this->assertArrayNotHasKey('duo_ip', $_SESSION);
        $this->assertArrayNotHasKey('duo_timestamp', $_SESSION);
    }
    
    // =========================================================================
    // IP WHITELIST TESTS
    // =========================================================================
    
    /**
     * @test
     * IPv4 CIDR matching
     */
    public function testIpv4CidrMatching()
    {
        $rc = DuoAuthTestHelper::configure();
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        $reflection = new ReflectionClass($plugin);
        $method = $reflection->getMethod('is_ip_whitelisted');
        $method->setAccessible(true);
        
        // Test match
        $this->assertTrue($method->invoke($plugin, '192.168.1.50', ['192.168.1.0/24']));
        
        // Test no match
        $this->assertFalse($method->invoke($plugin, '192.168.2.50', ['192.168.1.0/24']));
        
        // Test exact match
        $this->assertTrue($method->invoke($plugin, '10.0.0.1', ['10.0.0.1']));
    }
    
    /**
     * @test
     * IPv6 CIDR matching
     */
    public function testIpv6CidrMatching()
    {
        $rc = DuoAuthTestHelper::configure();
        $plugin = new duo_auth($rc);
        $plugin->init();
        
        $reflection = new ReflectionClass($plugin);
        $method = $reflection->getMethod('is_ip_whitelisted');
        $method->setAccessible(true);
        
        // Test match
        $this->assertTrue($method->invoke($plugin, '2001:db8::1', ['2001:db8::/32']));
        
        // Test no match
        $this->assertFalse($method->invoke($plugin, '2001:db9::1', ['2001:db8::/32']));
        
        // Test localhost
        $this->assertTrue($method->invoke($plugin, '::1', ['::1']));
    }
}

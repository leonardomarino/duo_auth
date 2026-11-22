<?php
/**
 * Regression tests for bypass hardening:
 * proxy header spoofing, default bypass IPs, malformed CIDR,
 * username canonicalization / _url injection, login-task action guard.
 */

use PHPUnit\Framework\TestCase;

class SecurityHardeningTest extends TestCase
{
    protected function setUp(): void
    {
        DuoAuthTestHelper::reset();
    }

    protected function tearDown(): void
    {
        DuoAuthTestHelper::reset();
        unset($_SERVER['HTTP_X_FORWARDED_FOR'], $_SERVER['HTTP_CF_CONNECTING_IP'], $_SERVER['HTTP_X_REAL_IP']);
    }

    private function plugin(array $options = []): duo_auth
    {
        $rc = DuoAuthTestHelper::configure($options);
        $plugin = new duo_auth($rc);
        $plugin->init();
        return $plugin;
    }

    private function call(duo_auth $plugin, string $method, ...$args)
    {
        $m = new ReflectionMethod($plugin, $method);
        $m->setAccessible(true);
        return $m->invoke($plugin, ...$args);
    }

    private function assertStartupBlocks(duo_auth $plugin, array $args = []): void
    {
        try {
            $plugin->startup($args);
            $this->fail('Expected startup() to block the request');
        } catch (DuoAuthTestRedirectException $e) {
            $this->assertSame('login', $e->url['_task']);
        }
        $this->assertTrue(rcube::get_instance()->killed_session);
    }

    // =========================================================================
    // 1. Proxy header handling
    // =========================================================================

    public function testProxyHeadersIgnoredWhenTrustedProxiesEmpty()
    {
        $plugin = $this->plugin([
            'remote_addr' => '198.51.100.7',
            'config' => ['duo_trust_proxy_headers' => true, 'duo_trusted_proxies' => []],
        ]);
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '127.0.0.1';

        $this->assertSame('198.51.100.7', $this->call($plugin, 'get_client_ip'));
    }

    public function testProxyHeadersIgnoredFromUntrustedPeer()
    {
        $plugin = $this->plugin([
            'remote_addr' => '198.51.100.7',
            'config' => ['duo_trust_proxy_headers' => true, 'duo_trusted_proxies' => ['10.0.0.1']],
        ]);
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '127.0.0.1';

        $this->assertSame('198.51.100.7', $this->call($plugin, 'get_client_ip'));
    }

    public function testSpoofedLeftmostForwardedForIsIgnored()
    {
        // Client sends "X-Forwarded-For: 127.0.0.1"; proxy appends the real address
        $plugin = $this->plugin([
            'remote_addr' => '10.0.0.1',
            'config' => ['duo_trust_proxy_headers' => true, 'duo_trusted_proxies' => ['10.0.0.1']],
        ]);
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '127.0.0.1, 198.51.100.7';

        $this->assertSame('198.51.100.7', $this->call($plugin, 'get_client_ip'));
    }

    public function testTrustedHopsAreSkippedRightToLeft()
    {
        $plugin = $this->plugin([
            'remote_addr' => '10.0.0.1',
            'config' => ['duo_trust_proxy_headers' => true, 'duo_trusted_proxies' => ['10.0.0.0/24']],
        ]);
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '198.51.100.7, 10.0.0.2';

        $this->assertSame('198.51.100.7', $this->call($plugin, 'get_client_ip'));
    }

    public function testOnlyConfiguredHeaderIsRead()
    {
        $plugin = $this->plugin([
            'remote_addr' => '10.0.0.1',
            'config' => ['duo_trust_proxy_headers' => true, 'duo_trusted_proxies' => ['10.0.0.1']],
        ]);
        $_SERVER['HTTP_CF_CONNECTING_IP'] = '127.0.0.1';

        $this->assertSame('10.0.0.1', $this->call($plugin, 'get_client_ip'));
    }

    public function testCustomHeaderNameIsSupported()
    {
        $plugin = $this->plugin([
            'remote_addr' => '10.0.0.1',
            'config' => [
                'duo_trust_proxy_headers' => true,
                'duo_trusted_proxies' => ['10.0.0.1'],
                'duo_proxy_header' => 'X-Real-IP',
            ],
        ]);
        $_SERVER['HTTP_X_REAL_IP'] = '198.51.100.7';

        $this->assertSame('198.51.100.7', $this->call($plugin, 'get_client_ip'));
    }

    public function testInvalidHeaderEntryStopsAtLastTrustedHop()
    {
        $plugin = $this->plugin([
            'remote_addr' => '10.0.0.1',
            'config' => ['duo_trust_proxy_headers' => true, 'duo_trusted_proxies' => ['10.0.0.1']],
        ]);
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '127.0.0.1, not-an-ip';

        $this->assertSame('10.0.0.1', $this->call($plugin, 'get_client_ip'));
    }

    public function testSpoofedForwardedForDoesNotBypassDuo()
    {
        $plugin = $this->plugin([
            'task' => 'mail',
            'user' => ['id' => 1, 'username' => 'victim'],
            'remote_addr' => '10.0.0.1',
            'config' => [
                'duo_bypass_ips' => ['127.0.0.1'],
                'duo_trust_proxy_headers' => true,
                'duo_trusted_proxies' => ['10.0.0.1'],
            ],
        ]);
        $_SERVER['HTTP_X_FORWARDED_FOR'] = '127.0.0.1, 198.51.100.7';

        $this->assertStartupBlocks($plugin);
    }

    // =========================================================================
    // 2. Default config
    // =========================================================================

    public function testDefaultConfigHasNoBypassIps()
    {
        $config = [];
        include __DIR__ . '/../config.inc.php.dist';

        $this->assertSame([], $config['duo_bypass_ips']);
    }

    // =========================================================================
    // 3. CIDR validation
    // =========================================================================

    public function testMalformedOrMatchAllCidrNeverMatches()
    {
        $plugin = $this->plugin();

        foreach (['10.0.0.0/', '10.0.0.0/abc', '10.0.0.0/-8', '10.0.0.0/8/1', '0.0.0.0/0'] as $range) {
            $this->assertFalse(
                $this->call($plugin, 'is_ip_whitelisted', '8.8.8.8', [$range]),
                "IPv4 range '$range' must not match"
            );
        }
        foreach (['::/', '::/x', '::/0'] as $range) {
            $this->assertFalse(
                $this->call($plugin, 'is_ip_whitelisted', '2001:db8::1', [$range]),
                "IPv6 range '$range' must not match"
            );
        }
    }

    public function testValidCidrStillMatches()
    {
        $plugin = $this->plugin();

        $this->assertTrue($this->call($plugin, 'is_ip_whitelisted', '10.1.2.3', ['10.0.0.0/8']));
        $this->assertTrue($this->call($plugin, 'is_ip_whitelisted', '2001:db8::1', ['2001:db8::/32']));
    }

    // =========================================================================
    // 4. Username source and canonicalization
    // =========================================================================

    public function testLoginAfterIgnoresUserInjectedViaUrlArgs()
    {
        // Roundcube builds login_after args from the client-supplied _url POST
        // field, so _url=user=bypassuser must not select the bypass list entry.
        $plugin = $this->plugin([
            'task' => 'login',
            'action' => 'login',
            'user' => ['id' => 1, 'username' => 'victim'],
            'config' => ['duo_bypass_users' => ['bypassuser']],
        ]);

        try {
            $plugin->login_after(['_task' => 'mail', 'user' => 'bypassuser', 'username' => 'bypassuser']);
            $this->fail('Expected Duo to be required for the real user');
        } catch (DuoAuthTestRedirectException $e) {
            // Redirect either to Duo or (no reachable Duo in tests) back to login
        }

        $this->assertArrayNotHasKey('duo_authenticated', $_SESSION);
        foreach (rcube::get_instance()->output->messages as $msg) {
            $this->assertNotSame('notice', $msg['type'], 'Bypass message must not be shown');
        }
    }

    public function testUsernameIsCanonicalized()
    {
        $plugin = $this->plugin(['user' => ['id' => 1, 'username' => '  John@Example.COM ']]);

        $this->assertSame('john@example.com', $this->call($plugin, 'get_username'));
    }

    public function testUsernameFallsBackToSessionNotPost()
    {
        $plugin = $this->plugin(['session' => ['username' => 'Alice']]);
        rcube_utils::set_input_value('_user', 'mallory');

        $this->assertSame('alice', $this->call($plugin, 'get_username'));
    }

    public function testBypassUserMatchIsCaseInsensitive()
    {
        $plugin = $this->plugin([
            'task' => 'mail',
            'user' => ['id' => 1, 'username' => 'Julia'],
            'config' => ['duo_bypass_users' => ['JULIA']],
        ]);

        $this->assertIsArray($plugin->startup([]));
        $this->assertFalse(rcube::get_instance()->killed_session);
    }

    public function testBypassRuleMatchIsCaseInsensitive()
    {
        $plugin = $this->plugin([
            'task' => 'mail',
            'user' => ['id' => 1, 'username' => 'admin'],
            'remote_addr' => '192.168.1.5',
            'config' => ['duo_bypass_rules' => ['Admin' => ['192.168.1.0/24']]],
        ]);

        $this->assertIsArray($plugin->startup([]));
        $this->assertFalse(rcube::get_instance()->killed_session);
    }

    // =========================================================================
    // 5. Login-task actions
    // =========================================================================

    public function testOtherLoginTaskActionBlockedWithoutDuo()
    {
        $plugin = $this->plugin([
            'task' => 'login',
            'action' => 'plugin.other_plugin_action',
            'user' => ['id' => 1, 'username' => 'victim'],
        ]);

        $this->assertStartupBlocks($plugin);
    }

    public function testOtherLoginTaskActionBlockedWhilePending()
    {
        $plugin = $this->plugin([
            'task' => 'login',
            'action' => 'plugin.other_plugin_action',
            'user' => ['id' => 1, 'username' => 'victim'],
            'session' => ['duo_state' => 'state', 'duo_user' => 'victim', 'duo_timestamp' => time()],
        ]);

        $this->assertStartupBlocks($plugin);
    }

    public function testOtherLoginTaskActionAllowedForAnonymousVisitor()
    {
        $plugin = $this->plugin(['task' => 'login', 'action' => 'plugin.other_plugin_action']);

        $this->assertIsArray($plugin->startup([]));
        $this->assertFalse(rcube::get_instance()->killed_session);
    }

    // =========================================================================
    // 6. Duo approval bound to user; optional callback IP check
    // =========================================================================

    public function testDuoApprovalForAnotherUserIsRejected()
    {
        $plugin = $this->plugin([
            'task' => 'mail',
            'user' => ['id' => 1, 'username' => 'victim'],
            'session' => [
                'duo_authenticated' => ['username' => 'attacker', 'method' => 'duo_push', 'timestamp' => time()],
            ],
        ]);

        $this->assertStartupBlocks($plugin);
    }

    public function testDuoApprovalMatchingUserIsAccepted()
    {
        $plugin = $this->plugin([
            'task' => 'mail',
            'user' => ['id' => 1, 'username' => 'Victim'],
            'session' => [
                'duo_authenticated' => ['username' => 'victim', 'method' => 'duo_push', 'timestamp' => time()],
            ],
        ]);

        $this->assertIsArray($plugin->startup([]));
        $this->assertFalse(rcube::get_instance()->killed_session);
    }

    private function callbackSession(string $ip): array
    {
        return [
            'duo_state' => 'state123',
            'duo_user' => 'victim',
            'duo_ip' => $ip,
            'duo_timestamp' => time(),
        ];
    }

    public function testCallbackFromDifferentIpRejectedWhenEnabled()
    {
        $plugin = $this->plugin([
            'task' => 'login',
            'action' => 'plugin.duo_callback',
            'remote_addr' => '203.0.113.9',
            'session' => $this->callbackSession('198.51.100.7'),
            'config' => ['duo_callback_ip_check' => true],
        ]);
        rcube_utils::set_input_value('duo_code', 'code');
        rcube_utils::set_input_value('state', 'state123');

        try {
            $plugin->callback_handler();
            $this->fail('Expected callback to be rejected');
        } catch (DuoAuthTestRedirectException $e) {
            $this->assertSame('login', $e->url['_task']);
        }
        $this->assertStringContainsString('Network address changed', rcube::get_instance()->output->messages[0]['message']);
    }

    public function testCallbackIpCheckOffByDefault()
    {
        $plugin = $this->plugin([
            'task' => 'login',
            'action' => 'plugin.duo_callback',
            'remote_addr' => '203.0.113.9',
            'session' => $this->callbackSession('198.51.100.7'),
        ]);
        rcube_utils::set_input_value('duo_code', 'code');
        rcube_utils::set_input_value('state', 'state123');

        try {
            $plugin->callback_handler();
        } catch (DuoAuthTestRedirectException $e) {
            // Fails later at the Duo code exchange (no Duo in tests), not on IP
        }
        foreach (rcube::get_instance()->output->messages as $msg) {
            $this->assertStringNotContainsString('Network address changed', $msg['message']);
        }
    }

    // =========================================================================
    // 7-9. Config template and installer
    // =========================================================================

    public function testConfigTemplateWarnsAgainstFailOpenAndDefaultsSecure()
    {
        $config = [];
        include __DIR__ . '/../config.inc.php.dist';
        $text = file_get_contents(__DIR__ . '/../config.inc.php.dist');

        $this->assertSame('secure', $config['duo_failmode']);
        $this->assertStringContainsString('never in production', $text);
        $this->assertFalse($config['duo_callback_ip_check']);
    }

    public function testInstallerDoesNotCreateWebAccessibleLogsOrWorldReadableConfig()
    {
        $src = file_get_contents(__DIR__ . '/../bin/install.php');

        $this->assertStringNotContainsString("mkdir('logs'", $src);
        $this->assertStringNotContainsString('logs/duo_auth.log', str_replace('<roundcube>/logs/duo_auth.log', '', $src));
        $this->assertStringNotContainsString('0644', $src);
        $this->assertStringContainsString('chmod($config_file, 0640)', $src);
    }

    public function testLoginFormPostIsNotBlocked()
    {
        $plugin = $this->plugin([
            'task' => 'login',
            'action' => 'login',
            'user' => ['id' => 1, 'username' => 'victim'],
        ]);

        $this->assertIsArray($plugin->startup([]));
        $this->assertFalse(rcube::get_instance()->killed_session);
    }
}

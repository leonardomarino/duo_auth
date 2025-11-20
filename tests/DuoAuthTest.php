<?php

use PHPUnit\Framework\TestCase;

class DuoAuthTest extends TestCase
{
    public function testPluginClassExists()
    {
        // Assert the class is defined (loaded via bootstrap)
        $this->assertTrue(class_exists('duo_auth'));
    }

    public function testPluginInitialization()
    {
        // Mock the API object required by the plugin constructor
        $api = rcube::get_instance();
        
        // Instantiate the plugin
        $plugin = new duo_auth($api);

        // Verify it is an instance of the plugin and the parent class
        $this->assertInstanceOf('duo_auth', $plugin);
        $this->assertInstanceOf('rcube_plugin', $plugin);
    }
}

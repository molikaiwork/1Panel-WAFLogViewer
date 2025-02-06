<?php
/**
 * 1panel-WAF数据查看接口API文件
 *
 * @author Juneha juneha@qq.com
 * @author molikaiwork
 * @version 1.1.0
 * @website https://blog.mo60.cn/
 * @website https://github.com/molikaiwork/1Panel-WAFLogViewer
 * @created 2024-08-19
 * @updated 2025-02-05
 */

error_reporting(0);
// error_reporting(E_ALL);
// ini_set('display_errors', 1);

header("Access-Control-Allow-Origin: *");
header("Access-Control-Allow-Methods: POST, GET, OPTIONS, DELETE");
header("Access-Control-Allow-Headers: X-Requested-With, Content-Type");
header("Access-Control-Allow-Credentials: true");
header("Access-Control-Max-Age: 86400");

class SQLite {
    private $connection;

    public function __construct($file) {
        try {
            $this->connection = new PDO('sqlite:' . $file);
            $this->connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
        } catch (PDOException $e) {
            exit(jsonResponse(['error' => 'Unable to connect to the database.']));
        }
    }

    public function __destruct() {
        $this->connection = null;
    }

    public function query($sql) {
        try {
            $stmt = $this->connection->query($sql);
            return $stmt;
        } catch (PDOException $e) {
            exit(jsonResponse(['error' => 'SQL query failed.']));
        }
    }

    public function getList($sql) {
        $stmt = $this->query($sql);
        return $stmt->fetchAll(PDO::FETCH_ASSOC);
    }

    public function execute($sql) {
        try {
            return $this->query($sql)->fetch();
        } catch (PDOException $e) {
            exit(jsonResponse(['error' => 'Execution of SQL failed.']));
        }
    }

    public function recordArray($sql) {
        return $this->query($sql)->fetchAll();
    }

    public function recordCount($sql) {
        return count($this->recordArray($sql));
    }

    public function recordLastID() {
        return $this->connection->lastInsertId();
    }
}

function jsonResponse($data) {
    header('Content-Type: application/json');
    echo json_encode($data, JSON_UNESCAPED_UNICODE);
    exit;
}

function doubleSingleQuotes($string) {
    return str_replace("'", "''", $string);
}

function getParameterValue($key, $default = '') {
    return isset($_GET[$key]) ? doubleSingleQuotes(trim($_GET[$key])) : $default;
}

function translateWAFParams($param) {
    $translations = [
        'urlDefense' => 'URL 规则',
        'urlHelper' => '禁止访问的 URL',
        'dirFilter' => '目录过滤',
        'sql' => 'SQL 注入',
        'xss' => 'XSS',
        'phpExec' => 'PHP 脚本执行',
        'oneWordTrojan' => '一句话木马',
        'appFilter' => '应用危险目录过滤',
        'webshell' => 'Webshell',
        'protocolFilter' => '协议过滤',
        'javaFileter' => 'Java 危险文件过滤',
        'scannerFilter' => '扫描器过滤',
        'escapeFilter' => '转义过滤',
        'customRule' => '自定义规则',
        'fileExt' => '文件上传限制',
        'fileExtHelper' => '禁止上传的文件扩展名',
        'fiveSeconds' => "5 秒验证",
        'acl' => "ACL",
        'captcha' => "人机验证",
        'uaBlack' => "User-Agent 黑名单",
        'urlBlockList' => "URL 黑名单",
        'ipBlack' => "IP 黑名单",
        'unknownWebsite' => "未授权域名访问",
        'geoRestrict' => "地区访问限制",
        'attackCount' => "攻击频率限制",
        'notFoundCount' => "404 频率限制",
        'defaultUaBlack' => "User-Agent 规则",
        'defaultUrlBlack' => "URL 规则",
        'defaultIpBlack' => "恶意 IP 组",
        'fileExtCheck' => "文件上传限制",
        'args' => "参数规则",
        'methodWhite' => "HTTP 规则",
        'cookie' => "Cookie 规则",
        'cc' => "访问频率限制",
        'header' => "Header 规则",
        'sqlInject' => "SQL 注入",
        'httpMethod' => "HTTP 方法过滤",
    ];

    return $translations[$param] ?? $param;
}

function buildInClause($data) {
    if (empty($data)) {
        return "IN ('')";
    }

    if (!is_array($data)) {
        $data = [$data];
    }

    $escaped_values = array_map(function ($value) {
        return "'" . doubleSingleQuotes($value) . "'";
    }, $data);

    return "IN (" . implode(', ', $escaped_values) . ")";
}

$rootPath = $_SERVER['DOCUMENT_ROOT'];
$onepwafPath = $rootPath . '/../../../db/1pwaf.db';
$req_logPath = $rootPath . '/../../../db/req_log.db';

if (!file_exists($onepwafPath)) {
    exit(jsonResponse(['error' => "1pwaf.db file does not exist!"]));
}

if (!file_exists($req_logPath)) {
    exit(jsonResponse(['error' => "req_log.db file does not exist!"]));
}

$onepwafDB = new SQLite($onepwafPath);
$req_logDB = new SQLite($req_logPath);

$action = $_GET['action'] ?? null;

switch ($action) {
    case 'wafstat':
        try {
            $wafData = $onepwafDB->getList("SELECT * FROM main.waf_stat ORDER BY id DESC LIMIT 1");
            exit(jsonResponse($wafData[0]));
        } catch (Exception $e) {
            exit(jsonResponse(['error' => 'Error fetching WAF stats.']));
        }
        break;

    case 'wafdays':
        try {
            $wafSQL = $onepwafDB->getList("
                SELECT *
                FROM main.waf_stat
                ORDER BY id DESC
                LIMIT 7;
            ");

            $wafData['data'] = array_reverse($wafSQL);

            exit(jsonResponse($wafData));
        } catch (Exception $e) {
            exit(jsonResponse(['error' => 'Error fetching WAF old stats.']));
        }
        break;
        
    
    case 'sitelist':
        try {
            $webList = $req_logDB->getList("SELECT DISTINCT website_key FROM main.req_logs WHERE website_key <> 'unknown' ORDER BY time DESC");
            exit(jsonResponse($webList));
        } catch (Exception $e) {
            exit(jsonResponse(['error' => 'Error fetching website list.']));
        }
        break;

    case 'log':
        $page = intval(getParameterValue('page', 1));
        $size = intval(getParameterValue('size', 10));
        $websiteKey = getParameterValue('website_key');
        $exec_rule = $_GET['exec_rule'] ?? null;
        $uri = getParameterValue('uri');
        $ip = getParameterValue('ip');
        $offset = ($page - 1) * $size;

        $conditions = [];
        if ($websiteKey) {
            $conditions[] = "website_key='{$websiteKey}'";
        }
        if ($exec_rule) {
            $conditions[] = "(exec_rule " . buildInClause($exec_rule) . " OR rule_type " . buildInClause($exec_rule) . ")";
        }
        if ($uri) {
            $conditions[] = "uri LIKE '%{$uri}%'";
        }
        if ($ip) {
            $conditions[] = "ip='{$ip}'";
        }

        $sql = "SELECT * FROM main.req_logs WHERE 1=1";
        if ($conditions) {
            $sql .= " AND " . implode(' AND ', $conditions);
        }

        try {
            $total = $req_logDB->recordCount($sql);
            $sql .= " ORDER BY time DESC LIMIT {$offset}, {$size}";
            $req_logData['data'] = $req_logDB->getList($sql);
            $req_logData['total'] = $total;

            foreach ($req_logData['data'] as &$log) {
                $log['rule_type'] = translateWAFParams($log['rule_type']);
                $log['exec_rule'] = translateWAFParams($log['exec_rule']);
            }

            exit(jsonResponse($req_logData));
        } catch (Exception $e) {
            exit(jsonResponse(['error' => 'Error fetching logs.']));
        }
        break;

    case 'block':
        $page = intval(getParameterValue('page', 1));
        $size = intval(getParameterValue('size', 10));
        $ip = getParameterValue('ip');
        $offset = ($page - 1) * $size;

        $conditions = [];

        if ($ip) {
            $conditions[] = "ip='{$ip}'";
        }

        $sql = "SELECT * FROM main.block_ips WHERE 1=1";
        if ($conditions) {
            $sql .= " AND " . implode(' AND ', $conditions);
        }

        try {
            $total = $req_logDB->recordCount($sql);
            $sql .= " ORDER BY create_date DESC LIMIT {$offset}, {$size}";
            $blockData['data'] = $req_logDB->getList($sql);
            $blockData['total'] = $total;

            foreach ($blockData['data'] as &$blockIp) {
                if ($blockIp['req_log_id']) {
                    $req_log_sql = "SELECT * FROM main.req_logs WHERE id = '{$blockIp['req_log_id']}'";
                    $req_log_data = $req_logDB->getList($req_log_sql);
                    if (!empty($req_log_data)) {
                        $blockIp['reqLog'] = $req_log_data[0];

                        $blockIp['reqLog']['rule_type'] = translateWAFParams($blockIp['reqLog']['rule_type']);
                        $blockIp['reqLog']['exec_rule'] = translateWAFParams($blockIp['reqLog']['exec_rule']);
                    } else {
                        $blockIp['reqLog'] = null;
                    }
                } else {
                    $blockIp['reqLog'] = null;
                }
            }

            exit(jsonResponse($blockData));
        } catch (Exception $e) {
            exit(jsonResponse(['error' => 'Error fetching block.']));
        }
        break;

    case 'clearlogs':
        try {
            $status = $req_logDB->query("DELETE FROM main.req_logs");
            exit(jsonResponse(['status' => $status ? 1 : 0]));
        } catch (Exception $e) {
            exit(jsonResponse(['error' => 'Error clearing logs.']));
        }
        break;
    
    case 'clearBlocklogs':
        try {
            $status = $req_logDB->query("DELETE FROM main.block_ips");
            exit(jsonResponse(['status' => $status ? 1 : 0]));
        } catch (Exception $e) {
            exit(jsonResponse(['error' => 'Error clearing block.']));
        }
        break;

    default:
        header("HTTP/1.1 404 Not Found");
        exit(jsonResponse(['error' => 'Invalid action.']));
        break;
}
?>

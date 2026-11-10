<?php
/**
 * 假登录页：只记录，不校验，不登录。
 *
 * 设计取舍（这几条决定了它是不是一个"负责任的"采集点）：
 *
 * 1. 不连数据库
 *    扫描器和爆破工具会往这个表单里灌 SQL 注入载荷。只要后端不碰数据库，
 *    这些载荷就只是文本，不会真的执行。这是"可采集"和"变成跳板"的分界线。
 *
 * 2. 口令不存明文
 *    收集别人的明文口令在伦理上站不住，也有实际风险（万一被泄露，
 *    你就是泄露者）。这里只存 SHA-256 的前 16 位，足够做词频统计
 *    （"123456" 这种高频弱口令的 hash 是固定的，一比对就能识别），
 *    又还原不出原文。
 *
 * 3. 永远返回"用户名或密码错误"
 *    不给攻击者任何区分信号，行为上跟真实登录失败一致。
 *
 * 4. 记录内容严格限定
 *    只记：时间、IP、UA、提交的账号、口令指纹、完整的原始请求参数。
 *    不记 Cookie（不含本站的），不记任何来源域之外的请求头。
 */

declare(strict_types=1);

const LOG_DIR   = '/var/log/login';
const LOG_FILE  = LOG_DIR . '/credential.log';

function client_ip(): string {
    // 不信任 X-Forwarded-For 的优先级，因为本机没挂 CDN，用它会被伪造。
    // 取 REMOTE_ADDR 才可靠；XFF 单独记一列备查。
    return $_SERVER['REMOTE_ADDR'] ?? '-';
}

function fp(string $pw): string {
    // 只保留前 16 位十六进制，用于比对，不可逆
    return substr(hash('sha256', $pw), 0, 16);
}

$user = isset($_POST['username']) ? (string)$_POST['username'] : '';
$pass = isset($_POST['password']) ? (string)$_POST['password'] : '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!is_dir(LOG_DIR)) {
        @mkdir(LOG_DIR, 0750, true);
    }

    $record = [
        'time'    => date('c'),
        'ip'      => client_ip(),
        'xff'     => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? '',
        'method'  => $_SERVER['REQUEST_METHOD'],
        'ua'      => $_SERVER['HTTP_USER_AGENT'] ?? '',
        'user'    => mb_substr($user, 0, 128),
        // 原文不落盘，只留指纹；长度保留下来，能看出攻击者是不是在试探长度
        'pass_fp' => fp($pass),
        'pass_len'=> strlen($pass),
        // 原始参数：攻击载荷（' OR 1=1 等）就在里面，这是最有价值的字段
        'raw'     => mb_substr(http_build_query($_POST), 0, 1024),
    ];

    // JSON Lines：一行一条，方便后续用任何语言流式解析，不会因为单行损坏丢整个文件
    $line = json_encode($record, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES) . "\n";

    // 用 LOCK_EX 防止并发写串行破坏行结构（爆破工具通常是并发请求）
    @file_put_contents(LOG_FILE, $line, FILE_APPEND | LOCK_EX);
}

// 无论成功失败，都返回同一个页面
http_response_code(401);
?>
<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>管理登录</title>
<style>
  body { font-family: -apple-system, "Microsoft YaHei", sans-serif; background: #f3f4f6;
         display: flex; align-items: center; justify-content: center; min-height: 100vh; margin: 0; }
  .box { background: #fff; padding: 40px; border-radius: 8px; width: 340px;
         box-shadow: 0 1px 3px rgba(0,0,0,.08); }
  h2 { font-size: 18px; margin: 0 0 24px; font-weight: 600; color: #1f2937; text-align: center; }
  label { display: block; font-size: 13px; color: #4b5563; margin-bottom: 6px; }
  input { width: 100%; padding: 10px 12px; border: 1px solid #d1d5db; border-radius: 6px;
          font-size: 14px; margin-bottom: 16px; box-sizing: border-box; }
  input:focus { outline: none; border-color: #2563eb; }
  button { width: 100%; padding: 11px; background: #2563eb; color: #fff; border: 0;
           border-radius: 6px; font-size: 14px; cursor: pointer; }
  .err { background: #fef2f2; color: #dc2626; font-size: 13px; padding: 10px;
         border-radius: 6px; margin-bottom: 16px; text-align: center; }
</style>
</head>
<body>
  <div class="box">
    <h2>管理后台登录</h2>
    <?php if ($_SERVER['REQUEST_METHOD'] === 'POST'): ?>
      <div class="err">用户名或密码错误</div>
    <?php endif; ?>
    <form method="POST" action="/admin/login.php">
      <label for="u">账号</label>
      <input id="u" name="username" type="text" autocomplete="off" required>
      <label for="p">密码</label>
      <input id="p" name="password" type="password" autocomplete="off" required>
      <button type="submit">登录</button>
    </form>
  </div>
</body>
</html>

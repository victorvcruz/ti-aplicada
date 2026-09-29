<?php
/**
 * NMS - Network Management System (PHP + SNMP via shell_exec)
 * Atividade TI Aplicada - Dashboard SNMP
 *
 * Requisitos no host: snmp-utils (snmpget, snmpwalk, snmpbulkwalk)
 *   sudo apt-get install -y snmp
 *
 * Uso: coloque este arquivo em /var/www/html/nms/index.php
 *      acesse: http://<IP-VM>/nms
 */

// ======================== CONFIGURAÇÃO ========================
$STATIONS = [
    ['host' => '10.2.168.242', 'label' => 'Estação Gerenciada 1'],
    ['host' => '10.2.169.29',  'label' => 'Estação Gerenciada 2'],
    ['host' => '10.2.169.37',  'label' => 'Estação Gerenciada 3'],
    ['host' => '10.2.168.68',  'label' => 'Estação Dev - Outro Grupo'],
    ['host' => '10.2.168.52',  'label' => 'Estação Dev - Outro Grupo'],
];

$COMMUNITY       = 'public';   // community string SNMP v2c
$SNMP_VERSION    = '2c';
$SNMP_TIMEOUT    = 2;          // segundos
$SNMP_RETRIES    = 1;
$REFRESH_SECONDS = 15;         // auto-refresh do dashboard
$STATE_FILE      = sys_get_temp_dir() . '/nms_state.json';  // cache p/ calcular taxa

// ======================== HELPERS SNMP ========================
function snmp_cmd(string $bin, string $host, string $community, string $oid, int $timeout, int $retries, string $ver = '2c'): string {
    $cmd = sprintf(
        '%s -v %s -c %s -t %d -r %d -Ovq -On %s %s 2>/dev/null',
        escapeshellcmd($bin),
        escapeshellarg($ver),
        escapeshellarg($community),
        $timeout,
        $retries,
        escapeshellarg($host),
        escapeshellarg($oid)
    );
    $out = shell_exec($cmd);
    return $out === null ? '' : trim($out);
}

function snmp_get(string $host, string $community, string $oid): string {
    global $SNMP_TIMEOUT, $SNMP_RETRIES, $SNMP_VERSION;
    return snmp_cmd('snmpget', $host, $community, $oid, $SNMP_TIMEOUT, $SNMP_RETRIES, $SNMP_VERSION);
}

/**
 * snmpwalk retornando array [oidCompleto => valor]
 * usa -Oqn para linhas no formato: ".1.3.6...  valor"
 */
function snmp_walk_table(string $host, string $community, string $baseOid): array {
    global $SNMP_TIMEOUT, $SNMP_RETRIES, $SNMP_VERSION;
    $cmd = sprintf(
        'snmpbulkwalk -v %s -c %s -t %d -r %d -Oqn %s %s 2>/dev/null',
        escapeshellarg($SNMP_VERSION),
        escapeshellarg($community),
        $SNMP_TIMEOUT,
        $SNMP_RETRIES,
        escapeshellarg($host),
        escapeshellarg($baseOid)
    );
    $out = shell_exec($cmd);
    if (!$out) return [];

    $result = [];
    foreach (explode("\n", trim($out)) as $line) {
        $line = trim($line);
        if ($line === '') continue;
        // formato: .1.3.6.1.2.1.x.y.z  valor
        $parts = preg_split('/\s+/', $line, 2);
        if (count($parts) === 2) {
            $result[$parts[0]] = trim($parts[1], " \t\n\r\0\x0B\"");
        }
    }
    return $result;
}

// ======================== COLETA DE MÉTRICAS ========================
function station_metrics(string $host, string $community): array {
    $m = [
        'reachable'   => false,
        'sysDescr'    => '',
        'sysName'     => '',
        'sysUpTime'   => '',
        'cpu_percent' => null,
        'mem_total'   => 0,
        'mem_used'    => 0,
        'mem_unit'    => 0,
        'disks'       => [],   // [{descr, size, used, unit}]
        'ifaces'      => [],   // [{descr, in, out}]
        'error'       => '',
    ];

    // Identificação
    $m['sysDescr']  = snmp_get($host, $community, '1.3.6.1.2.1.1.1.0');
    $m['sysName']   = snmp_get($host, $community, '1.3.6.1.2.1.1.5.0');
    $m['sysUpTime'] = snmp_get($host, $community, '1.3.6.1.2.1.1.3.0');

    if ($m['sysDescr'] === '') {
        $m['error'] = 'Sem resposta SNMP (verifique agente/community/firewall).';
        return $m;
    }
    $m['reachable'] = true;

    // CPU: média de hrProcessorLoad
    $cpuTable = snmp_walk_table($host, $community, '1.3.6.1.2.1.25.3.3.1.2');
    if (!empty($cpuTable)) {
        $sum = 0; $n = 0;
        foreach ($cpuTable as $v) {
            if (is_numeric($v)) { $sum += (int)$v; $n++; }
        }
        if ($n > 0) $m['cpu_percent'] = round($sum / $n, 1);
    }

    // Storage (memória + discos) via HOST-RESOURCES-MIB
    // hrStorageType  1.3.6.1.2.1.25.2.3.1.2
    // hrStorageDescr 1.3.6.1.2.1.25.2.3.1.3
    // hrStorageAllocationUnits 1.3.6.1.2.1.25.2.3.1.4
    // hrStorageSize  1.3.6.1.2.1.25.2.3.1.5
    // hrStorageUsed  1.3.6.1.2.1.25.2.3.1.6
    $types  = snmp_walk_table($host, $community, '1.3.6.1.2.1.25.2.3.1.2');
    $descr  = snmp_walk_table($host, $community, '1.3.6.1.2.1.25.2.3.1.3');
    $units  = snmp_walk_table($host, $community, '1.3.6.1.2.1.25.2.3.1.4');
    $sizes  = snmp_walk_table($host, $community, '1.3.6.1.2.1.25.2.3.1.5');
    $useds  = snmp_walk_table($host, $community, '1.3.6.1.2.1.25.2.3.1.6');

    // Extrai índice da linha
    $indexOf = function (string $oid): string {
        $p = explode('.', $oid);
        return end($p);
    };

    $ramType   = '.1.3.6.1.2.1.25.2.1.2';
    $fixedDisk = '.1.3.6.1.2.1.25.2.1.4';

    $memBest = null; // fallback: primeiro RAM
    foreach ($types as $oid => $t) {
        $idx = $indexOf($oid);
        $d   = $descr[".1.3.6.1.2.1.25.2.3.1.3.$idx"] ?? '';
        $u   = (int)($units[".1.3.6.1.2.1.25.2.3.1.4.$idx"] ?? 0);
        $s   = (int)($sizes[".1.3.6.1.2.1.25.2.3.1.5.$idx"] ?? 0);
        $used= (int)($useds[".1.3.6.1.2.1.25.2.3.1.6.$idx"] ?? 0);

        if ($t === $ramType || stripos($d, 'physical memory') !== false) {
            if ($memBest === null && $s > 0) {
                $memBest = ['descr' => $d, 'total' => $s, 'used' => $used, 'unit' => $u];
            }
        } elseif ($t === $fixedDisk) {
            // ignora pseudo-fs
            if (preg_match('/(tmpfs|devtmpfs|overlay|snap|loop|udev|run\/)/i', $d)) continue;
            if ($s <= 0) continue;
            $m['disks'][] = ['descr' => $d, 'size' => $s, 'used' => $used, 'unit' => $u];
        }
    }
    if ($memBest) {
        $m['mem_total'] = $memBest['total'];
        $m['mem_used']  = $memBest['used'];
        $m['mem_unit']  = $memBest['unit'];
    }

    // Interfaces: ifDescr + contadores de 64 bits (ou 32 se HC não existir)
    $ifDescr = snmp_walk_table($host, $community, '1.3.6.1.2.1.2.2.1.2');
    $ifIn64  = snmp_walk_table($host, $community, '1.3.6.1.2.1.31.1.1.1.6');
    $ifOut64 = snmp_walk_table($host, $community, '1.3.6.1.2.1.31.1.1.1.10');
    $ifIn32  = $ifIn64  ?: snmp_walk_table($host, $community, '1.3.6.1.2.1.2.2.1.10');
    $ifOut32 = $ifOut64 ?: snmp_walk_table($host, $community, '1.3.6.1.2.1.2.2.1.16');

    foreach ($ifDescr as $oid => $name) {
        $idx = $indexOf($oid);
        if (preg_match('/^(lo|Loopback|Null|Software Loopback)/i', $name)) continue;

        $in  = $ifIn64[".1.3.6.1.2.1.31.1.1.1.6.$idx"]  ?? ($ifIn32[".1.3.6.1.2.1.2.2.1.10.$idx"]  ?? null);
        $out = $ifOut64[".1.3.6.1.2.1.31.1.1.1.10.$idx"] ?? ($ifOut32[".1.3.6.1.2.1.2.2.1.16.$idx"] ?? null);

        $m['ifaces'][] = [
            'idx'   => $idx,
            'descr' => $name,
            'in'    => is_numeric($in)  ? (float)$in  : null,
            'out'   => is_numeric($out) ? (float)$out : null,
        ];
    }

    return $m;
}

// ======================== TAXA (bps) A PARTIR DO ESTADO ANTERIOR ========================
function load_state(string $file): array {
    if (!is_file($file)) return [];
    $raw = @file_get_contents($file);
    $arr = json_decode($raw ?: '[]', true);
    return is_array($arr) ? $arr : [];
}
function save_state(string $file, array $state): void {
    @file_put_contents($file, json_encode($state), LOCK_EX);
}

function iface_rates(array $prev, array $curr, float $now): array {
    // retorna [descr => ['bps_in' => x, 'bps_out' => y]]
    $rates = [];
    $prevTs = $prev['ts'] ?? 0;
    $dt = $now - $prevTs;
    if ($dt <= 0) return $rates;

    $prevIf = $prev['ifaces'] ?? [];
    foreach ($curr as $if) {
        $key = $if['descr'] . '@' . $if['idx'];
        if (!isset($prevIf[$key])) continue;
        $dIn  = ($if['in']  !== null && $prevIf[$key]['in']  !== null) ? ($if['in']  - $prevIf[$key]['in'])  : null;
        $dOut = ($if['out'] !== null && $prevIf[$key]['out'] !== null) ? ($if['out'] - $prevIf[$key]['out']) : null;
        // trata wrap de contador
        if ($dIn  !== null && $dIn  < 0) $dIn  = null;
        if ($dOut !== null && $dOut < 0) $dOut = null;
        $rates[$key] = [
            'bps_in'  => $dIn  !== null ? ($dIn  * 8) / $dt : null,
            'bps_out' => $dOut !== null ? ($dOut * 8) / $dt : null,
        ];
    }
    return $rates;
}

// ======================== FORMATADORES ========================
function fmt_bytes(float $bytes): string {
    if ($bytes <= 0) return '0 B';
    $u = ['B','KB','MB','GB','TB','PB'];
    $i = (int)floor(log($bytes, 1024));
    $i = min($i, count($u) - 1);
    return sprintf('%.2f %s', $bytes / (1024 ** $i), $u[$i]);
}
function fmt_bps(?float $bps): string {
    if ($bps === null) return '—';
    if ($bps < 1000) return sprintf('%.0f bps', $bps);
    $u = ['bps','Kbps','Mbps','Gbps'];
    $i = (int)floor(log($bps, 1000));
    $i = min($i, count($u) - 1);
    return sprintf('%.2f %s', $bps / (1000 ** $i), $u[$i]);
}
function fmt_uptime(string $ticks): string {
    // sysUpTime pode vir "(12345678) 1:2:3:4.56" ou apenas número
    if (preg_match('/([0-9]+)/', $ticks, $mm)) {
        $sec = (int)$mm[1] / 100;
        $d = intdiv((int)$sec, 86400);
        $h = intdiv((int)$sec % 86400, 3600);
        $m = intdiv((int)$sec % 3600, 60);
        return sprintf('%dd %02dh %02dm', $d, $h, $m);
    }
    return htmlspecialchars($ticks);
}
function h(?string $s): string { return htmlspecialchars($s ?? '', ENT_QUOTES, 'UTF-8'); }

// ======================== COLETA (com estado para calcular taxa) ========================
$state = load_state($STATE_FILE);
$now   = microtime(true);
$newState = [];
$results = [];

foreach ($STATIONS as $st) {
    $metrics = station_metrics($st['host'], $COMMUNITY);
    $prev    = $state[$st['host']] ?? [];

    // reindexa interfaces por chave estável
    $ifIndexed = [];
    foreach ($metrics['ifaces'] as $if) {
        $ifIndexed[$if['descr'] . '@' . $if['idx']] = $if;
    }
    $rates = iface_rates($prev, $metrics['ifaces'], $now);
    $metrics['rates'] = $rates;

    $newState[$st['host']] = ['ts' => $now, 'ifaces' => $ifIndexed];
    $results[] = ['station' => $st, 'm' => $metrics];
}
save_state($STATE_FILE, $newState);

?><!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta http-equiv="refresh" content="<?= (int)$REFRESH_SECONDS ?>">
<title>NMS Dashboard - TI Aplicada</title>
<style>
  :root {
    --bg:#0f172a; --panel:#1e293b; --panel2:#0b1220; --text:#e2e8f0;
    --muted:#94a3b8; --ok:#22c55e; --warn:#f59e0b; --bad:#ef4444;
    --acc:#38bdf8; --border:#334155;
  }
  * { box-sizing: border-box; }
  body { margin:0; font-family: -apple-system, Segoe UI, Roboto, sans-serif; background:var(--bg); color:var(--text); }
  header { padding:20px 28px; border-bottom:1px solid var(--border); display:flex; justify-content:space-between; align-items:center; background:var(--panel2); }
  header h1 { margin:0; font-size:20px; letter-spacing:.3px; }
  header .meta { color:var(--muted); font-size:13px; }
  main { padding:20px 28px; display:grid; gap:20px; grid-template-columns: repeat(auto-fit, minmax(460px, 1fr)); }
  .card { background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:18px 20px; }
  .card h2 { margin:0 0 4px; font-size:16px; }
  .card .host { color:var(--muted); font-size:12px; font-family: monospace; margin-bottom:12px; }
  .descr { font-size:12.5px; color:var(--muted); background:var(--panel2); padding:8px 10px; border-radius:6px; border:1px solid var(--border); margin-bottom:14px; white-space:pre-wrap; word-break: break-word; }
  .row { display:flex; justify-content:space-between; font-size:13px; margin:4px 0; }
  .row .k { color:var(--muted); }
  .bar { height:8px; border-radius:4px; background:#0b1220; overflow:hidden; margin:4px 0 10px; border:1px solid var(--border);}
  .bar > span { display:block; height:100%; background:linear-gradient(90deg,var(--ok),var(--acc)); }
  .bar.warn > span { background:linear-gradient(90deg,var(--warn),var(--bad)); }
  .section-title { text-transform:uppercase; font-size:11px; letter-spacing:1px; color:var(--acc); margin:14px 0 6px; }
  table { width:100%; border-collapse: collapse; font-size:12.5px; }
  th, td { text-align:left; padding:5px 6px; border-bottom:1px solid var(--border); }
  th { color:var(--muted); font-weight:500; }
  td.num { font-family: monospace; text-align:right; }
  .status { display:inline-block; padding:2px 8px; border-radius:12px; font-size:11px; }
  .status.ok  { background:rgba(34,197,94,.15);  color:var(--ok);  border:1px solid rgba(34,197,94,.4); }
  .status.bad { background:rgba(239,68,68,.15); color:var(--bad); border:1px solid rgba(239,68,68,.4); }
  .err { color:var(--bad); font-size:13px; margin-top:8px; }
  footer { text-align:center; color:var(--muted); font-size:12px; padding:16px; }
</style>
</head>
<body>
<header>
  <div>
    <h1>NMS Dashboard - Monitoramento SNMP</h1>
    <div class="meta">Community: <code><?= h($COMMUNITY) ?></code> · SNMP v<?= h($SNMP_VERSION) ?> · Auto-refresh: <?= (int)$REFRESH_SECONDS ?>s</div>
  </div>
  <div class="meta">Atualizado em <?= date('d/m/Y H:i:s') ?></div>
</header>

<main>
<?php foreach ($results as $r):
    $st = $r['station']; $m = $r['m'];
    $memPct  = ($m['mem_total'] > 0) ? ($m['mem_used'] * 100 / $m['mem_total']) : 0;
    $memTotB = $m['mem_total'] * $m['mem_unit'];
    $memUseB = $m['mem_used']  * $m['mem_unit'];
?>
  <section class="card">
    <div style="display:flex; justify-content:space-between; align-items:flex-start;">
      <div>
        <h2><?= h($st['label']) ?> <?= $m['sysName'] ? '<span style="color:var(--muted); font-weight:400;">('.h($m['sysName']).')</span>' : '' ?></h2>
        <div class="host"><?= h($st['host']) ?></div>
      </div>
      <span class="status <?= $m['reachable'] ? 'ok' : 'bad' ?>"><?= $m['reachable'] ? 'ONLINE' : 'OFFLINE' ?></span>
    </div>

    <?php if (!$m['reachable']): ?>
      <div class="err"><?= h($m['error']) ?></div>
    <?php else: ?>

      <div class="section-title">Identificação (sysDescr)</div>
      <div class="descr"><?= h($m['sysDescr']) ?></div>
      <div class="row"><span class="k">Uptime</span><span><?= fmt_uptime($m['sysUpTime']) ?></span></div>

      <div class="section-title">CPU</div>
      <?php $cpu = $m['cpu_percent']; ?>
      <div class="row"><span class="k">Ocupação média</span><span><?= $cpu === null ? 'n/d' : number_format($cpu,1).' %' ?></span></div>
      <div class="bar <?= ($cpu !== null && $cpu > 80) ? 'warn' : '' ?>">
        <span style="width: <?= $cpu === null ? 0 : max(0,min(100,$cpu)) ?>%"></span>
      </div>

      <div class="section-title">Memória</div>
      <div class="row">
        <span class="k">Usada / Total</span>
        <span><?= fmt_bytes($memUseB) ?> / <?= fmt_bytes($memTotB) ?> (<?= number_format($memPct,1) ?>%)</span>
      </div>
      <div class="bar <?= $memPct > 85 ? 'warn' : '' ?>">
        <span style="width: <?= max(0,min(100,$memPct)) ?>%"></span>
      </div>

      <div class="section-title">Discos</div>
      <?php if (empty($m['disks'])): ?>
        <div class="row"><span class="k">Nenhum disco fixo reportado</span><span>—</span></div>
      <?php else: ?>
        <table>
          <thead><tr><th>Volume</th><th class="num">Livre</th><th class="num">Total</th><th class="num">Uso</th></tr></thead>
          <tbody>
          <?php foreach ($m['disks'] as $d):
              $tot = $d['size'] * $d['unit'];
              $use = $d['used'] * $d['unit'];
              $free = max(0, $tot - $use);
              $pct = $tot > 0 ? ($use * 100 / $tot) : 0;
          ?>
            <tr>
              <td><?= h($d['descr']) ?></td>
              <td class="num"><?= fmt_bytes($free) ?></td>
              <td class="num"><?= fmt_bytes($tot) ?></td>
              <td class="num" style="color: <?= $pct>85?'var(--bad)':($pct>70?'var(--warn)':'var(--ok)') ?>">
                <?= number_format($pct,1) ?>%
              </td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
      <?php endif; ?>

      <div class="section-title">Tráfego nas interfaces</div>
      <?php if (empty($m['ifaces'])): ?>
        <div class="row"><span class="k">Sem interfaces reportadas</span><span>—</span></div>
      <?php else: ?>
        <table>
          <thead><tr><th>Interface</th><th class="num">In (taxa)</th><th class="num">Out (taxa)</th><th class="num">Total In</th><th class="num">Total Out</th></tr></thead>
          <tbody>
          <?php foreach ($m['ifaces'] as $if):
              $key = $if['descr'].'@'.$if['idx'];
              $r = $m['rates'][$key] ?? ['bps_in'=>null,'bps_out'=>null];
          ?>
            <tr>
              <td><?= h($if['descr']) ?></td>
              <td class="num"><?= fmt_bps($r['bps_in']) ?></td>
              <td class="num"><?= fmt_bps($r['bps_out']) ?></td>
              <td class="num"><?= $if['in']  !== null ? fmt_bytes((float)$if['in'])  : '—' ?></td>
              <td class="num"><?= $if['out'] !== null ? fmt_bytes((float)$if['out']) : '—' ?></td>
            </tr>
          <?php endforeach; ?>
          </tbody>
        </table>
        <div style="font-size:11px; color:var(--muted); margin-top:6px;">
          Taxa calculada a partir da diferença entre coletas (aguarde 1 refresh após abrir a página).
        </div>
      <?php endif; ?>

    <?php endif; ?>
  </section>
<?php endforeach; ?>
</main>

<footer>
  NMS PHP · TI Aplicada · <?= date('Y') ?> — usa <code>snmpget/snmpbulkwalk</code> via <code>shell_exec()</code>.
</footer>
</body>
</html>

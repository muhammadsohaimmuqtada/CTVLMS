<?php
require_once __DIR__ . '/../includes/sync_cve.php';
$tests = 0;
function c(bool $ok, string $msg): void { global $tests; $tests++; if (!$ok) { fwrite(STDERR, "FAIL: $msg\n"); exit(1); } }
$cve = ['configurations' => [[
    'operator'=>'AND',
    'nodes'=>[
        ['operator'=>'OR','cpeMatch'=>[[
            'vulnerable'=>true,'criteria'=>'cpe:2.3:a:python:python:*:*:*:*:*:*:*:*','matchCriteriaId'=>'11111111-1111-1111-1111-111111111111','versionEndIncluding'=>'3.14.4'
        ]]],
        ['operator'=>'OR','cpeMatch'=>[[
            'vulnerable'=>false,'criteria'=>'cpe:2.3:o:microsoft:windows:-:*:*:*:*:*:*:*','matchCriteriaId'=>'22222222-2222-2222-2222-222222222222'
        ]]],
    ]
]]];
$matches = extractNvdCpeMatches($cve);
c(count($matches) === 2, 'flatten preserves both vulnerable and environment criteria');
c($matches[0]['configurationComplex'] === 1 && $matches[1]['configurationComplex'] === 1, 'AND marks criteria complex');
c($matches[0]['matchCriteriaId'] === '11111111-1111-1111-1111-111111111111', 'matchCriteriaId preserved');
c($matches[1]['vulnerable'] === 0, 'vulnerable=false environment prerequisite preserved');
echo "PASS: {$tests} NVD parser tests\n";

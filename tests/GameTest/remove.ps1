# Removes what deploy.ps1 added. Deactivate these mods in the game's mod menu first, so their approvals are dropped.
param(
    [string]$GameDir = 'F:\Program Files (x86)\Steam\steamapps\common\Probably Stolen'
)
$ErrorActionPreference = 'Stop'
$mods = Join-Path $GameDir 'Mods'
foreach ($name in 'ModGuard', 'ModGuardTestImports', 'ModGuardTestBlocked', 'ModGuardTestSuspect', 'ModGuardTestFake') {
    $target = Join-Path $mods $name
    if (Test-Path -LiteralPath $target) {
        Remove-Item -LiteralPath $target -Recurse -Force
        Write-Output "Removed $target"
    }
}
$ack = Join-Path $env:USERPROFILE 'AppData\LocalLow\Questing Goose Studio\Probably Stolen\ModData\modguard_fjwjmmc\ack.txt'
if (Test-Path -LiteralPath $ack) {
    Remove-Item -LiteralPath $ack -Force
    Write-Output 'Removed the seen-warnings file'
}

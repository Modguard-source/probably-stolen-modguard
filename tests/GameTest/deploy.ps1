# Puts a TEST build of Mod Guard and four harmless stubs into the game's Mods folder.
# The test list adds entries only for the stubs. Close the game first: it keeps loaded DLLs open.
# Mods folders are only read at game start. Undo with remove.ps1.
#
# The test build says its official item is 1, so this local copy shows the "not the official item" warning and
# the footer shows an item number. A real build leaves both at 0 until the Workshop item exists.
#
# -SuspectConfirmed  lists the "suspect" stub as confirmed instead. Activate that stub with "Activate anyway" first,
#                    then deploy with it, to see the startup report for an active malicious mod.
# -Tamper            adds a language file the release did not ship, the way a repack would slip in its own text.
#                    Mod Guard should then warn about its own files and show only its built-in messages.
# -StubsOnly         puts only the stubs in, for testing the Mod Guard you subscribed to. Its list has no entries
#                    for the stubs, so only the import rule and the fake-guard check can be tested that way.
#
# A local Mod Guard and a subscribed one share a mod id, and the game loads the local folder first, silently
# skipping the subscription. So this refuses to put a local guard in while a subscribed copy is installed.
param(
    [string]$GameDir = 'F:\Program Files (x86)\Steam\steamapps\common\Probably Stolen',
    [switch]$SuspectConfirmed,
    [switch]$Tamper,
    [switch]$StubsOnly
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..\..')).Path
$mods = Join-Path $GameDir 'Mods'
$work = Join-Path $root 'build\gametest'

if (-not $StubsOnly) {
    $workshop = Join-Path (Split-Path (Split-Path $GameDir)) 'workshop\content\4348910'
    if (Test-Path -LiteralPath $workshop) {
        $subscribed = Get-ChildItem -LiteralPath $workshop -Directory | Where-Object {
            $manifest = Join-Path $_.FullName 'manifest.xml'
            (Test-Path -LiteralPath $manifest) -and (Select-String -LiteralPath $manifest -Pattern '<ID>\s*modguard\.fjwjmmc\s*</ID>' -Quiet)
        }
        if ($subscribed) {
            throw ("A subscribed Mod Guard is installed (Workshop item " + (($subscribed | ForEach-Object Name) -join ', ') + "). A local copy would hide it. Use -StubsOnly.")
        }
    }
}
if ($StubsOnly -and ($SuspectConfirmed -or $Tamper)) {
    throw '-SuspectConfirmed and -Tamper change the local guard build, so they do not work with -StubsOnly.'
}
if ($StubsOnly -and (Test-Path -LiteralPath (Join-Path $mods 'ModGuard'))) {
    throw "A local Mod Guard is still in $mods\ModGuard and would hide the subscribed one. Deactivate it in the menu, then run remove.ps1 first."
}

function Sha([string]$path) { (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash.ToLowerInvariant() }

# Same formula as the game's ModFingerprint: manifest hash, then "assembly|hash" per listed DLL.
function Combined([string]$folder, [string]$assembly) {
    $text = (Sha (Join-Path $folder 'manifest.xml')) + "`n" + $assembly + '|' + (Sha (Join-Path $folder $assembly))
    $bytes = [Text.Encoding]::UTF8.GetBytes($text)
    ([Convert]::ToHexString([Security.Cryptography.SHA256]::HashData($bytes))).ToLowerInvariant()
}

# Ids starting with "modguard" count as claiming to be Mod Guard, so new stubs avoid that prefix. The suspect stub
# keeps its old id because the game remembers by id that the player activated it.
$stubs = @(
    @{ Name = 'ModGuardTestImports'; Id = 'guardtest_imports'; Title = '[守卫测试] 导入规则：应被阻止'; Define = 'WITH_IMPORTS'; Caps = '<Capabilities><Capability>native</Capability></Capabilities>' },
    @{ Name = 'ModGuardTestBlocked'; Id = 'guardtest_blocked'; Title = '[守卫测试] 名单确认：应被阻止'; Define = 'PLAIN'; Caps = '<Capabilities />' },
    @{ Name = 'ModGuardTestSuspect'; Id = 'modguard_test_suspect'; Title = '[守卫测试] 名单可疑：应被提醒'; Define = 'PLAIN'; Caps = '<Capabilities />' },
    # No "modguard" id prefix, so only the name can give it away.
    @{ Name = 'ModGuardTestFake'; Id = 'guardtest_fake'; Title = '[守卫测试] 模组守卫（仿冒）：应被提醒'; Define = 'PLAIN'; Caps = '<Capabilities />' }
)

$hashes = @{}
foreach ($stub in $stubs) {
    $name = $stub.Name
    $target = Join-Path $mods $name
    dotnet build (Join-Path $PSScriptRoot 'Stub.csproj') -c Release --nologo -v q "-p:AssemblyName=$name" "-p:DefineConstants=$($stub.Define)" "-p:GameDir=$GameDir" "-p:BaseOutputPath=$work\$name\bin\" "-p:IntermediateOutputPath=$work\$name\obj\"
    if ($LASTEXITCODE -ne 0) { throw "stub build failed: $name" }
    New-Item -ItemType Directory -Force $target | Out-Null
    Copy-Item (Get-ChildItem "$work\$name\bin" -Recurse -Filter "$name.dll" | Select-Object -First 1).FullName $target -Force
    @"
<?xml version="1.0" encoding="utf-8"?>
<Manifest>
  <ID>$($stub.Id)</ID>
  <Name>$($stub.Title)</Name>
  <Author>Mod Guard test</Author>
  <ModVersion>0.0.1</ModVersion>
  <Description>Mod Guard test stub. It only writes one log line. Safe to delete.</Description>
  <Prerequisites />
  <Assemblies>
    <Assembly>$name.dll</Assembly>
  </Assemblies>
  $($stub.Caps)
</Manifest>
"@ | Set-Content -LiteralPath (Join-Path $target 'manifest.xml') -Encoding utf8NoBOM
    $hashes[$name] = Combined $target "$name.dll"
}

if ($StubsOnly) {
    Write-Output "Deployed stubs only to $mods (testing the subscribed Mod Guard)"
    Get-ChildItem $mods -Directory | ForEach-Object { Write-Output ('  ' + $_.Name) }
    return
}

# The test list is written before the guard is built, so the hash the build puts into the DLL is this list's.
$list =Get-Content (Join-Path $root 'src\ModGuard\blocklist.json') -Raw | ConvertFrom-Json
$list.entries += [pscustomobject]@{ kind = 'version'; value = $hashes['ModGuardTestBlocked']; level = 'confirmed'; reason = 'malware_confirmed'; case = 'TEST-1'; added = '2026-11-08' }
if ($SuspectConfirmed) {
    $list.entries += [pscustomobject]@{ kind = 'version'; value = $hashes['ModGuardTestSuspect']; level = 'confirmed'; reason = 'malware_confirmed'; case = 'TEST-2'; added = '2026-11-08' }
} else {
    $list.entries += [pscustomobject]@{ kind = 'version'; value = $hashes['ModGuardTestSuspect']; level = 'suspect'; reason = 'mass_reupload'; case = 'TEST-2'; added = '2026-11-08' }
}
New-Item -ItemType Directory -Force $work | Out-Null
$testList = Join-Path $work 'blocklist.json'
$list | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $testList -Encoding utf8NoBOM

$content = Join-Path $work 'guard'
if (Test-Path -LiteralPath $content) { Remove-Item -LiteralPath $content -Recurse -Force }
dotnet build (Join-Path $root 'src\ModGuard\ModGuard.csproj') -c Release --nologo -v q "-p:DeployDir=$content" "-p:GameDir=$GameDir" "-p:BlocklistPath=$testList" '-p:OfficialItem=1' '-p:OfficialPublisher=1'
if ($LASTEXITCODE -ne 0) { throw 'guard build failed' }

# Start from an empty folder, so a file left by an earlier run (say, the -Tamper file) cannot linger.
$guard = Join-Path $mods 'ModGuard'
if (Test-Path -LiteralPath $guard) { Remove-Item -LiteralPath $guard -Recurse -Force }
New-Item -ItemType Directory -Force $guard | Out-Null
Copy-Item (Join-Path $content '*') $guard -Recurse -Force
if ($Tamper) {
    # "zz" is no language the game has, so this never collides with a real translation the release may ship.
    "tamper_test,This line was added after the build." | Set-Content -LiteralPath (Join-Path $guard 'Localization\zz.csv') -Encoding utf8NoBOM
}

# So the startup report shows again on the next launch.
$ack = Join-Path $env:USERPROFILE 'AppData\LocalLow\Questing Goose Studio\Probably Stolen\ModData\modguard_fjwjmmc\ack.txt'
if (Test-Path -LiteralPath $ack) { Remove-Item -LiteralPath $ack -Force }

Write-Output "Deployed to $mods"
Get-ChildItem $mods -Directory | ForEach-Object { Write-Output ('  ' + $_.Name) }
Write-Output ('Test list entries: ' + $list.entries.Count + ($(if ($SuspectConfirmed) { ' (suspect stub listed as confirmed)' } else { '' })) + ($(if ($Tamper) { ', tampered' } else { '' })))

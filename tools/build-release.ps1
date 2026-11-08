# Builds the folder to upload to the Workshop, from scratch, and checks it. It never uploads anything.
#   1. Set OfficialItem in src/ModGuard/ModGuard.csproj (left at 0 only for the very first, private upload).
#   2. Run this. Upload build/release exactly as it is when this finishes, and do not touch it afterwards.
#   3. Put the printed ModGuard.dll SHA-256 into the release notes.
# -FirstUpload is for the private upload that creates the item: OfficialItem stays 0, every other check still
# applies. That build has no identity check and must never be made public.
param(
    [string]$GameDir = 'F:\Program Files (x86)\Steam\steamapps\common\Probably Stolen',
    [switch]$FirstUpload
)
$ErrorActionPreference = 'Stop'
$root = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$out = Join-Path $root 'build\release'

# A clean folder: anything left over from an earlier build would ship beside the DLL and fail the check.
if (Test-Path -LiteralPath $out) { Remove-Item -LiteralPath $out -Recurse -Force }

dotnet build (Join-Path $root 'src\ModGuard\ModGuard.csproj') -c Release --nologo -v q "-p:DeployDir=$out" "-p:GameDir=$GameDir"
if ($LASTEXITCODE -ne 0) { throw 'build failed' }

dotnet run --project (Join-Path $root 'tests\CoreTests') -c Release
if ($LASTEXITCODE -ne 0) { throw 'tests failed' }

dotnet run --project (Join-Path $root 'tests\CoreTests') -c Release -- patch (Join-Path $out 'ModGuard.dll')
if ($LASTEXITCODE -ne 0) { throw 'patch targets do not match the game' }

$check = @('run', '--project', (Join-Path $root 'tests\CoreTests'), '-c', 'Release', '--', 'release', $out)
if ($FirstUpload) { $check += '--first-upload' }
dotnet @check
if ($LASTEXITCODE -ne 0) { throw 'release check failed: do not upload' }

# Which sources this hash belongs to. Uncommitted changes mean nobody else can rebuild it.
$commit = git -C $root rev-parse HEAD 2>$null
if ($LASTEXITCODE -eq 0 -and $commit) {
    Write-Output "Built from commit $commit"
    if (git -C $root status --porcelain) { Write-Warning 'The working tree has uncommitted changes: commit them, or nobody can reproduce this build.' }
} else {
    Write-Warning 'No commit yet: nobody can reproduce this build until the sources are committed.'
}

if ($FirstUpload) {
    Write-Output "Ready for the FIRST, PRIVATE upload: $out"
} else {
    Write-Output "Ready to upload: $out"
}

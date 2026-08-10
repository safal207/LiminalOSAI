param(
    [string]$Ref = "9e696c2f65d15a390afc312cf783ef52429fdc55"
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$skillsRoot = Join-Path $repoRoot ".windsurf\skills"
$dest = Join-Path $skillsRoot "orchstep-workflow-design"
$tempRoot = Join-Path $env:TEMP ("orchstep-windsurf-skill-" + [guid]::NewGuid().ToString("N"))
$zip = Join-Path $tempRoot "orchstep.zip"
$extract = Join-Path $tempRoot "extract"

New-Item -ItemType Directory -Force -Path $tempRoot, $extract, $skillsRoot | Out-Null

try {
    $url = "https://github.com/orchstep/orchstep/archive/$Ref.zip"
    Write-Host "Downloading OrchStep skill from $url"
    Invoke-WebRequest -Uri $url -OutFile $zip
    Expand-Archive -Path $zip -DestinationPath $extract -Force

    $archiveRoot = Get-ChildItem -Path $extract -Directory | Select-Object -First 1
    if (-not $archiveRoot) { throw "Archive root not found" }

    $source = Join-Path $archiveRoot.FullName "skills\orchstep-workflow-design"
    if (-not (Test-Path (Join-Path $source "SKILL.md"))) {
        throw "SKILL.md not found in downloaded archive"
    }

    if (Test-Path $dest) { Remove-Item -Recurse -Force $dest }
    Copy-Item -Recurse -Force $source $dest

    $required = @(
        "SKILL.md",
        "wizard.md",
        "references\syntax.md",
        "references\error-handling.md",
        "examples\01-ci-pipeline.yml"
    )
    foreach ($relative in $required) {
        $path = Join-Path $dest $relative
        if (-not (Test-Path $path)) { throw "Missing required skill resource: $relative" }
    }

    Write-Host "Installed native Windsurf skill to: $dest"
    Write-Host "Start a NEW Cascade session and ask:"
    Write-Host 'design an OrchStep workflow that builds, tests, and deploys my app'
    Write-Host "Then save the generated YAML and run: orchstep lint -f <file>"
}
finally {
    if (Test-Path $tempRoot) { Remove-Item -Recurse -Force $tempRoot }
}

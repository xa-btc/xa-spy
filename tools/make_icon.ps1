# XA Spy XX icon v1.00 - deterministic assets only; does not build or launch the application.
# Matches the XA DevHub / XA Sweep family: navy rounded tile, blue ring, white/blue monogram.
# Regenerate explicitly with Windows PowerShell; not part of the normal build.
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Drawing

$assetRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\assets'))
if (-not (Test-Path -LiteralPath $assetRoot)) { New-Item -ItemType Directory -Path $assetRoot | Out-Null }
$iconPath = Join-Path $assetRoot 'xa-spy.ico'
$previewPath = Join-Path $assetRoot 'xa-spy.png'

function New-RoundRect([single]$x, [single]$y, [single]$w, [single]$h, [single]$r) {
    $path = New-Object System.Drawing.Drawing2D.GraphicsPath
    $d = 2 * $r
    $path.AddArc($x, $y, $d, $d, 180, 90)
    $path.AddArc($x + $w - $d, $y, $d, $d, 270, 90)
    $path.AddArc($x + $w - $d, $y + $h - $d, $d, $d, 0, 90)
    $path.AddArc($x, $y + $h - $d, $d, $d, 90, 90)
    $path.CloseFigure()
    return $path
}

$top = [System.Drawing.Color]::FromArgb(255, 0x22, 0x2f, 0x4a)
$bottom = [System.Drawing.Color]::FromArgb(255, 0x0d, 0x11, 0x17)
$blue = [System.Drawing.Color]::FromArgb(255, 0x4f, 0x8f, 0xf7)
$white = [System.Drawing.Color]::FromArgb(255, 0xe8, 0xed, 0xf5)
$family = New-Object System.Drawing.FontFamily('Segoe UI')
$format = [System.Drawing.StringFormat]::GenericTypographic
$entries = @()

foreach ($size in @(256, 128, 64, 48, 32, 24, 16)) {
    $ss = 4
    $canvas = $size * $ss
    $scale = $canvas / 256.0
    $bitmap = New-Object System.Drawing.Bitmap($canvas, $canvas)
    $graphics = [System.Drawing.Graphics]::FromImage($bitmap)
    $graphics.SmoothingMode = [System.Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $graphics.Clear([System.Drawing.Color]::Transparent)
    $inset = [Math]::Max($ss, 6 * $scale)
    $radius = [Math]::Max(2 * $ss, 46 * $scale)
    $tile = New-RoundRect $inset $inset ($canvas - 2 * $inset) ($canvas - 2 * $inset) $radius
    $rectangle = New-Object System.Drawing.RectangleF(0, 0, $canvas, $canvas)
    $background = New-Object System.Drawing.Drawing2D.LinearGradientBrush($rectangle, $top, $bottom, 65.0)
    $graphics.FillPath($background, $tile)
    if ($size -ge 32) {
        $stroke = [Math]::Max(2 * $ss, 11 * $scale)
        $edge = $inset + $stroke / 2
        $border = New-RoundRect $edge $edge ($canvas - 2 * $edge) ($canvas - 2 * $edge) ($radius - $stroke / 2)
        $pen = New-Object System.Drawing.Pen($blue, $stroke)
        $graphics.DrawPath($pen, $border)
        $pen.Dispose(); $border.Dispose()
    }
    $em = 118 * $scale
    if ($size -le 24) { $em = 130 * $scale }
    $glyph = New-Object System.Drawing.Drawing2D.GraphicsPath
    $glyph.AddString('X', $family, [int][System.Drawing.FontStyle]::Bold, $em, [System.Drawing.PointF]::Empty, $format)
    $bounds = $glyph.GetBounds()
    $gap = 5 * $scale
    $left = ($canvas - (2 * $bounds.Width + $gap)) / 2
    $y = ($canvas - $bounds.Height) / 2
    $brightBlue = if ($size -le 24) { [System.Drawing.Color]::FromArgb(255, 0x8a, 0xb8, 0xff) } else { $blue }
    for ($index = 0; $index -lt 2; $index++) {
        $letter = $glyph.Clone()
        $transform = New-Object System.Drawing.Drawing2D.Matrix
        $transform.Translate(($left + $index * ($bounds.Width + $gap) - $bounds.X), ($y - $bounds.Y))
        $letter.Transform($transform)
        $color = if ($index -eq 0) { $white } else { $brightBlue }
        $ink = New-Object System.Drawing.SolidBrush($color)
        $graphics.FillPath($ink, $letter)
        $ink.Dispose(); $transform.Dispose(); $letter.Dispose()
    }
    $glyph.Dispose(); $tile.Dispose(); $background.Dispose(); $graphics.Dispose()
    $small = New-Object System.Drawing.Bitmap($size, $size)
    $resize = [System.Drawing.Graphics]::FromImage($small)
    $resize.InterpolationMode = [System.Drawing.Drawing2D.InterpolationMode]::HighQualityBicubic
    $resize.PixelOffsetMode = [System.Drawing.Drawing2D.PixelOffsetMode]::HighQuality
    $resize.DrawImage($bitmap, (New-Object System.Drawing.Rectangle(0, 0, $size, $size)))
    $resize.Dispose(); $bitmap.Dispose()
    if ($size -eq 256) { $small.Save($previewPath, [System.Drawing.Imaging.ImageFormat]::Png) }
    $stream = New-Object System.IO.MemoryStream
    $small.Save($stream, [System.Drawing.Imaging.ImageFormat]::Png)
    $entries += , @{ Size = $size; Data = $stream.ToArray() }
    $stream.Dispose(); $small.Dispose()
}
$family.Dispose(); $format.Dispose()
$file = [System.IO.File]::Create($iconPath)
$writer = New-Object System.IO.BinaryWriter($file)
try {
    $writer.Write([uint16]0); $writer.Write([uint16]1); $writer.Write([uint16]$entries.Count)
    $offset = 6 + 16 * $entries.Count
    foreach ($entry in $entries) {
        $dimension = if ($entry.Size -eq 256) { 0 } else { $entry.Size }
        $writer.Write([byte]$dimension); $writer.Write([byte]$dimension)
        $writer.Write([byte]0); $writer.Write([byte]0)
        $writer.Write([uint16]1); $writer.Write([uint16]32)
        $writer.Write([uint32]$entry.Data.Length); $writer.Write([uint32]$offset)
        $offset += $entry.Data.Length
    }
    foreach ($entry in $entries) { $writer.Write($entry.Data) }
} finally { $writer.Dispose(); $file.Dispose() }
Write-Host "Wrote XX icon: $iconPath (7 sizes) and $previewPath"

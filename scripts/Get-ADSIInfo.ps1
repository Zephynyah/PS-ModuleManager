<#
.SYNOPSIS
    Discovers DomainLdapPath and available OUs using ADSI.
.DESCRIPTION
    Uses ADSI (no Active Directory module required) to determine the domain
    LDAP path and enumerate available OUs for use in settings.json.
#>

# ── Get Domain LDAP Path ────────────────────────────────────────────────────
try {
    $rootDSE = [ADSI]"LDAP://RootDSE"
    $defaultNC = $rootDSE.defaultNamingContext.ToString()
    $domainLdapPath = "LDAP://$defaultNC"

    Write-Host "`n=== Domain Info ===" -ForegroundColor Cyan
    Write-Host "Domain LDAP Path : " -NoNewline; Write-Host $domainLdapPath -ForegroundColor Green
    Write-Host "Naming Context   : $defaultNC"
    Write-Host "DNS Host Name    : $($rootDSE.dnsHostName)"
}
catch {
    Write-Host "ERROR: Could not connect to domain via ADSI. Are you domain-joined?" -ForegroundColor Red
    Write-Host $_.Exception.Message
    return
}

# ── Enumerate OUs ───────────────────────────────────────────────────────────
Write-Host "`n=== Available OUs ===" -ForegroundColor Cyan

$searcher = [ADSISearcher]"(objectClass=organizationalUnit)"
$searcher.SearchRoot = [ADSI]"LDAP://$defaultNC"
$searcher.PageSize = 1000
$searcher.PropertiesToLoad.AddRange(@("distinguishedName", "name", "description"))

$ous = $searcher.FindAll() | ForEach-Object {
    [PSCustomObject]@{
        Name              = ($_.Properties["name"] | Select-Object -First 1)
        DistinguishedName = ($_.Properties["distinguishedname"] | Select-Object -First 1)
        Description       = ($_.Properties["description"] | Select-Object -First 1)
    }
} | Sort-Object DistinguishedName

if ($ous.Count -eq 0) {
    Write-Host "No OUs found." -ForegroundColor Yellow
}
else {
    Write-Host "Found $($ous.Count) OU(s):`n"
    $ous | Format-Table -Property Name, DistinguishedName, Description -AutoSize -Wrap

    # ── Suggested settings.json values ──────────────────────────────────────
    Write-Host "=== Suggested settings.json values ===" -ForegroundColor Cyan
    Write-Host '"DomainLdapPath": "' -NoNewline
    Write-Host $domainLdapPath -ForegroundColor Green -NoNewline
    Write-Host '"'
    Write-Host ""
    Write-Host "Pick an OuFilter from the list above, e.g.:" -ForegroundColor Yellow
    $ous | Select-Object -First 5 | ForEach-Object {
        Write-Host "  `"OuFilter`": `"$($_.DistinguishedName)`""
    }
}

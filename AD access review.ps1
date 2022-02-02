#

Class Test
{
$a
$b
$c
}

Class Perm
{
$name
$OU
$ACType
$identityReference
$ADRights
$IsInhereted
}

Import-Module ActiveDirectory
Set-Location AD:
$OUs = @("DC=company,DC=pri","OU=Domain Controllers,DC=company,DC=pri","OU=Test OU,DC=company,DC=pri")
foreach ($OU in $OUs)
{

$OU -match "\w\w="
$Name = (($OU -split ",")[0]).replace($Matches.values,"")

$ACLs = ((get-acl (Get-ADObject "$OU").distinguishedname).access) | select *

    foreach ($ACL in $ACLs)
    {
    $obj = New-Object Perm

    $obj.name = $Name
    $obj.ou = $OU
    $obj.ACType = $ACL.AccessControlType
    $obj.identityReference = $ACL.IdentityReference
    $obj.ADRights = $ACL.ActiveDirectoryRights
    $obj.IsInhereted = $ACL.IsInherited

    $obj | Export-Csv C:\temp\Access.csv -Append -NoTypeInformation
    }
}
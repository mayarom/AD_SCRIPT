Import-Module ActiveDirectory

# הגדרת שם משתמש המשתמש הנוכחי
$currentUser = Get-ADUser -Identity $env:USERNAME

# הגדרת נתיב התיקייה לקובץ הפלט
$outputFilePath = Join-Path -Path $currentUser.HomeDirectory -ChildPath "Desktop\ADSecuritySettings.txt"

# פתיחת קובץ הפלט
$outputFile = New-Object System.IO.StreamWriter($outputFilePath)

# פונקציה לכתיבת תיאור ראשוני לקטגוריה
function Write-CategoryHeader($categoryName) {
    $outputFile.WriteLine("")
    $outputFile.WriteLine("###########################################")
    $outputFile.WriteLine("### $categoryName")
    $outputFile.WriteLine("###########################################")
    $outputFile.WriteLine("")
}

# פונקציה לבדיקת וכתיבת הגדרה
function Check-And-Write-Setting($settingName, $settingValue) {
    $outputFile.WriteLine("$settingName: $settingValue")
}

# בדיקת מדיניות סיסמאות
Write-CategoryHeader "מדיניות סיסמאות"
$passwordPolicy = Get-ADDefaultDomainPolicy
Check-And-Write-Setting "אורך סיסמאות מינימלי" $passwordPolicy.MinimumPasswordLength
Check-And-Write-Setting "דרישת אותיות קטנות" $passwordPolicy.RequireLowerCaseLetters
Check-And-Write-Setting "דרישת אותיות גדולות" $passwordPolicy.RequireUpperCaseLetters
Check-And-Write-Setting "דרישת ספרות" $passwordPolicy.RequireNumbers
Check-And-Write-Setting "דרישת תווים מיוחדים" $passwordPolicy.RequireSymbols
Check-And-Write-Setting "גיל סיסמאות מקסימלי" $passwordPolicy.MaximumPasswordAge
Check-And-Write-Setting "היסטוריה של סיסמאות" $passwordPolicy.PasswordHistoryLength
Check-And-Write-Setting "נעילת חשבון לאחר מספר ניסיונות כושלים" $passwordPolicy.LockoutThreshold
Check-And-Write-Setting "משך נעילה של חשבון" $passwordPolicy.LockoutDuration

# בדיקת מדיניות נעילת חשבון
Write-CategoryHeader "מדיניות נעילת חשבון"
$accountLockoutPolicy = Get-ADAccountLockoutPolicy
Check-And-Write-Setting "נעילת חשבון לאחר מספר ניסיונות כושלים" $accountLockoutPolicy.LockoutThreshold
Check-And-Write-Setting "משך נעילה של חשבון" $accountLockoutPolicy.LockoutDuration

# בדיקת אבטחת חשבונות משתמש
Write-CategoryHeader "אבטחת חשבונות משתמש"
Check-And-Write-Setting "דרישת כניסה חזקה" (Get-ADDefaultDomainPolicy | Select-Object -ExpandProperty RequireStrongPassword)
Check-And-Write-Setting "דרישת שינוי סיסמאות תקופתי" (Get-ADDefaultDomainPolicy | Select-Object -ExpandProperty PasswordExpiration)
Check-And-Write-Setting "דרישת PIN" (Get-ADDefaultDomainPolicy | Select-Object -ExpandProperty UserPinRequired)
Check-And-Write-Setting "אפשרות שינוי שם משתמש" (Get-ADDefaultDomainPolicy | Select-Object -ExpandProperty UserRenameAllowed)
Check-And-Write-Setting "אפשרות כניסה למחשב נעול" (Get-ADDefaultDomainPolicy | Select-Object -ExpandProperty AllowLogonToLockedWorkstation)

# בדיקת הגדרות קבוצות אבטחה
Write-CategoryHeader "הגדרות קבוצות אבטחה"
$securityGroups = @("Domain Admins", "Domain Users")  # הוסף כאן את שמות הקבוצות הרלוונטיות לארגון שלך
foreach ($group in $securityGroups) {
    $groupDetails = Get-ADGroup -Identity $group
    Write-CategoryHeader "קבוצת '$group'"
    Check-And-Write-Setting "גודל קבוצה" $groupDetails.Members.Count
    $groupMembers = $groupDetails.Members | Select-Object -ExpandProperty Name -Unique
    Check-And-Write-Setting "חברות בקבוצה" $groupMembers
}

# סגירת קובץ הפלט
$outputFile.Close()

# הודעה על סיום
Write-Host "הגדרות אבטחה נכתבו בהצלחה לקובץ: $outputFilePath"

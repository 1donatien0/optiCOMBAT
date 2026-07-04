/*
    Règle qui détecte des chaînes suspectes
*/

rule SuspiciousPowerShell
{
    meta:
        description = "Detects suspicious PowerShell commands"
        severity = "medium"
        
    strings:
        $ps1 = "powershell -ExecutionPolicy Bypass" nocase
        $ps2 = "powershell -enc" nocase
        $ps3 = "Invoke-Expression" nocase
        $ps4 = "IEX" nocase
        
    condition:
        2 of them
}

rule SuspiciousDownloads
{
    meta:
        description = "Detects suspicious download patterns combined with execution or decoding"
        severity = "low"
        // CORRECTION : condition 'any of them' sur "wget"/"curl"/"download" nocase
        // déclenchait des faux positifs massifs (README, installeurs, scripts légitimes).
        // On exige désormais soit (a) une combinaison wget/curl + un indicateur d'exécution,
        // soit (b) le pattern "DownloadString" ou "DownloadFile" spécifique à PowerShell/NET,
        // soit (c) wget/curl accompagné d'un shell indicator.

    strings:
        // Téléchargeurs en ligne de commande
        $wget    = "wget " nocase
        $curl    = "curl " nocase

        // Méthodes .NET / PowerShell de téléchargement (très spécifiques)
        $dl_str  = "DownloadString" nocase
        $dl_file = "DownloadFile" nocase
        $dl_data = "DownloadData" nocase
        $webclient = "WebClient" nocase

        // Indicateurs d'exécution (contexte malveillant)
        $exec1 = "| bash" nocase
        $exec2 = "| sh " nocase
        $exec3 = "| cmd" nocase
        $exec4 = "Invoke-Expression" nocase
        $exec5 = "IEX(" nocase
        $exec6 = "-exec bypass" nocase

    condition:
        // Cas 1 : méthode .NET de téléchargement + WebClient (pattern classique malware PS)
        ($dl_str or $dl_file or $dl_data) and $webclient
        or
        // Cas 2 : wget ou curl + pipe vers un shell ou exécution directe
        ($wget or $curl) and (1 of ($exec*))
        or
        // Cas 3 : DownloadString/File seul suffit (trop rare dans les fichiers légitimes non-PS)
        ($dl_str or $dl_file) and (1 of ($exec*))
}
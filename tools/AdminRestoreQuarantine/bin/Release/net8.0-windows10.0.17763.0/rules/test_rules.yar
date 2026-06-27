/*
    Règle de test - Détecte un fichier contenant le mot "X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-"
    C'est le fichier de test EICAR standard
*/

rule EICAR_Test
{
    meta:
        description = "Detects the EICAR test file"
        severity = "test"
        author = "optiSCAN"
        
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-"
        
    condition:
        $eicar
}
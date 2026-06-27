using optiCombat.Services;

if (!OperatingSystem.IsWindows())
{
    Console.Error.WriteLine("Windows uniquement.");
    return 1;
}

var id = args.FirstOrDefault(a => !a.StartsWith('-'));
if (string.IsNullOrWhiteSpace(id))
{
    Console.Error.WriteLine("Usage: AdminRestoreQuarantine <quarantineId>");
    return 1;
}

var qm = new QuarantineManager();
var entry = qm.GetEntriesPaged(0, 1000).FirstOrDefault(e => e.Id == id);
if (entry == null)
{
    Console.Error.WriteLine($"Entrée introuvable: {id}");
    return 2;
}

Console.WriteLine($"Restauration admin vers: {entry.OriginalPath}");
if (!qm.RestoreAdministrative(id))
{
    Console.Error.WriteLine("Échec (droits admin, fichier .quar ou disque).");
    return 3;
}

Console.WriteLine("OK.");
return 0;

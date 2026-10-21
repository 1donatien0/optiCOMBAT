namespace optiCombat.Services
{
    /// <summary>Arguments de ligne de commande pour scans sans interface (tâche planifiée).</summary>
    public static class HeadlessScanArguments
    {
        public const string FullScan = "--fullscan";
        public const string QuickScan = "--quickscan";
        public const string Quiet = "--quiet";
        public const string Guard = "--guard";
        public const string Watchdog = "--watchdog";
        public const string ServiceHost = "--service-host";
        public const string DefenderExclusions = "--defender-exclusions";

        public enum Mode { None, FullScan, QuickScan, Guard, Watchdog, ServiceHost, DefenderExclusions }

        public static Mode ParseMode(IReadOnlyList<string> args)
        {
            foreach (var a in args)
            {
                if (string.Equals(a, Watchdog, StringComparison.OrdinalIgnoreCase))
                    return Mode.Watchdog;
                if (string.Equals(a, Guard, StringComparison.OrdinalIgnoreCase))
                    return Mode.Guard;
                if (string.Equals(a, ServiceHost, StringComparison.OrdinalIgnoreCase))
                    return Mode.ServiceHost;
                if (string.Equals(a, DefenderExclusions, StringComparison.OrdinalIgnoreCase))
                    return Mode.DefenderExclusions;
                if (string.Equals(a, FullScan, StringComparison.OrdinalIgnoreCase))
                    return Mode.FullScan;
                if (string.Equals(a, QuickScan, StringComparison.OrdinalIgnoreCase))
                    return Mode.QuickScan;
            }
            return Mode.None;
        }

        public static bool IsQuiet(IReadOnlyList<string> args) =>
            args.Any(a => string.Equals(a, Quiet, StringComparison.OrdinalIgnoreCase));
    }
}

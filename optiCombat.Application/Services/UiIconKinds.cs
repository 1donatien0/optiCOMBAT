namespace optiCombat.Services
{
    /// <summary>
    /// Noms <see cref="MaterialDesignThemes.Wpf.PackIconKind"/> pour l'UI WPF (pas d'emojis dans les textes).
    /// </summary>
    internal static class UiIconKinds
    {
        public const string Success = "CheckCircle";
        public const string Error = "CloseCircle";
        public const string Warning = "Alert";
        public const string Info = "InformationOutline";
        public const string Shield = "Shield";
        public const string ShieldCheck = "ShieldCheck";
        public const string ShieldOff = "ShieldOff";
        public const string Lock = "Lock";
        public const string Delete = "TrashCanOutline";
        public const string Refresh = "Refresh";
        public const string Stop = "StopCircleOutline";
        public const string EyeOff = "EyeOff";
        public const string Wrench = "Wrench";
        public const string Broom = "Broom";

        public static string ForRiskLevel(RiskLevel level) => level switch
        {
            RiskLevel.Critical => "AlertOctagon",
            RiskLevel.Major => "Alert",
            RiskLevel.Minor => "AlertCircleOutline",
            _ => "InformationOutline"
        };

        public static string ForStatusFooter(bool isError, bool isWarning) =>
            isError ? Error : isWarning ? Warning : Success;
    }

    /// <summary>Préfixes texte pour journaux / exports (sans emoji).</summary>
    internal static class UiLogText
    {
        public const string OkPrefix = "[OK]";
        public const string ErrorPrefix = "[Erreur]";
        public const string WarnPrefix = "[Attention]";
        public const string InfoPrefix = "[Info]";

        public static string Ok(string message) => $"{OkPrefix} {message}";
        public static string Error(string message) => $"{ErrorPrefix} {message}";
        public static string Warn(string message) => $"{WarnPrefix} {message}";
        public static string Info(string message) => $"{InfoPrefix} {message}";
        public static string ReadyLine(string name) => $"{OkPrefix} {name}";
        public static string MissingLine(string name) => $"{ErrorPrefix} {name}";
    }
}

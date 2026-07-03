namespace optiCombat.Services
{
    /// <summary>Masque les chemins sensibles dans exports et journaux.</summary>
    internal static class PathRedaction
    {
        /// <summary>Remplace le profil utilisateur par <c>%UserProfile%</c>.</summary>
        public static string RedactPath(string? path)
        {
            if (string.IsNullOrEmpty(path))
                return string.Empty;

            var profile = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
            if (!string.IsNullOrEmpty(profile)
                && path.StartsWith(profile, StringComparison.OrdinalIgnoreCase))
                return "%UserProfile%" + path[profile.Length..];

            return path;
        }
    }
}

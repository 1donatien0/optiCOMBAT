namespace optiCombat.Models
{
    public sealed class SecurityPostureCheck
    {
        public required string Id { get; init; }
        public required string Title { get; init; }
        public bool Passed { get; init; }
        public int Weight { get; init; }
        public string? FixUri { get; init; }
    }

    public sealed class SecurityPostureReport
    {
        public int Score { get; init; }
        public IReadOnlyList<SecurityPostureCheck> Checks { get; init; } = Array.Empty<SecurityPostureCheck>();
    }
}

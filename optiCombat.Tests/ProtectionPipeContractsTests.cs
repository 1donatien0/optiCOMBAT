using optiCombat.Platform;
using System.Text.Json;

namespace optiCombat.Tests;

public sealed class ProtectionPipeContractsTests
{
    private static readonly JsonSerializerOptions JsonOptions = new() { PropertyNameCaseInsensitive = true };

    [Fact]
    public void Request_serializes_scan_path_operation()
    {
        var request = new ProtectionPipeRequest
        {
            Operation = ProtectionPipeOperations.ScanPath,
            Path = @"C:\test\eicar.com",
        };

        var json = JsonSerializer.Serialize(request, JsonOptions);
        var roundTrip = JsonSerializer.Deserialize<ProtectionPipeRequest>(json, JsonOptions);

        Assert.NotNull(roundTrip);
        Assert.Equal(ProtectionPipeOperations.ScanPath, roundTrip!.Operation);
        Assert.Equal(request.Path, roundTrip.Path);
    }

    [Fact]
    public void Response_threat_factory_sets_fields()
    {
        var response = ProtectionPipeResponse.Threat("EICAR_Test", "YARA");

        Assert.True(response.Ok);
        Assert.False(response.Clean);
        Assert.Equal("EICAR_Test", response.ThreatName);
        Assert.Equal("YARA", response.Engine);
    }
}

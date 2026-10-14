using optiCombat.Services;

namespace optiCombat.Tests;

/// <summary>
/// Classification des codes de sortie winget. Ces tests protègent la règle
/// métier du panneau « Mises à jour » : seules les issues résolues font
/// disparaître une ligne de la liste ; tout le reste doit rester affiché.
/// </summary>
public sealed class WingetUpgradeStatusTests
{
    [Fact]
    public void ExitCode_zero_is_success()
    {
        Assert.Equal(WingetUpgradeStatus.Succeeded, WingetUpdateService.ClassifyExitCode(0));
    }

    [Theory]
    [InlineData(unchecked((int)0x8A15002B))] // UPDATE_NOT_APPLICABLE
    [InlineData(unchecked((int)0x8A15004F))] // UPGRADE_VERSION_NOT_NEWER
    public void No_op_exit_codes_are_already_up_to_date(int exitCode)
    {
        Assert.Equal(WingetUpgradeStatus.AlreadyUpToDate, WingetUpdateService.ClassifyExitCode(exitCode));
    }

    [Theory]
    [InlineData(unchecked((int)0x8A150109))] // REBOOT_REQUIRED_TO_FINISH
    [InlineData(unchecked((int)0x8A15010A))] // REBOOT_REQUIRED_FOR_INSTALL
    [InlineData(unchecked((int)0x8A15010B))] // REBOOT_INITIATED
    [InlineData(3010)]                       // ERROR_SUCCESS_REBOOT_REQUIRED
    [InlineData(1641)]                       // ERROR_SUCCESS_REBOOT_INITIATED
    public void Reboot_exit_codes_are_reboot_required(int exitCode)
    {
        Assert.Equal(WingetUpgradeStatus.RebootRequired, WingetUpdateService.ClassifyExitCode(exitCode));
    }

    [Theory]
    [InlineData(unchecked((int)0x8A15010C))] // INSTALL_CANCELLED_BY_USER
    [InlineData(unchecked((int)0x8A150005))] // CTRL_SIGNAL_RECEIVED
    [InlineData(unchecked((int)0x8A15006A))] // APPTERMINATION_RECEIVED
    [InlineData(unchecked((int)0x8A150077))] // AUTHENTICATION_CANCELLED_BY_USER
    [InlineData(1223)]                       // ERROR_CANCELLED (UAC refusé)
    [InlineData(1602)]                       // ERROR_INSTALL_USEREXIT
    public void Cancellation_exit_codes_are_cancelled(int exitCode)
    {
        Assert.Equal(WingetUpgradeStatus.CancelledByUser, WingetUpdateService.ClassifyExitCode(exitCode));
    }

    [Theory]
    [InlineData(1)]
    [InlineData(-1)]
    [InlineData(unchecked((int)0x8A150008))] // DOWNLOAD_FAILED
    [InlineData(unchecked((int)0x8A150105))] // INSTALL_DISK_FULL
    [InlineData(unchecked((int)0x8A150019))] // COMMAND_REQUIRES_ADMIN
    [InlineData(unchecked((int)0x8A150068))] // PACKAGE_IS_PINNED
    public void Unknown_exit_codes_fall_back_to_failed(int exitCode)
    {
        // Repli prudent : un code non reconnu laisse le paquet dans la liste.
        Assert.Equal(WingetUpgradeStatus.Failed, WingetUpdateService.ClassifyExitCode(exitCode));
    }

    [Theory]
    [InlineData(unchecked((int)0x8A15010D))] // INSTALL_ALREADY_INSTALLED
    [InlineData(unchecked((int)0x8A150114))] // INSTALL_UPGRADE_NOT_SUPPORTED
    public void Misleading_codes_are_not_treated_as_up_to_date(int exitCode)
    {
        // Ces codes ressemblent à « déjà à jour » mais la mise à niveau n'a pas
        // eu lieu : la ligne doit rester dans la liste.
        var status = WingetUpdateService.ClassifyExitCode(exitCode);
        Assert.Equal(WingetUpgradeStatus.Failed, status);
    }

    [Theory]
    [InlineData(WingetUpgradeStatus.Succeeded, true)]
    [InlineData(WingetUpgradeStatus.AlreadyUpToDate, true)]
    [InlineData(WingetUpgradeStatus.RebootRequired, false)]
    [InlineData(WingetUpgradeStatus.CancelledByUser, false)]
    [InlineData(WingetUpgradeStatus.Failed, false)]
    public void IsResolved_only_for_settled_outcomes(WingetUpgradeStatus status, bool expected)
    {
        var result = new WingetUpgradeResult
        {
            Package = new WingetPackageUpdate { Name = "Test", Id = "Test.Id" },
            ExitCode = 0,
            Status = status,
        };
        Assert.Equal(expected, result.IsResolved);
    }
}

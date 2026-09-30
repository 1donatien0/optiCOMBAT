using Moq;
using optiCombat.Coordinators;
using optiCombat.Services;

namespace optiCombat.Tests;

[Collection("Localization")]
public sealed class OnboardingCoordinatorTests
{
  private static (OnboardingCoordinator.Host host, UserPreferences prefs, Mock<IUserConfirmService> confirm, List<string> calls)
    Build(bool defenderActive, params bool[] answers)
  {
    var prefs = new UserPreferences();
    var calls = new List<string>();
    var confirm = new Mock<IUserConfirmService>();
    var queue = new Queue<bool>(answers);
    confirm.Setup(c => c.ConfirmYesNo(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>()))
      .Returns(() => queue.Count > 0 && queue.Dequeue());
    var host = new OnboardingCoordinator.Host
    {
      Confirm = confirm.Object,
      Preferences = prefs,
      SavePreferences = () => calls.Add("save"),
      IsDefenderActive = () => defenderActive,
      ApplyDefenderComplement = c => calls.Add("complement:" + c),
      StartSignatureUpdate = () => calls.Add("update"),
    };
    return (host, prefs, confirm, calls);
  }

  [Fact]
  public void Skipped_when_already_completed_or_scans_exist()
  {
    var (host, prefs, confirm, _) = Build(false);
    prefs.OnboardingCompleted = true;
    Assert.False(OnboardingCoordinator.RunIfNeeded(host));

    var (host2, prefs2, confirm2, calls2) = Build(false);
    prefs2.TotalScansCount = 3;
    Assert.False(OnboardingCoordinator.RunIfNeeded(host2));
    Assert.True(prefs2.OnboardingCompleted);
    Assert.Contains("save", calls2);
    confirm.VerifyNoOtherCalls();
    confirm2.VerifyNoOtherCalls();
  }

  [Fact]
  public void Declining_the_guide_marks_it_completed()
  {
    var (host, prefs, _, calls) = Build(true, false);
    Assert.True(OnboardingCoordinator.RunIfNeeded(host));
    Assert.True(prefs.OnboardingCompleted);
    Assert.DoesNotContain(calls, c => c.StartsWith("complement", StringComparison.Ordinal));
  }

  [Fact]
  public void Full_path_with_defender_applies_choice_and_starts_update()
  {
    var (host, prefs, confirm, calls) = Build(true, true, true, true);
    Assert.True(OnboardingCoordinator.RunIfNeeded(host));
    Assert.Equal(new[] { "complement:True", "update", "save" }, calls);
    Assert.True(prefs.OnboardingCompleted);
    confirm.Verify(c => c.Inform(It.IsAny<string>(), It.IsAny<string>()), Times.Once);
  }

  [Fact]
  public void Without_defender_no_coexistence_question()
  {
    var (host, _, confirm, calls) = Build(false, true, false);
    OnboardingCoordinator.RunIfNeeded(host);
    Assert.Equal(new[] { "save" }, calls);
    confirm.Verify(c => c.ConfirmYesNo(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<bool>()), Times.Exactly(2));
  }
}

using optiCombat.Services;

namespace optiCombat.Tests;

public sealed class ScheduledScanApplyTests
{
    private sealed class FakeScheduledScanService : IScheduledScanService
    {
        public bool? LastEnable;
        public TimeSpan? LastTime;
        public bool CreateResult = true;
        public bool DeleteResult = true;
        public bool Exists { get; set; }
        public int CreateCalls;
        public int DeleteCalls;

        public bool CreateDailyScan(TimeSpan? time = null)
        {
            CreateCalls++;
            LastEnable = true;
            LastTime = time;
            return CreateResult;
        }

        public bool DeleteTask()
        {
            DeleteCalls++;
            LastEnable = false;
            return DeleteResult;
        }

        public bool IsTaskExists() => Exists;

        public DateTime? GetNextRunTime() => null;

        public bool RunNow() => true;
    }

    [Fact]
    public void SetEnabled_true_calls_CreateDailyScan_with_time()
    {
        var fake = new FakeScheduledScanService();
        var time = new TimeSpan(3, 15, 0);

        Assert.True(ScheduledScanApply.SetEnabled(true, time, fake));

        Assert.Equal(1, fake.CreateCalls);
        Assert.Equal(0, fake.DeleteCalls);
        Assert.Equal(time, fake.LastTime);
    }

    [Fact]
    public void SetEnabled_false_calls_DeleteTask()
    {
        var fake = new FakeScheduledScanService();

        Assert.True(ScheduledScanApply.SetEnabled(false, null, fake));

        Assert.Equal(0, fake.CreateCalls);
        Assert.Equal(1, fake.DeleteCalls);
    }

    [Fact]
    public void SetEnabled_true_propagates_create_failure()
    {
        var fake = new FakeScheduledScanService { CreateResult = false };

        Assert.False(ScheduledScanApply.SetEnabled(true, TimeSpan.FromHours(2), fake));
    }
}

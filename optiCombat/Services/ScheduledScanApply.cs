namespace optiCombat.Services
{
    /// <summary>
    /// Active ou désactive le scan planifié quotidien (logique pure, testable sans schtasks).
    /// </summary>
    public static class ScheduledScanApply
    {
        /// <summary>
        /// Crée ou supprime la tâche Windows selon <paramref name="enable"/>.
        /// </summary>
        /// <returns>Succès de l'opération schtasks (toujours true pour <c>enable == false</c> si DeleteTask ne lève pas).</returns>
        public static bool SetEnabled(bool enable, TimeSpan? dailyTime, IScheduledScanService service)
        {
            ArgumentNullException.ThrowIfNull(service);
            return enable
                ? service.CreateDailyScan(dailyTime)
                : service.DeleteTask();
        }
    }
}

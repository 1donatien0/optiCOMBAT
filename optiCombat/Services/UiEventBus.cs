using optiCombat.Models;

namespace optiCombat.Services;

/// <summary>
/// Implémentation du bus UI partagé (singleton DI). Découplé de <see cref="ServiceContainer"/>
/// pour permettre l'injection dans les services d'arrière-plan (ex. <see cref="RemovableDriveScanService"/>).
/// </summary>
public sealed class UiEventBus : IUiEventBus
{
    private EventHandler? _requestSignatureUpdateHandlers;
    private EventHandler? _focusAntivirusSignaturesHandlers;
    private EventHandler? _scanHistoryViewsRefreshHandlers;
    private EventHandler? _exportScanHistoryHtmlHandlers;
    private EventHandler<ScanSession>? _exportScanSessionPdfHandlers;
    private EventHandler<ScanSession>? _reviewHistorySessionHandlers;
    private EventHandler? _openQuarantineTabHandlers;
    private EventHandler? _protectionStateRefreshHandlers;

    public event EventHandler? RequestSignatureUpdate
    {
        add => _requestSignatureUpdateHandlers += value;
        remove => _requestSignatureUpdateHandlers -= value;
    }

    public void TriggerSignatureUpdate() =>
        _requestSignatureUpdateHandlers?.Invoke(this, EventArgs.Empty);

    public event EventHandler? FocusAntivirusSignaturesRequested
    {
        add => _focusAntivirusSignaturesHandlers += value;
        remove => _focusAntivirusSignaturesHandlers -= value;
    }

    public void RequestFocusAntivirusSignaturesTab() =>
        _focusAntivirusSignaturesHandlers?.Invoke(this, EventArgs.Empty);

    public event EventHandler? ScanHistoryViewsRefreshRequested
    {
        add => _scanHistoryViewsRefreshHandlers += value;
        remove => _scanHistoryViewsRefreshHandlers -= value;
    }

    public void RequestScanHistoryViewsRefresh() =>
        _scanHistoryViewsRefreshHandlers?.Invoke(this, EventArgs.Empty);

    public event EventHandler? ExportScanHistoryHtmlRequested
    {
        add => _exportScanHistoryHtmlHandlers += value;
        remove => _exportScanHistoryHtmlHandlers -= value;
    }

    public void RequestExportScanHistoryHtml() =>
        _exportScanHistoryHtmlHandlers?.Invoke(this, EventArgs.Empty);

    public event EventHandler<ScanSession>? ExportScanSessionPdfRequested
    {
        add => _exportScanSessionPdfHandlers += value;
        remove => _exportScanSessionPdfHandlers -= value;
    }

    public void RequestExportScanSessionPdf(ScanSession session) =>
        _exportScanSessionPdfHandlers?.Invoke(this, session);

    public event EventHandler<ScanSession>? ReviewHistorySessionRequested
    {
        add => _reviewHistorySessionHandlers += value;
        remove => _reviewHistorySessionHandlers -= value;
    }

    public void RequestReviewHistorySession(ScanSession session) =>
        _reviewHistorySessionHandlers?.Invoke(this, session);

    public event EventHandler? OpenQuarantineTabRequested
    {
        add => _openQuarantineTabHandlers += value;
        remove => _openQuarantineTabHandlers -= value;
    }

    public void RequestOpenQuarantineTab() =>
        _openQuarantineTabHandlers?.Invoke(this, EventArgs.Empty);

    public event EventHandler? ProtectionStateRefreshRequested
    {
        add => _protectionStateRefreshHandlers += value;
        remove => _protectionStateRefreshHandlers -= value;
    }

    public void RequestProtectionStateRefresh() =>
        _protectionStateRefreshHandlers?.Invoke(this, EventArgs.Empty);

    /// <summary>Libère les abonnements au shutdown applicatif.</summary>
    internal void ClearHandlers()
    {
        _requestSignatureUpdateHandlers = null;
        _focusAntivirusSignaturesHandlers = null;
        _scanHistoryViewsRefreshHandlers = null;
        _exportScanHistoryHtmlHandlers = null;
        _exportScanSessionPdfHandlers = null;
        _reviewHistorySessionHandlers = null;
        _openQuarantineTabHandlers = null;
        _protectionStateRefreshHandlers = null;
    }
}

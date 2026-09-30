using optiCombat.Localization;
using optiCombat.Models;
using System.Globalization;
using System.Linq;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;
using System.IO;

namespace optiCombat.Services
{
    /// <summary>
    /// Génère des rapports PDF complets à partir d'un ScanResult.
    /// Utilise QuestPDF (licence Community).
    /// </summary>
    public class PdfReportGenerator
    {
        static PdfReportGenerator()
        {
            QuestPDF.Settings.License = LicenseType.Community;
        }

        private static string RedactPath(string? path) => PathRedaction.RedactPath(path);

        /// <summary>
        /// Génère un rapport PDF et le sauvegarde au chemin indiqué.
        /// Retourne les octets du PDF généré.
        /// </summary>
        public byte[] GenerateReport(ScanResult result, string outputPath = "")
        {
            // AssessAll évalue TOUTES les menaces et retourne la plus sévère
            var riskAssessment = RiskScoringService.AssessAll(result.Threats);
            var cult = CultureInfo.CurrentCulture;
            static string L(string key) => LocalizationService.GetString(key);
            var headerWhen = DateTime.Now.ToString("g", cult);

            var document = Document.Create(container =>
            {
                container.Page(page =>
                {
                    page.Size(PageSizes.A4);
                    page.Margin(2, Unit.Centimetre);
                    page.DefaultTextStyle(x => x.FontFamily("Segoe UI"));

                    // ── En-tête ──────────────────────────────────────────────
                    page.Header()
                        .Row(row =>
                        {
                            row.AutoItem()
                                .Text("optiCombat")
                                .FontSize(24)
                                .FontColor(Colors.Blue.Darken2)
                                .Bold();

                            row.Spacing(10);

                            row.RelativeItem()
                                .AlignRight()
                                .Text(LocalizationService.Format("Export_Pdf_HeaderSubtitle", headerWhen))
                                .FontSize(10)
                                .FontColor(Colors.Grey.Medium);
                        });

                    // ── Contenu ──────────────────────────────────────────────
                    page.Content()
                        .PaddingVertical(10)
                        .Column(col =>
                        {
                            // Résumé
                            col.Item()
                                .BorderBottom(1).BorderColor(Colors.Grey.Lighten2)
                                .PaddingBottom(5)
                                .Text(L("Export_Pdf_Summary"))
                                .FontSize(14).Bold()
                                .FontColor(Colors.Blue.Darken2);

                            col.Item().PaddingTop(10)
                                .Table(table =>
                                {
                                    table.ColumnsDefinition(cols =>
                                    {
                                        cols.ConstantColumn(130);
                                        cols.RelativeColumn();
                                    });

                                    AddRow(table, L("Export_Pdf_RowType"), result.TypeDisplay);
                                    AddRow(table, L("Export_Pdf_RowTarget"), RedactPath(result.TargetPath));
                                    AddRow(table, L("Export_Pdf_RowStart"), result.StartedAt.ToString("G", cult));
                                    if (result.FinishedAt.HasValue)
                                        AddRow(table, L("Export_Pdf_RowEnd"), result.FinishedAt.Value.ToString("G", cult));
                                    AddRow(table, L("Export_Pdf_RowDuration"),
                                        LocalizationService.Format("Export_Pdf_DurationSeconds", $"{result.Duration.TotalSeconds:F0}"));
                                    AddRow(table, L("Export_Pdf_RowFiles"), result.FilesScanned.ToString("N0", cult));

                                    table.Cell().Text(L("Export_Pdf_RowThreats")).FontSize(11).SemiBold();
                                    table.Cell().Text($"{result.ThreatsFound}")
                                        .FontSize(11)
                                        .FontColor(result.ThreatsFound > 0 ? Colors.Red.Medium : Colors.Green.Medium);
                                });

                            // Évaluation de risque
                            if (result.Threats.Count > 0)
                            {
                                col.Item().PaddingTop(15)
                                    .BorderBottom(1).BorderColor(Colors.Grey.Lighten2)
                                    .PaddingBottom(5)
                                    .Text(L("Export_Pdf_RiskTitle"))
                                    .FontSize(14).Bold()
                                    .FontColor(Colors.Blue.Darken2);

                                col.Item().PaddingTop(8)
                                    .Border(1).BorderColor(Colors.Grey.Lighten1)
                                    .Padding(10)
                                    .Column(riskCol =>
                                    {
                                        riskCol.Item().Row(row =>
                                        {
                                            row.AutoItem()
                                                .Text(riskAssessment.Severity)
                                                .FontSize(16).Bold();
                                            row.Spacing(20);
                                            row.AutoItem()
                                                .Text(LocalizationService.Format("Export_Pdf_Score", riskAssessment.Score))
                                                .FontSize(12)
                                                .FontColor(Colors.Grey.Darken1);
                                        });

                                        riskCol.Item().PaddingTop(5)
                                            .Text(riskAssessment.Recommendation)
                                            .FontSize(11)
                                            .FontColor(Colors.Grey.Darken1);

                                        if (riskAssessment.Reasons.Count > 0)
                                        {
                                            riskCol.Item().PaddingTop(5)
                                                .Text("• " + string.Join("\n• ", riskAssessment.Reasons))
                                                .FontSize(10)
                                                .FontColor(Colors.Grey.Medium);
                                        }
                                    });

                                // Liste des menaces
                                col.Item().PaddingTop(15)
                                    .BorderBottom(1).BorderColor(Colors.Grey.Lighten2)
                                    .PaddingBottom(5)
                                    .Text(L("Export_Pdf_ThreatsTitle"))
                                    .FontSize(14).Bold()
                                    .FontColor(Colors.Blue.Darken2);

                                col.Item().PaddingTop(10)
                                    .Table(table =>
                                    {
                                        table.ColumnsDefinition(cols =>
                                        {
                                            cols.RelativeColumn(4);
                                            cols.RelativeColumn(3);
                                            cols.RelativeColumn(1);
                                        });

                                        table.Header(header =>
                                        {
                                            header.Cell().Text(L("Export_Pdf_ColLocation")).FontSize(10).Bold();
                                            header.Cell().Text(L("Export_Pdf_ColThreat")).FontSize(10).Bold();
                                            header.Cell().Text(L("Export_Pdf_ColTime")).FontSize(10).Bold();
                                        });

                                        foreach (var threat in result.Threats)
                                        {
                                            table.Cell().Text(RedactPath(threat.FilePath)).FontSize(8);
                                            table.Cell().Text(threat.VirusName).FontSize(9).FontColor(Colors.Red.Medium);
                                            table.Cell().Text(threat.DetectedAt.ToString("T", cult)).FontSize(9);
                                        }
                                    });
                            }
                            else
                            {
                                col.Item().PaddingTop(15)
                                    .Background(Colors.Green.Lighten3)
                                    .Padding(10)
                                    .AlignCenter()
                                    .Text(L("Export_Pdf_NoThreats"))
                                    .FontSize(12)
                                    .FontColor(Colors.Green.Darken2);
                            }
                        });

                    // ── Pied de page ─────────────────────────────────────────
                    page.Footer()
                        .AlignCenter()
                        .DefaultTextStyle(s => s.FontSize(8).FontColor(Colors.Grey.Medium))
                        .Text(x =>
                        {
                            x.Span(LocalizationService.Format(
                                "Export_Pdf_Footer",
                                ProductVersionInfo.ReleaseLabel,
                                ProductVersionInfo.SemVer,
                                DateTime.Now.ToString("G", cult)));
                            x.CurrentPageNumber();
                            x.Span(" / ");
                            x.TotalPages();
                        });
                });
            });

            var pdfBytes = document.GeneratePdf();

            if (!string.IsNullOrEmpty(outputPath))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(outputPath)!);
                File.WriteAllBytes(outputPath, pdfBytes);
            }

            return pdfBytes;
        }

        /// <summary>
        /// Rapport PDF à partir d’une entrée d’historique (sans liste détaillée des fichiers si elle n’a pas été conservée).
        /// </summary>
        public byte[] GenerateReportFromSession(ScanSession session, string outputPath = "")
        {
            var result = new ScanResult
            {
                SessionId = session.SessionId,
                StartedAt = session.StartedAt,
                FinishedAt = session.FinishedAt,
                TargetPath = session.TargetPath,
                FilesScanned = session.FilesScanned,
                Status = Enum.TryParse<ScanStatus>(session.StatusDisplay, ignoreCase: true, out var st)
                    ? st
                    : ScanStatus.Completed,
                Type = MapScanType(session.TypeDisplay),
            };

            if (session.Threats.Count > 0)
                result.Threats = session.Threats.Select(t => t.Clone()).ToList();
            else if (session.ThreatsFound > 0)
            {
                var path = string.IsNullOrWhiteSpace(session.TargetPath) ? "—" : session.TargetPath;
                var at = session.FinishedAt ?? session.StartedAt;
                for (int i = 0; i < session.ThreatsFound; i++)
                {
                    result.Threats.Add(new ThreatInfo
                    {
                        FilePath = path,
                        VirusName = session.ThreatsFound == 1
                            ? LocalizationService.GetString("Export_Pdf_ThreatLegacySingle")
                            : LocalizationService.Format("Export_Pdf_ThreatLegacyMulti", i + 1, session.ThreatsFound),
                        DetectedAt = at,
                        DetectedBy = "historique"
                    });
                }
            }

            return GenerateReport(result, outputPath);
        }

        private static ScanType MapScanType(string typeDisplay)
        {
            foreach (ScanType t in Enum.GetValues<ScanType>())
            {
                if (string.Equals(typeDisplay, LocalizationService.ScanTypeDisplay(t), StringComparison.OrdinalIgnoreCase))
                    return t;
            }
            return ScanType.Folder;
        }

        /// <summary>
        /// Génère et sauvegarde automatiquement dans %LocalAppData%\optiCombat\Reports\
        /// Retourne le chemin du fichier créé.
        /// </summary>
        public string GenerateAndSave(ScanResult result)
        {
            var fileName = $"SCAN_{result.TypeDisplay}_{result.StartedAt:yyyyMMdd_HHmmss}.pdf";
            // Supprimer les caractères invalides
            foreach (var c in Path.GetInvalidFileNameChars())
                fileName = fileName.Replace(c, '_');

            var outputPath = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                "optiCombat", "Reports", fileName);

            GenerateReport(result, outputPath);
            return outputPath;
        }

        // ── Helpers ──────────────────────────────────────────────────────────────

        private static void AddRow(TableDescriptor table, string label, string value)
        {
            table.Cell().Text(label).FontSize(11).SemiBold();
            table.Cell().Text(value).FontSize(11);
        }
    }
}

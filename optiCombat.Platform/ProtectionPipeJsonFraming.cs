using System.Text;
using System.Text.Json;

namespace optiCombat.Platform;

public static class ProtectionPipeJsonFraming
{
    public static async Task<string> ReadJsonPayloadAsync(Stream stream, CancellationToken ct, int maxBytes = 1024 * 1024)
    {
        using var ms = new MemoryStream();
        var buf = new byte[8192];

        while (ms.Length < maxBytes)
        {
            var read = await stream.ReadAsync(buf, ct).ConfigureAwait(false);
            if (read <= 0)
                break;

            ms.Write(buf, 0, read);
            var text = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
            if (IsCompleteJson(text))
                return text;
        }

        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static bool IsCompleteJson(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
            return false;

        try
        {
            using var _ = JsonDocument.Parse(text);
            return true;
        }
        catch (JsonException)
        {
            return false;
        }
    }
}

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
            // On ne tente l'analyse (coûteuse) que si le flux se termine par '}' : auparavant chaque
            // bloc de 8 Kio redécodait et réanalysait tout le message (coût quadratique).
            if (!EndsWithClosingBrace(ms.GetBuffer(), (int)ms.Length))
                continue;
            var text = Encoding.UTF8.GetString(ms.GetBuffer(), 0, (int)ms.Length);
            if (IsCompleteJson(text))
                return text;
        }

        return Encoding.UTF8.GetString(ms.ToArray());
    }

    private static bool EndsWithClosingBrace(byte[] buffer, int length)
    {
        for (int i = length - 1; i >= 0; i--)
        {
            var b = buffer[i];
            if (b is (byte)' ' or (byte)'\t' or (byte)'\r' or (byte)'\n' or 0)
                continue;
            return b == (byte)'}';
        }
        return false;
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

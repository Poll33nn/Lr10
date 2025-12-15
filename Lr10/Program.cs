using System.Text.Json;

namespace Lr10
{
    class Program
    {
        private const string ApiKey = "7a01139cf3d43d65accc9fd07c2bbf8402b1f884570bdaa761917609874aba47";
        private static readonly HttpClient client = new();

        static async Task Main(string[] args)
        {
            if (args.Length == 0)
            {
                Console.WriteLine("Укажите путь к файлу");
                return;
            }

            string filePath = args[0];
            if (!File.Exists(filePath))
            {
                Console.WriteLine("Файл не найден.");
                return;
            }

            string fileHash = ComputeSha256(filePath);
            Console.WriteLine($"SHA-256: {fileHash}");

            var result = await QueryVirusTotalAsync(fileHash);
            if (result != null)
            {
                int detected = result.data.attributes.last_analysis_stats.malicious;
                int total = result.data.attributes.last_analysis_stats.total;

                Console.WriteLine($"\nРезультат анализа:");
                Console.WriteLine($"Всего движков: {total}");
                Console.WriteLine($"Обнаружено вредоносным: {detected}");
                Console.WriteLine($"Статус: {(detected > 0 ? "⚠️ ПОДОЗРИТЕЛЬНЫЙ" : "✅ ЧИСТЫЙ")}");

                foreach (var vendor in result.data.attributes.last_analysis_results)
                {
                    if (vendor.Value.category == "malicious")
                    {
                        Console.WriteLine($"- {vendor.Key}: {vendor.Value.result}");
                    }
                }
            }
            else
            {
                Console.WriteLine("Файл не найден в базе VirusTotal.");
            }
        }

        static string ComputeSha256(string filePath)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            using var stream = File.OpenRead(filePath);
            var hash = sha256.ComputeHash(stream);
            return BitConverter.ToString(hash).Replace("-", "").ToLowerInvariant();
        }

        static async Task<VtResponse?> QueryVirusTotalAsync(string sha256)
        {
            client.DefaultRequestHeaders.Add("x-apikey", ApiKey);
            var url = $"https://www.virustotal.com/api/v3/files/{sha256}";

            try
            {
                var response = await client.GetAsync(url);
                if (response.IsSuccessStatusCode)
                {
                    var json = await response.Content.ReadAsStringAsync();
                    return JsonSerializer.Deserialize<VtResponse>(json);
                }
                return null;
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Ошибка: {ex.Message}");
                return null;
            }
        }
    }

    public class VtResponse
    {
        public VtData data { get; set; } = null!;
    }

    public class VtData
    {
        public VtAttributes attributes { get; set; } = null!;
    }

    public class VtAttributes
    {
        public VtAnalysisStats last_analysis_stats { get; set; } = null!;
        public Dictionary<string, VtAnalysisResult> last_analysis_results { get; set; } = new();
    }

    public class VtAnalysisStats
    {
        public int malicious { get; set; }
        public int total { get; set; }
    }

    public class VtAnalysisResult
    {
        public string category { get; set; } = "";
        public string result { get; set; } = "";
    }
}

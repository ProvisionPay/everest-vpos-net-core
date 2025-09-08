using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Net.Http;
using System.Threading.Tasks;
using System.Collections.Generic;

// 3D Secure isteğinde bankaya gönderilecek alanları tutan model
public class SecureRequest
{
    [JsonPropertyName("transactionType")] public string TransactionType { get; set; }   // İşlem tipi
    [JsonPropertyName("orderId")] public string OrderId { get; set; }                   // Sipariş numarası
    [JsonPropertyName("pan")] public string Pan { get; set; }                           // Kart numarası
    [JsonPropertyName("cardHolderName")] public string CardHolderName { get; set; }     // Kart sahibi adı
    [JsonPropertyName("expireDate")] public string ExpireDate { get; set; }             // SKT (MMYY)
    [JsonPropertyName("cvv2")] public string Cvv2 { get; set; }                         // Güvenlik kodu
    [JsonPropertyName("transactionAmount")] public string TransactionAmount { get; set; } // İşlem tutarı
    [JsonPropertyName("currencyCode")] public string CurrencyCode { get; set; }         // Para birimi (949 = TL)
    [JsonPropertyName("installmentCount")] public string InstallmentCount { get; set; } // Taksit sayısı
    [JsonPropertyName("acquirerMerchantId")] public string AcquirerMerchantId { get; set; } // Üye işyeri numarası
    [JsonPropertyName("userId")] public string UserId { get; set; }                     // Üye işyeri kullanıcı kodu
    [JsonPropertyName("okUrl")] public string OkUrl { get; set; }                       // Başarılı dönüş URL
    [JsonPropertyName("failUrl")] public string FailUrl { get; set; }                   // Hatalı dönüş URL
    [JsonPropertyName("storeType")] public string StoreType { get; set; }               // Mağaza tipi (3d vb.)
    [JsonPropertyName("rnd")] public string Rnd { get; set; }                           // Rastgele değer
    [JsonPropertyName("linkPaymentToken")] public string LinkPaymentToken { get; set; } // (Opsiyonel)
    [JsonPropertyName("timeStamp")] public string TimeStamp { get; set; }               // Zaman damgası
    [JsonPropertyName("hash")] public string Hash { get; set; }                         // SHA512 hash değeri
}

// Hash üretimi için kullanılacak değerleri dönen model
public class HashInputResult
{
    public string HashInput { get; set; }  // Hash'e girecek metin
    public string Timestamp { get; set; }  // Zaman damgası
    public string RandomHex { get; set; }  // Rastgele üretilen hex
}

// Banka dönüşlerini temsil eden model
public class SecureResponse
{
    public string ResponseCode { get; set; }
    public string ResponseReasonCode { get; set; }
    public string ResponseMessage { get; set; }
    public string OrderId { get; set; }
    public string AuthorizationNumber { get; set; }
    public string RRN { get; set; }
    public string Stan { get; set; }
    public string TransactionId { get; set; }
    public DateTime TransactionDate { get; set; }
    public bool IsError { get; set; }
    public bool Success { get; set; }
}

// 3D Secure API’den dönen genel cevap yapısı
public class GatewayResponse
{
    public AuthenticationResult AuthenticationResult { get; set; }
    public Result Result { get; set; }
    public TransactionResponse TransactionResponse { get; set; }
}

// 3D Authentication işlem sonucu
public class AuthenticationResult
{
    public string AuthorizationNumber { get; set; }
    public string RRN { get; set; }
    public string Stan { get; set; }
}

// Banka işlem sonucu (kod + mesaj)
public class Result
{
    public string Code { get; set; }
    public string ReasonCode { get; set; }
    public string Message { get; set; }
}

// Banka işlem yanıtındaki transaction bilgileri
public class TransactionResponse
{
    public string TransactionId { get; set; }
    public string OrderId { get; set; }
    public DateTime TransactionDate { get; set; }
}

public class SecureService
{
    private readonly HttpClient _httpClient;

    public SecureService(HttpClient httpClient, SecureSettings settings)
    {
        _httpClient = httpClient;
    }

    // 3D Secure ödeme isteğini hazırlar
    public async ProcessSecureAsync(SecureRequest request)
    {
        // Bankaya gönderilecek hash input değerini oluştur
        var inputString = BuildHashInputSecure(request);

        // Hash değerini HMAC-SHA512 ile üret
        var hash = CalculateSHA512(inputString.HashInput, _settings.SecretKey);

        // Bankaya gönderilecek modelin alanlarını doldur
        return new()
        {
            Hash = hash,
            Rnd = inputString.RandomHex,
            TimeStamp = inputString.Timestamp,
            AcquirerMerchantId = request.AcquirerMerchantId,
            CardHolderName = request.CardHolderName,
            CurrencyCode = request.CurrencyCode,
            Cvv2 = request.Cvv2,
            ExpireDate = request.ExpireDate,
            OkUrl = request.OkUrl,
            FailUrl = request.FailUrl,
            InstallmentCount = request.InstallmentCount,
            OrderId = request.OrderId,
            Pan = request.Pan,
            StoreType = request.StoreType,
            TransactionAmount = request.TransactionAmount,
            TransactionType = request.TransactionType,
            UserId = request.UserId
        };
    }

    // Hash girdi değerini oluşturur (banka istediği sıra ile alanlar birleştirilir)
    public static HashInputResult BuildHashInputSecure(SecureRequest request)
    {
        HashInputResult hashInputResult = new HashInputResult();

        string Safe(string s) => s ?? "";

        // Rastgele 128 karakterlik hex değeri üret
        hashInputResult.RandomHex = GenerateRandomHex(128);

        // UTC zaman damgası ekle
        hashInputResult.Timestamp = DateTime.UtcNow.ToString("yyyyMMddHHmmss");

        // Banka istediği formatta string birleştirme
        hashInputResult.HashInput = string.Concat(
                Safe(request.TransactionType),
                Safe(request.AcquirerMerchantId),
                Safe(request.OrderId),
                Safe(request.Pan),
                Safe(request.CardHolderName),
                Safe(request.ExpireDate),
                Safe(request.TransactionAmount),
                Safe(request.CurrencyCode),
                Safe(request.InstallmentCount),
                Safe(request.UserId),
                Safe(request.OkUrl),
                Safe(request.FailUrl),
                Safe(request.StoreType),
                hashInputResult.Timestamp,
                hashInputResult.RandomHex);

        return hashInputResult;
    }

    // SHA512 HMAC ile hash değeri üretir
    public static string CalculateSHA512(string input, string secretKey)
    {
        using var hmac = new HMACSHA512(Encoding.UTF8.GetBytes(secretKey));
        var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hashBytes);
    }
}

// Bankadan gelen Success sonucu yakalayan model
public class SecureSuccessModel
{
    public string ThreeDSResponse { get; set; }
    public string ResultThreeDSResponse { get; set; }
    public string ResultGoResponse { get; set; }
}

// Bankanın success URL’ine gönderdiği sonucu yakalayan action
[HttpPost("SuccessResult")]
public async Task<IActionResult> SuccessResult([FromForm] SecureSuccessModel secureModel)
{
    var queryParams = "";

    // Bankadan gelen veri hangi parametre ile geldiyse onu ekle
    if (!string.IsNullOrEmpty(secureModel.ResultThreeDSResponse))
    {
        queryParams = $"?data={secureModel.ResultThreeDSResponse}";
    }
    else if (!string.IsNullOrEmpty(secureModel.ThreeDSResponse))
    {
        queryParams = $"?data={secureModel.ThreeDSResponse}";
    }
    else if (!string.IsNullOrEmpty(secureModel.ResultGoResponse))
    {
        queryParams = $"?data={secureModel.ResultGoResponse}";
    }

    // Başarılı sayfaya yönlendir
    return Redirect($"{OkPage}{queryParams}");
}
using System;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Security.Cryptography;
using System.Net.Http;
using System.Threading.Tasks;

// Ödeme isteği modelidir. API'ye gönderilecek alanları içerir.

public class NonSecureRequest
{
    [JsonPropertyName("userId")] public string UserId { get; set; }
    [JsonPropertyName("password")] public string Password { get; set; }
    [JsonPropertyName("merchantNumber")] public string MerchantNumber { get; set; }
    [JsonPropertyName("shopCode")] public string ShopCode { get; set; }
    [JsonPropertyName("transactionType")] public string TransactionType { get; set; }
    [JsonPropertyName("transactionId")] public string TransactionId { get; set; }
    [JsonPropertyName("cardHolderName")] public string CardHolderName { get; set; }
    [JsonPropertyName("transactionAmount")] public string Amount { get; set; }
    [JsonPropertyName("currencyCode")] public string Currency { get; set; }
    [JsonPropertyName("pan")] public string Pan { get; set; }
    [JsonPropertyName("cvv2")] public string Cvv2 { get; set; }
    [JsonPropertyName("expireDate")] public string ExpireDate { get; set; }
    [JsonPropertyName("installmentCount")] public string Installment { get; set; }
    [JsonPropertyName("securityType")] public string SecurityType { get; set; }
    [JsonPropertyName("rewardAmount")] public string RewardAmount { get; set; }
    [JsonPropertyName("pfMerchantNumber")] public string PFMerchantNumber { get; set; }
    [JsonPropertyName("cardBrand")] public string CardBrand { get; set; }
    [JsonPropertyName("bin")] public string Bin { get; set; }
    [JsonPropertyName("lastFourDigits")] public string LastFourDigits { get; set; }
    [JsonPropertyName("tcknVkn")] public string TcknVkn { get; set; }
}

// API'nin döneceği cevap modelidir.

public class NonSecureResponse
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

// Gateway API cevabı modelidir.

public class GatewayResponse
{
    public AuthenticationResult AuthenticationResult { get; set; }
    public Result Result { get; set; }
    public TransactionResponse TransactionResponse { get; set; }
}

public class AuthenticationResult
{
    public string AuthorizationNumber { get; set; }
    public string RRN { get; set; }
    public string Stan { get; set; }
}

public class Result
{
    public string Code { get; set; }
    public string ReasonCode { get; set; }
    public string Message { get; set; }
}

public class TransactionResponse
{
    public string TransactionId { get; set; }
    public string OrderId { get; set; }
    public DateTime TransactionDate { get; set; }
}

// Ödeme işlemlerini yöneten servis sınıfı.
public class NonSecureService
{
    private readonly HttpClient _httpClient;

    public NonSecureService(HttpClient httpClient, NonSecureSettings settings)
    {
        _httpClient = httpClient;
    }


    // Ödeme işlemini başlatır.

    public async Task<NonSecureResponse> ProcessNonSecureAsync(NonSecureRequest request)
    {
        try
        {
            // 1. Hash verisini oluştur
            var inputString = BuildHashInput(request);
            var hash = CalculateSHA512(inputString, request.SecretKey);

            // 2. İşlem tipine göre payload hazırla
            object payload = request.TransactionType switch
            {
                "SALEPOS" or "PREAUTH" or "MAILORDER" => PrepareSaleRequest(request, hash),
                "VOID" => PrepareVoidRequest(request, hash),
                "REFUND" => PrepareRefundRequest(request, hash),
                "POSTAUTH" => PreparePostAuthRequest(request, hash),
                "MOTOINSURANCE" => PrepareMotoInsuranceRequest(request, hash),
                _ => throw new InvalidOperationException($"Geçersiz işlem türü: {request.TransactionType}")
            };

            // 3. API'ye POST isteği gönder
            var content = new StringContent(JsonSerializer.Serialize(payload), Encoding.UTF8, "application/json");
            var response = await _httpClient.PostAsync("https://devcard.sim-ant.com/EverestVpos/V1/vposgateway/vposgateway/api/nonSecure", content);

            if (!response.IsSuccessStatusCode)
                return new NonSecureResponse { Success = false };

            // 4. Yanıtı işle
            var responseContent = await response.Content.ReadAsStringAsync();
            var gatewayResponse = JsonSerializer.Deserialize<GatewayResponse>(responseContent, new JsonSerializerOptions
            {
                PropertyNameCaseInsensitive = true
            });

            if (gatewayResponse == null)
                return new NonSecureResponse { Success = false };

            // 5. NonSecureResponse modelini doldur
            return new NonSecureResponse
            {
                AuthorizationNumber = gatewayResponse.AuthenticationResult?.AuthorizationNumber,
                RRN = gatewayResponse.AuthenticationResult?.RRN,
                Stan = gatewayResponse.AuthenticationResult?.Stan,
                TransactionId = gatewayResponse.TransactionResponse?.TransactionId,
                TransactionDate = gatewayResponse.TransactionResponse?.TransactionDate ?? DateTime.MinValue,
                OrderId = gatewayResponse.TransactionResponse?.OrderId,
                ResponseCode = gatewayResponse.Result?.Code,
                ResponseMessage = gatewayResponse.Result?.Message,
                ResponseReasonCode = gatewayResponse.Result?.ReasonCode,
                Success = true
            };
        }
        catch
        {
            return new NonSecureResponse { Success = false };
        }
    }

    #region Payload Hazırlama Metotları
    private object PrepareSaleRequest(NonSecureRequest request, string hash) => new
    {
        userId = request.UserId,
        password = request.Password,
        merchantNumber = request.MerchantNumber,
        shopCode = request.ShopCode,
        transactionType = request.TransactionType,
        transactionId = request.TransactionId,
        cardHolderName = request.CardHolderName,
        transactionAmount = request.Amount,
        currencyCode = request.Currency,
        pan = request.Pan,
        cvv2 = request.Cvv2,
        expireDate = request.ExpireDate,
        installmentCount = request.Installment,
        securityType = request.SecurityType,
        rewardAmount = request.RewardAmount,
        pfMerchantNumber = request.PFMerchantNumber,
        cardBrand = request.CardBrand,
        iPAddress = request.IPAddress,
        hashData = hash
    };

    private object PrepareVoidRequest(NonSecureRequest request, string hash) => new
    {
        userId = request.UserId,
        password = request.Password,
        merchantNumber = request.MerchantNumber,
        shopCode = request.ShopCode,
        transactionType = request.TransactionType,
        transactionId = request.TransactionId,
        securityType = request.SecurityType,
        iPAddress = request.IPAddress,
        hashData = hash
    };

    private object PrepareRefundRequest(NonSecureRequest request, string hash) => new
    {
        userId = request.UserId,
        password = request.Password,
        merchantNumber = request.MerchantNumber,
        shopCode = request.ShopCode,
        transactionType = request.TransactionType,
        transactionId = request.TransactionId,
        refundAmount = request.Amount,
        securityType = request.SecurityType,
        iPAddress = request.IPAddress,
        hashData = hash
    };

    private object PreparePostAuthRequest(NonSecureRequest request, string hash) => new
    {
        userId = request.UserId,
        password = request.Password,
        merchantNumber = request.MerchantNumber,
        shopCode = request.ShopCode,
        transactionType = request.TransactionType,
        transactionId = request.TransactionId,
        transactionAmount = request.Amount,
        currencyCode = request.Currency,
        securityType = request.SecurityType,
        iPAddress = request.IPAddress,
        hashData = hash
    };

    private object PrepareMotoInsuranceRequest(NonSecureRequest request, string hash) => new
    {
        userId = request.UserId,
        password = request.Password,
        merchantNumber = request.MerchantNumber,
        shopCode = request.ShopCode,
        transactionType = request.TransactionType,
        transactionAmount = request.Amount,
        currencyCode = request.Currency,
        installmentCount = request.Installment,
        securityType = request.SecurityType,
        bin = request.Bin,
        lastFourDigits = request.LastFourDigits,
        tcknVkn = request.TcknVkn,
        rewardAmount = request.RewardAmount,
        iPAddress = request.IPAddress,
        hashData = hash
    };
    #endregion

    #region Yardımcı Metotlar
    private static string BuildHashInput(NonSecureRequest request)
    {
        string Safe(string s) => s ?? "";

        return request.TransactionType switch
        {
            "SALEPOS" or "MAILORDER" or "PREAUTH" => string.Concat(
                Safe(request.UserId), Safe(request.Password), Safe(request.MerchantNumber), Safe(request.ShopCode),
                Safe(request.TransactionType), Safe(request.CardHolderName), Safe(request.Amount), Safe(request.Currency),
                Safe(request.Pan), Safe(request.Cvv2), Safe(request.ExpireDate), Safe(request.Installment),
                Safe(request.SecurityType), Safe(request.RewardAmount), Safe(request.CardBrand)
            ),
            "VOID" => string.Concat(
                Safe(request.UserId), Safe(request.Password), Safe(request.MerchantNumber), Safe(request.ShopCode),
                Safe(request.TransactionType), Safe(request.TransactionId), Safe(request.SecurityType)
            ),
            "REFUND" => string.Concat(
                Safe(request.UserId), Safe(request.Password), Safe(request.MerchantNumber), Safe(request.ShopCode),
                Safe(request.TransactionType), Safe(request.TransactionId), Safe(request.Amount), Safe(request.SecurityType)
            ),
            "MOTOINSURANCE" => string.Concat(
                Safe(request.UserId), Safe(request.Password), Safe(request.MerchantNumber), Safe(request.ShopCode),
                Safe(request.TransactionType), Safe(request.TransactionId), Safe(request.Amount), Safe(request.Currency),
                Safe(request.Bin), Safe(request.LastFourDigits), Safe(request.Installment), Safe(request.SecurityType)
            ),
            "POSTAUTH" => string.Concat(
                Safe(request.UserId), Safe(request.Password), Safe(request.MerchantNumber), Safe(request.ShopCode),
                Safe(request.TransactionType), Safe(request.TransactionId), Safe(request.Amount), Safe(request.SecurityType)
            ),
            _ => string.Empty
        };
    }

    private static string CalculateSHA512(string input, string secretKey)
    {
        using var hmac = new HMACSHA512(Encoding.UTF8.GetBytes(secretKey));
        var hashBytes = hmac.ComputeHash(Encoding.UTF8.GetBytes(input));
        return Convert.ToBase64String(hashBytes);
    }
    #endregion
}

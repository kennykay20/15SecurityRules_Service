using System.Text.Json.Serialization;

namespace _15SecurityRulesAPI.Application.Dtos.Response
{
    public class ProductAPIResponse<T>
    {
        [JsonPropertyName("responseCode")]
        /// <summary> Gets or sets the response code. </summary>
        public string? ResponseCode { get; set; }

        [JsonPropertyName("responseMsg")]
        /// <summary> Gets or sets the response message. </summary>
        public string? ResponseMessage { get; set; }

        [JsonPropertyName("responseDetails")]
        public T? ResponseData { get; set; }
    }

    public class AuthAPIResponse<T>
    {
        [JsonPropertyName("responseCode")]
        /// <summary> Gets or sets the response code. </summary>
        public string? ResponseCode { get; set; }

        [JsonPropertyName("responseMsg")]
        /// <summary> Gets or sets the response message. </summary>
        public string? ResponseMessage { get; set; }

        [JsonPropertyName("responseDetails")]
        public T? ResponseData { get; set; }
    }

    public class ProductListDataDto
    {
        public List<ProductDataDto> Data { get; set; }
    }
    public class ProductDataDto
    {
        public int Id { get; set; }
        public string Name { get; set; }
        public string Price { get; set; }
        public string? Description { get; set; }
        public string? DateCreated { get; set; }
    }
}

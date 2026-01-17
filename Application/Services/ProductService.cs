using _15SecurityRulesAPI.Application.Dtos.Request;
using _15SecurityRulesAPI.Application.Dtos.Response;
using _15SecurityRulesAPI.Application.Interfaces;
using _15SecurityRulesAPI.Infrastructure.Repository.Interfaces;
using _15SecurityRulesAPI.Models.entities;

namespace _15SecurityRulesAPI.Application.Services
{
    public class ProductService : IProductService
    {
        private readonly ILogger<ProductService> _logger;
        private readonly IProductRecordRepository _productRepo;
        public ProductService(ILogger<ProductService> logger, IProductRecordRepository productRepo)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _productRepo = productRepo ?? throw new ArgumentNullException(nameof(productRepo));
        }

        public async Task<ProductAPIResponse<ProductDataDto>> CreateProduct(ProductCreateDto dto)
        {
            try
            {
                var response = await _productRepo.CreateProduct(dto);
                if(response.Id > 0)
                    return new ProductAPIResponse<ProductDataDto>
                    {
                        ResponseCode = "00",
                        ResponseMessage = "Successful",
                        ResponseData = response
                    };
                return new ProductAPIResponse<ProductDataDto>
                {
                    ResponseCode = "99",
                    ResponseMessage = "Failed",
                    ResponseData = null
                };
            }
            catch(Exception ex)
            {
                return new ProductAPIResponse<ProductDataDto>
                {
                    ResponseCode = "500",
                    ResponseMessage = "Failed " + ex.Message,
                    ResponseData = null
                };
            }
        }

        public async Task<ProductAPIResponse<ProductListDataDto>> GetAllProduct()
        {
            var product = await _productRepo.GetAllProducts();
            if (product?.Data?.Any() == true)
                return new ProductAPIResponse<ProductListDataDto>
                {
                    ResponseCode = "00",
                    ResponseMessage = "Successful",
                    ResponseData = product
                };
            else
                return new ProductAPIResponse<ProductListDataDto>
                {
                    ResponseCode = "99",
                    ResponseMessage = "",
                    ResponseData = null
                };
        }

        public async Task<ProductAPIResponse<ProductDataDto>> GetProductById(int id)
        {
            var product = await _productRepo.GetProduct(id);
            if (product != null)
                return new ProductAPIResponse<ProductDataDto>
                {
                    ResponseCode = "00",
                    ResponseMessage = "Successful",
                    ResponseData = product
                };
            else if(product == null)
                return new ProductAPIResponse<ProductDataDto>
                {
                    ResponseCode = "43",
                    ResponseMessage = "Not found",
                    ResponseData = null
                };
            else
                return new ProductAPIResponse<ProductDataDto>
                {
                    ResponseCode = "99",
                    ResponseMessage = "Failed",
                    ResponseData = null
                };
        }
    }
}

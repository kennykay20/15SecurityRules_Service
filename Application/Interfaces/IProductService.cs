using _15SecurityRulesAPI.Application.Dtos.Request;
using _15SecurityRulesAPI.Application.Dtos.Response;

namespace _15SecurityRulesAPI.Application.Interfaces
{
    public interface IProductService
    {
        Task<ProductAPIResponse<ProductListDataDto>> GetAllProduct();

        Task<ProductAPIResponse<ProductDataDto>> GetProductById(int id);

        Task<ProductAPIResponse<ProductDataDto>> CreateProduct(ProductCreateDto dto);
    }
}

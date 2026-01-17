using _15SecurityRulesAPI.Application.Dtos.Request;
using _15SecurityRulesAPI.Application.Dtos.Response;
using _15SecurityRulesAPI.Models.entities;

namespace _15SecurityRulesAPI.Infrastructure.Repository.Interfaces
{
    public interface IProductRecordRepository
    {
        Task<ProductListDataDto> GetAllProducts();
        Task<ProductDataDto> GetProduct(int id);
        Task<ProductDataDto> CreateProduct(ProductCreateDto dto);
    }
}

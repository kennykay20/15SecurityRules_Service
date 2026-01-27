using _15SecurityRulesAPI.Application.Dtos.Request;
using _15SecurityRulesAPI.Application.Dtos.Response;
using _15SecurityRulesAPI.Infrastructure.Context;
using _15SecurityRulesAPI.Infrastructure.Repository.Interfaces;
using _15SecurityRulesAPI.Models.entities;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Distributed;

namespace _15SecurityRulesAPI.Infrastructure.Repository.Services
{
    public class ProductRecordRepository(AppDbContext _dbContext) : IProductRecordRepository
    {
        /// <summary>The cache.</summary>
        //private readonly IDistributedCache _cache;

        public async Task<ProductDataDto> CreateProduct(ProductCreateDto dto)
        {
            var product = new Product
            {
                Id = 1,
                Name = dto.Name ?? "",
                Price = Decimal.Parse(dto.Price.ToString()!),
                Description = dto.Description ?? "",
                DateCreated = DateTime.UtcNow,
            };

            _dbContext.Products.Add(product);
            await _dbContext.SaveChangesAsync();
            return new ProductDataDto
            {
                Id = product.Id,
                Name = product.Name,
                Price = product.Price.ToString(),
                Description = product.Description,
                DateCreated = product.Description
            };
        }

        public async Task<ProductListDataDto> GetAllProducts()
        {

            var products = await _dbContext.Products.ToListAsync();

            var response = products.Select(product => new ProductDataDto
            {
                Id = product.Id,
                Name = product.Name,
                Price = product.Price.ToString(),
                Description = product.Description,
                DateCreated = product.DateCreated.ToString()
            }).ToList();

            return new ProductListDataDto
            {
                Data = response
            };
        }

        public async Task<ProductDataDto> GetProduct(int id)
        {
            var product = await _dbContext.Products.ToListAsync();

            var response = product.Where(product => product.Id == id).FirstOrDefault();
            return new ProductDataDto
            {
                Id = response.Id, Name = response.Name, Price = response.Price.ToString(),
                Description = response.Description, DateCreated = response.DateCreated.ToString()
            };
        }
    }
}

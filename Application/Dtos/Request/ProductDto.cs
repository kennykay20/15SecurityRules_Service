using System.ComponentModel.DataAnnotations;

namespace _15SecurityRulesAPI.Application.Dtos.Request
{
    public class ProductDto
    {
        public int Id { get; set; }
        public string? Name { get; set; }
        public decimal? Price { get; set; }
        public string? Description { get; set; }
        public string? DateCreated { get; set; }
    }

    public class ProductCreateDto
    {
        [Required(ErrorMessage = "Product name is required")]
        [StringLength(100, MinimumLength = 3)]
        public string? Name { get; set; }

        [Required]
        [Range(0.01, 1000000)]
        public decimal? Price { get; set; }

        [StringLength(500)]
        public string? Description { get; set; }
    }
}

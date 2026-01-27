using _15SecurityRulesAPI.Application.Dtos.Request;
using _15SecurityRulesAPI.Application.Dtos.Response;
using _15SecurityRulesAPI.Application.Interfaces;
using _15SecurityRulesAPI.Infrastructure.Context;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Security.Claims;

namespace _15SecurityRulesAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class ProductsController : ControllerBase
    {
        private readonly ILogger<ProductsController> _logger;
        private readonly IProductService _instanceMgtSvc;

        public ProductsController(ILogger<ProductsController> logger, IProductService instanceMgtSvc)
        {
            _logger = logger;
            _instanceMgtSvc = instanceMgtSvc;
        }

        [HttpGet("getAll")]
        [Authorize(Policy = "UserOrAdmin")]
        public async Task<IActionResult> GetAll()
        {
            //Rule 10: Don't log sensitive data
            _logger.LogInformation("User {userId} retrived products", User.FindFirstValue(ClaimTypes.NameIdentifier));

            try
            {
                var response = await _instanceMgtSvc.GetAllProduct();
                return response.ResponseCode switch
                {
                    "00" => Ok(response),                   // Success
                    "99" => BadRequest(response),          // Business error
                    "500" => StatusCode(500, response), // Other errors / exceptions
                    _ => StatusCode(500, response)  // Fallback
                };
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occured in GetAllProduct request {ex}", ex);

                return StatusCode(500, new ProductAPIResponse<ProductListDataDto>
                {
                    ResponseCode = "500",
                    ResponseMessage = "An error occurred. Try again later.",
                    ResponseData = null
                }); // HTTP 500
            }
        }

        [HttpGet("getById/{id}")]
        [Authorize(Policy = "UserOrAdmin")]
        public async Task<IActionResult> GetById(int id)
        {
            try
            {
                var response = await _instanceMgtSvc.GetProductById(id);
                return response.ResponseCode switch
                {
                    "00" => Ok(response),                   // Success
                    "99" => BadRequest(response),         // Business error
                    "43" => NotFound(response),         // Not found error
                    "500" => StatusCode(500, response), // Other errors / exceptions
                    _ => StatusCode(500, response)  // Fallback
                };
            }
            catch (Exception ex)
            {
                _logger.LogError("An error occured in GetProductById request {ex}", ex);

                return StatusCode(500, new ProductAPIResponse<ProductDataDto>
                {
                    ResponseCode = "500",
                    ResponseMessage = "An error occurred. Try again later.",
                    ResponseData = null
                }); // HTTP 500
            }
        }

        // Rule 4 & 5: Authorization + Input validation
        [HttpPost("create")]
        [Authorize(Policy = "AdminOnly")]
        public async Task<IActionResult> Create([FromBody] ProductCreateDto request)
        { 
            try
            {
                // Rule 5: Model validation happens automatically with [ApiController]
                if (!ModelState.IsValid)
                    return BadRequest(ModelState);

                var response = await _instanceMgtSvc.CreateProduct(request);

                return response.ResponseCode switch
                {
                    "00" => Ok(response),                  // Success
                    "99" => BadRequest(response),          // Business error
                    "500" => StatusCode(500, response), // Other errors / exceptions
                    _ => StatusCode(500, response)  // Fallback
                };
            }
            catch(Exception ex)
            {
                _logger.LogError("An error occured in CreateProduct request {ex}", ex);

                return StatusCode(500, new ProductAPIResponse<ProductDataDto>
                {
                    ResponseCode = "500",
                    ResponseMessage = "An error occurred. Try again later.",
                    ResponseData = null
                }); // HTTP 500
            }
        }
    }
}

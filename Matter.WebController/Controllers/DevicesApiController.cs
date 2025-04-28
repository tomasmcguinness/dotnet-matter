using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Matter.WebController.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class DevicesApiController : ControllerBase
    {
        public IActionResult Post()
        {

            return Ok();
        }
    }
}

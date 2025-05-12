using Matter.Core;
using Microsoft.AspNetCore.Mvc;

namespace Matter.WebController.Controllers
{
    [Route("api/devices")]
    [ApiController]
    public class DevicesApiController : ControllerBase
    {
        private readonly IMatterController _matterController;

        public DevicesApiController(IMatterController matterController)
        {
            _matterController = matterController;
        }

        public async Task<IActionResult> Post()
        {
            var commissioner = await _matterController.CreateCommissionerAsync();
            commissioner.CommissionDevice(3840);

            return Ok(new { commissioner.Id });
        }
    }
}

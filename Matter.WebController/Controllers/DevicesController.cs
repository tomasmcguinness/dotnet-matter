using Microsoft.AspNetCore.Mvc;

namespace Matter.WebController.Controllers
{
    public class DevicesController : Controller
    {
        public IActionResult Add()
        {
            return View();
        }
    }
}

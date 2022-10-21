using IdentityAndSecurity.Models;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAndSecurity.Controllers
{
    public class IdentityController : Controller
    {
        public async Task<IActionResult> Signup()
        {
            var model = new SignupDto();
            return View(model);
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupDto model)
        {
            return View(model);
        }
        public async Task<IActionResult> Signin()
        {
            return View();
        }
        public async Task<IActionResult> AccessDenied()
        {
            return View();
        }
    }
}

using IdentityAndSecurity.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAndSecurity.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;

        public IdentityController(UserManager<IdentityUser> userManager)
        {
            _userManager = userManager;
        }

        public async Task<IActionResult> Signup()
        {
            var model = new SignupDto();
            return await Task.FromResult(View(model));
        }

        [HttpPost]
        public async Task<IActionResult> Signup(SignupDto model)
        {
            if (ModelState.IsValid)
            {
                if((await _userManager.FindByEmailAsync(model.Email) == null))
                {
                    var user = new IdentityUser { Email = model.Email, UserName = model.Email };
                    var result = await _userManager.CreateAsync(user, model.Password);

                    if (result.Succeeded)
                    {
                        return RedirectToAction("Signin");
                    }
                    ModelState.AddModelError("Signup",String.Join(" ", result.Errors.Select(it => it.Description)));
                    return View(model);
                }
            }
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

using IdentityAndSecurity.Models;
using IdentityAndSecurity.Service;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace IdentityAndSecurity.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IEmailSender _mail;

        public IdentityController(UserManager<IdentityUser> userManager, IEmailSender mail)
        {
            _userManager = userManager;
            _mail = mail;
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
                    user = await _userManager.FindByEmailAsync(model.Email);
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    if (result.Succeeded)
                    {
                        var confirmationLink = Url.ActionLink("ConfirmEmail", "Identity", new { userId = user.Id, token = token });
                        await _mail.SendEmailAsync("info@mydomain.com", user.Email, "Confirm your email address", confirmationLink);
                        return RedirectToAction("Signin");
                    }
                    ModelState.AddModelError("Signup",String.Join("", result.Errors.Select(it => it.Description)));
                    return View(model);
                }
            }
            return View(model);
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            return new OkResult();
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

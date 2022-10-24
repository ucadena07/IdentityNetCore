using IdentityAndSecurity.Models;
using IdentityAndSecurity.Service;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Options;
using System.Security.Claims;

namespace IdentityAndSecurity.Controllers
{
    public class IdentityController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IEmailSender _mail;
        private readonly SmtpOptions _options;

        public IdentityController(UserManager<IdentityUser> userManager, IEmailSender mail, IOptions<SmtpOptions> options, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager)
        {
            _userManager = userManager;
            _mail = mail;
            _options = options.Value;
            _signInManager = signInManager;
            _roleManager = roleManager; 
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
                if(!(await _roleManager.RoleExistsAsync(model.Role)))
                {
                    var role = new IdentityRole { Name = model.Role };
                    var roleResult  = await _roleManager.CreateAsync(role);
                    if(!roleResult.Succeeded)
                    {
                        var errors = roleResult.Errors.Select(it => it.Description);
                        ModelState.AddModelError("Role", string.Join(",", errors));
                        return View(model);
                    }
                }


                if((await _userManager.FindByEmailAsync(model.Email) == null))
                {

                    var user = new IdentityUser { Email = model.Email, UserName = model.Email };
                    var result = await _userManager.CreateAsync(user, model.Password);
                    user = await _userManager.FindByEmailAsync(model.Email);
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

                    if (result.Succeeded)
                    {
                        var confirmationLink = Url.ActionLink("ConfirmEmail", "Identity", new { userId = user.Id, token = token });
                        await _mail.SendEmailAsync(_options.Domain, user.Email, "Confirm your email address", confirmationLink);
                        await _userManager.AddToRoleAsync(user,model.Role);
                        var claim = new Claim("Department", model.Department);
                        await _userManager.AddClaimAsync(user, claim);  
                        return RedirectToAction("Signin");
                    }
                    ModelState.AddModelError("Signup",String.Join("", result.Errors.Select(it => it.Description)));
                    return View(model);
                }
            }
            return View(model);
        }
        public async Task<IActionResult> MFASetup()
        {
            
            var user = await _userManager.GetUserAsync(User);
            await _userManager.ResetAuthenticatorKeyAsync(user);
            var token = await _userManager.GetAuthenticatorKeyAsync(user);
            var model = new MFADto() { Token = token};
            return View(model);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> MFASetup(MFADto model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.GetUserAsync(User);
                var succeded = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider, model.Code);

                if (succeded)
                {
                    await _userManager.SetTwoFactorEnabledAsync(user, true);
                }
                else
                {
                    ModelState.AddModelError("Verify", "Your MFA code could not be validated.");
                }
            }
            return View(model);
        }

        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                return RedirectToAction("Signin");
            }


            return new NotFoundResult();
        }
        public IActionResult Signin()
        {       
            
            return View(new SigninDto());
        }

        [HttpPost]
        public async Task<IActionResult> Signin(SigninDto model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberMe,false);
                if (result.Succeeded)
                {
                    return Redirect("/");
                }
                else
                {
                    ModelState.AddModelError("Login","Cannot login.");
                    return View(model);
                }

            }
            return View(model);
        }
        public IActionResult AccessDenied()
        {
            return View();
        }

        public async Task<IActionResult> SignOut()
        {
            await _signInManager.SignOutAsync();
            return RedirectToAction("Signin");
        }
    }
}

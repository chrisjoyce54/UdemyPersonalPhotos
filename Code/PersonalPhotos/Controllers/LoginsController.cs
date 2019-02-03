using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PersonalPhotos.Contracts;
using PersonalPhotos.Models;
using SignInResult = Microsoft.AspNetCore.Identity.SignInResult;

namespace PersonalPhotos.Controllers
{
	public class LoginsController : Controller
	{
		private readonly IHttpContextAccessor _httpContextAccessor;
		private readonly ILogins _loginService;
		private readonly UserManager<IdentityUser> _userManager;
		private readonly SignInManager<IdentityUser> _signInManager;
		private readonly RoleManager<IdentityRole> _roleManager;
		private readonly IEmail _email;

		public LoginsController(ILogins loginService, 
			IHttpContextAccessor httpContextAccessor, 
			UserManager<IdentityUser> userManager, 
			SignInManager<IdentityUser> signInManager,
			RoleManager<IdentityRole> roleManager,
			IEmail email)
		{
			_loginService = loginService;
			_httpContextAccessor = httpContextAccessor;
			_userManager = userManager;
			_signInManager = signInManager;
			_roleManager = roleManager;
			_email = email;
		}

		public IActionResult Index(string returnUrl = null)
		{
			var model = new LoginViewModel { ReturnUrl = returnUrl };
			return View("Login", model);
		}

		[HttpPost]
		public async Task<IActionResult> Login(LoginViewModel model)
		{
			if (!ModelState.IsValid)
			{
				ModelState.AddModelError("", "Invalid login detils");
				return View("Login", model);
			}

			var user = await _userManager.FindByEmailAsync(model.Email);
			if (user == null || !user.EmailConfirmed)
			{
				ModelState.AddModelError("", "User not found or Email is not confirmed.");
				return View();
			}

			var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, false);
			if (!result.Succeeded)
			{
                if (result == SignInResult.TwoFactorRequired)
                {
                    return RedirectToAction("MfaLogin");
                }
				ModelState.AddModelError("", "Username and/or Password is incorrect");
				return View();
			}

			var claims = new List<Claim>
			{
				new Claim("Over18Claim", "True")
			};
			var claimIdentity = new ClaimsIdentity(claims);

			User.AddIdentity(claimIdentity);

			if (!string.IsNullOrEmpty(model.ReturnUrl))
			{
				return LocalRedirect(model.ReturnUrl);
			}
			else
			{
				return RedirectToAction("Display", "Photos");
			}
		}

		public IActionResult Create()
		{
			return View("Create");
		}

		[HttpPost]
		public async Task<IActionResult> Create(LoginViewModel model)
		{
			if (!ModelState.IsValid)
			{
				ModelState.AddModelError("", "Invalid user details");
				return View(model);
			}

			if (!await _roleManager.RoleExistsAsync("Editor"))
			{
				await _roleManager.CreateAsync(new IdentityRole("Editor"));
			}
			var user = new IdentityUser
			{
				UserName = model.Email,
				Email = model.Email
			};

			var result = await _userManager.CreateAsync(user, model.Password);
			if (!result.Succeeded)
			{
				foreach (var error in result.Errors)
				{
					ModelState.AddModelError(string.Empty, $"{error.Code}: {error.Description}");
				}
			}

			await _userManager.AddToRolesAsync(user, new List<string>{"Editor"});

			var token = _userManager.GenerateEmailConfirmationTokenAsync(user);
			var url = Url.Action("Confirmation", "Logins", new {id=user.Id, @token= token});
			var emailBody = $"Please confirm your email by clicking on the link below.<br/>{url}";

			await _email.Send(model.Email, emailBody);

			return RedirectToAction("Index", "Logins");
		}

		[Authorize]
		public async Task<IActionResult> Logout()
		{
			await _signInManager.SignOutAsync();
			return RedirectToAction("Index", "Logins");
		}

		public async Task<IActionResult> Confirmation(string id, string token)
		{
			var user = await _userManager.FindByIdAsync(id);
			var confirm = await _userManager.ConfirmEmailAsync(user, token);

            //Force MFA
            var is2FaEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            if (!is2FaEnabled)
            {
                return RedirectToAction("Setup2Fa");

            }
            return RedirectToAction("Index", "Logins");
            //if (confirm.Succeeded)
            //{
            //	return RedirectToAction("Login");
            //}

            //ViewBag["Error"] = "Error validating email address";
            //return View();
        }

		public async Task<IActionResult> ResetPassword()
		{
			return View();
		}
		[HttpPost]
		public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
		{
			if (ModelState.IsValid)
			{
				var user = await _userManager.FindByEmailAsync(model.EmailAddress);
				if (user != null && user.EmailConfirmed)
				{
					var token = await _userManager.GeneratePasswordResetTokenAsync(user);
					var link = Url.Action("ChangePassword", "Logins", new {userId = user.Id, token = token},
                        protocol: HttpContext.Request.Scheme);
					var emailBody = $"Click on the link to reset your password.<br/>{link}";
					await _email.Send(model.EmailAddress, emailBody);
				}
			}
			return View();
		}
		public async Task<IActionResult> ChangePassword(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user != null)
            {
                var model = new ChangePasswordViewModel();
                model.EmailAddress = user.Email;
                model.Token = token;
                return View(model);
            }
			return View();
        }

        public async Task<IActionResult> ChangePassword(ChangePasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                ModelState.AddModelError("", "Error in page");
                return View();
            }
            var user = await _userManager.FindByEmailAsync(model.EmailAddress);
            var resetPasswordResult = await _userManager.ResetPasswordAsync(user, model.Token, model.Password);
            return RedirectToAction("Index");
        }

        [Authorize]
        public async Task<IActionResult> Setup2Fa()
        {
            var user = await _userManager.GetUserAsync(User);
            if (user != null)
            {
                var authKey = await _userManager.GetAuthenticatorKeyAsync(user);
                if (string.IsNullOrEmpty(authKey))
                {
                    await _userManager.ResetAuthenticatorKeyAsync(user);
                    authKey = await _userManager.GetAuthenticatorKeyAsync(user);
                }
                var model = new MfaCreateViewModel()
                {
                    AuthKey = FormatAuthKey(authKey)
                };
                return View(model);

            }
            return View();
        }

        [Authorize]
        public async Task<IActionResult> Setup2Fa(MfaCreateViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.GetUserAsync(User);
            var isCodeCorrect = await _userManager.VerifyTwoFactorTokenAsync(user, _userManager.Options.Tokens.AuthenticatorTokenProvider,
                model.Code);
            if (!isCodeCorrect)
            {
                ModelState.AddModelError("", "Codedid not match Auth Key");
                return View(model);
            }

            await _userManager.SetTwoFactorEnabledAsync(user, true);
            return RedirectToAction("Index", "Logins");
        }

        private string FormatAuthKey(string authKey)
        {
            const int chunkLen = 5;
            int start = chunkLen;
            var sBuilder = new StringBuilder();
            sBuilder.Append(authKey.Substring(0, chunkLen));
            while (start < authKey.Length)
            {
                var len = chunkLen > authKey.Length-start ? authKey.Length-start : chunkLen;
                sBuilder.Append("-" + authKey.Substring(start, len));
                start += len;
            }

            return sBuilder.ToString();
        }

        public async Task<IActionResult> MfaLogin()
        {
            return View();
        }
        [HttpPost]
        public async Task<IActionResult> MfaLogin(MfaLoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var result = await _signInManager.TwoFactorSignInAsync(_userManager.Options.Tokens.AuthenticatorTokenProvider,
                model.Code, true, true);
            if (!result.Succeeded)
            {
                ModelState.AddModelError("","Your code could not be validated.");
                return View(model);
            }

            return RedirectToAction("Login");
        }
    }
}
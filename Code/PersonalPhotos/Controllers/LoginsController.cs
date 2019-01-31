﻿using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PersonalPhotos.Contracts;
using PersonalPhotos.Models;

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
				return Redirect(model.ReturnUrl);
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
			if (confirm.Succeeded)
			{
				return RedirectToAction("Login");
			}

			ViewBag["Error"] = "Error validating email address";
			return View();
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
					var link = Url.Action("ChangePassword", "Logins", new {userId = user.Id, token = token});
					var emailBody = $"Click on the link to reset your password.<br/>{link}";
					await _email.Send(model.EmailAddress, emailBody);
				}
			}
			return View();
		}
		public async Task<IActionResult> ChangePassword(string userId, string token)
		{
			return View();
		}
	}
}
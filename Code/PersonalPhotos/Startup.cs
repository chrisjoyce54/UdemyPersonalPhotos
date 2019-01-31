using System.Reflection;
using Core.Interfaces;
using Core.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using PersonalPhotos.Contracts;
using PersonalPhotos.Filters;
using PersonalPhotos.Strategies;

namespace PersonalPhotos
{
	public class Startup
	{
		public Startup(IConfiguration configuration)
		{
			Configuration = configuration;
		}

		public IConfiguration Configuration { get; }

		// This method gets called by the runtime. Use this method to add services to the container.
		public void ConfigureServices(IServiceCollection services)
		{
			services.AddMvc();
			services.AddSession();
			services.AddScoped<ILogins, SqlServerLogins>();
			services.AddSingleton<IKeyGenerator, DefaultKeyGenerator>();
			services.AddScoped<IPhotoMetaData, SqlPhotoMetaData>();
			services.AddScoped<IFileStorage, LocalFileStorage>();
			services.AddScoped<LoginAttribute>();
			services.AddSingleton<IEmail, SmtpEmail>();

			var connectionString = Configuration.GetConnectionString("Default");
			var currentAssemblyName = Assembly.GetExecutingAssembly().GetName().Name;

			services.AddDbContext<IdentityDbContext>(option =>
			{
				option.UseSqlServer(connectionString,
					obj => obj.MigrationsAssembly(currentAssemblyName));
			});

			services.AddIdentity<IdentityUser, IdentityRole>(option =>
			{
				new PasswordOptions
				{
					RequireDigit = true,
					RequireLowercase = true,
					RequireUppercase = true,
					RequiredLength = 6
				};
				option.User = new UserOptions
				{
					RequireUniqueEmail = true
				};
				option.SignIn = new SignInOptions
				{
					RequireConfirmedEmail = false,
					RequireConfirmedPhoneNumber = false
				};
				option.Lockout = new LockoutOptions
				{
					MaxFailedAccessAttempts = 3
				};
			}).AddEntityFrameworkStores<IdentityDbContext>().AddDefaultTokenProviders();

			services.ConfigureApplicationCookie(option => { option.LoginPath = "/Logins/Index"; });
			services.AddAuthorization(option => { option.AddPolicy("Editor", policy =>
				{
					policy.RequireClaim("Over18Claim"); //.RequireClaim("PaidClaim").RequireRole("Editor");
				});
			});

			services.Configure<EmailOptions>(Configuration.GetSection("Email"));
		}

		// This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
		public void Configure(IApplicationBuilder app, IHostingEnvironment env)
		{
			if (env.IsDevelopment())
			{
				app.UseBrowserLink();
				app.UseDeveloperExceptionPage();
			}
			else
			{
				app.UseExceptionHandler("/Home/Error");
			}

			app.UseStaticFiles();
			app.UseSession();
			app.UseMvc(routes =>
			{
				routes.MapRoute(
					"default",
					"{controller=Photos}/{action=Display}");
			});
		}
	}
}
using System;
using AspNetCore.Identity.Elastic;
using AspNetCore.Identity.Elastic.Extensions;
using AspNetCore.Identity.Elastic.Config;
using ElasticIdentitySample.Mvc.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Nest;

namespace ElasticIdentitySample.Mvc
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
            var elasticSettings = new ElasticSettings();
            Configuration.GetSection("Elastic").Bind(elasticSettings);

            var node = new Uri("http://" + elasticSettings.ServerName.Replace("http://", ""));
            var settings = new ConnectionSettings(node);
            if (!string.IsNullOrEmpty(elasticSettings.UserName) || !string.IsNullOrEmpty(elasticSettings.Password))
            {
                settings.BasicAuthentication(elasticSettings.UserName, elasticSettings.Password);
            }
            settings.MapDefaultTypeIndices(m => m
                .Add(typeof(ElasticIdentityUser), "users"));
            var elasticClient = new ElasticClient(settings);
            
            services.AddIdentity<ElasticIdentityUser, ElasticIdentityUserRole>()
                .AddElasticIdentity(elasticClient)
                .AddDefaultTokenProviders();
            
            services.AddAuthentication(options =>
            {
                options.DefaultSignInScheme = IdentityConstants.ExternalScheme;
            });
            
            // Hosting doesn't add IHttpContextAccessor by default
            services.TryAddSingleton<IHttpContextAccessor, HttpContextAccessor>();

            services.AddOptions();
            services.AddDataProtection();

            // Add application services.
            services.AddTransient<IEmailSender, AuthMessageSender>();
            services.AddTransient<ISmsSender, AuthMessageSender>();
            
            services.AddMvc();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env, ILoggerFactory loggerFactory)
        {
            loggerFactory.AddConsole(Configuration.GetSection("Logging"));
            loggerFactory.AddDebug();

            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseBrowserLink();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();
            
            app.UseAuthentication();


            // Add external authentication middleware below. To configure them please see https://go.microsoft.com/fwlink/?LinkID=532715

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}

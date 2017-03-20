using System.Linq;
using AspNetCore.Identity.Elastic;
using ElasticIdentitySample.Mvc.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Rendering;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;

namespace ElasticIdentitySample.Mvc.Controllers
{
    [Authorize(Roles = "Admin")]
    public class UsersController : Controller
    {
        private readonly UserManager<ElasticIdentityUser> _userManager;
        private readonly SignInManager<ElasticIdentityUser> _signInManager;
        private readonly IOptions<IdentityCookieOptions> _identityCookieOptions;
        private readonly IEmailSender _emailSender;
        private readonly ISmsSender _smsSender;
        private readonly ILoggerFactory _loggerFactory;

        public UsersController(
            UserManager<ElasticIdentityUser> userManager,
            SignInManager<ElasticIdentityUser> signInManager,
            IOptions<IdentityCookieOptions> identityCookieOptions,
            IEmailSender emailSender,
            ISmsSender smsSender,
            ILoggerFactory loggerFactory
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _identityCookieOptions = identityCookieOptions;
            _emailSender = emailSender;
            _smsSender = smsSender;
            _loggerFactory = loggerFactory;
        }

        // GET: Users
        public ActionResult Index()
        {
            return View(_userManager.Users.ToList());
        }

        // GET: Users/Details/5
        public ActionResult Details(string id)
        {
            return View(_userManager.FindByIdAsync(id));
        }

        // GET: Users/Create
        public ActionResult Create()
        {
            return View();
        }

        // POST: Users/Create
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create(IFormCollection collection)
        {
            try
            {
                // TODO: Add insert logic here

                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }

        // GET: Users/Edit/5
        public ActionResult Edit(string id)
        {
            return View();
        }

        // POST: Users/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Edit(string id, IFormCollection collection)
        {
            try
            {
                if (id == null)
                {
                    return new BadRequestResult();
                }

                var user = _userManager.FindByIdAsync(id).ConfigureAwait(false).GetAwaiter().GetResult();

                return View();
            }
            catch
            {
                return View();
            }
        }

        // GET: Users/Delete/5
        public ActionResult Delete(int id)
        {
            return View();
        }

        // POST: Users/Delete/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Delete(int id, IFormCollection collection)
        {
            try
            {
                // TODO: Add delete logic here

                return RedirectToAction("Index");
            }
            catch
            {
                return View();
            }
        }
    }
}
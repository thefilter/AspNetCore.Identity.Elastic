using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AspNetCore.Identity.Elastic;
using ElasticIdentitySample.Mvc.Services;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authorization;

namespace ElasticIdentitySample.Mvc.Controllers
{
    [Authorize(Roles = "Admin")]
    public class UsersController : Controller
    {
        private readonly UserManager<ElasticIdentityUser> _userManager;
        private readonly SignInManager<ElasticIdentityUser> _signInManager;
        private readonly IEmailSender _emailSender;
        private readonly ISmsSender _smsSender;
        private readonly ILoggerFactory _loggerFactory;

        public UsersController(
            UserManager<ElasticIdentityUser> userManager,
            SignInManager<ElasticIdentityUser> signInManager,
            IEmailSender emailSender,
            ISmsSender smsSender,
            ILoggerFactory loggerFactory
        )
        {
            _userManager = userManager;
            _signInManager = signInManager;
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
        public async Task<ActionResult> Edit(string id)
        {
            var user = await _userManager.FindByIdAsync(id);

            return View(user);
        }

        // POST: Users/Edit/5
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<ActionResult> Edit(string id, IFormCollection collection)
        {
            try
            {
                if (id == null)
                {
                    return new BadRequestResult();
                }

                var user = await _userManager.FindByIdAsync(id);

                var claimTypes = collection["Claim.Type"];
                var claimValues = collection["Claim.Value"];

                var claims = claimTypes
                    .Select((value, i) => new Claim(value, claimValues[i]))
                 //   .GroupBy(c => c.Type)
                    .ToList();
                var roles = collection["Roles"].ToList();

                await _userManager.AddClaimsAsync(user, claims);
                user = await _userManager.FindByIdAsync(id);
                await _userManager.AddToRolesAsync(user, roles);

                user = await _userManager.FindByIdAsync(id);

                return View(user);
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
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using MuAuthApp.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MuAuthApp.Controllers
{
    [Route("api/auth")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public AuthController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManger, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManger;
            _configuration = configuration;
        }

        // login endpoint as well as generate JSON web token (JWT)
        // this is a POST request where we accept a username and password in the request body
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var token = await GenerateJwtToken(user);
                var roles = await _userManager.GetRolesAsync(user);
            
                
                // uncomment to sent the jwt token as a json response instead of a cookie
                // return Ok(new { Token = token });

                // send jwt as a cookie instead of a json response comment out if you prefer json
                Response.Cookies.Append("jwt", token, new CookieOptions
                {
                    HttpOnly = true,
                    SameSite = SameSiteMode.Lax,
                    Expires = DateTime.UtcNow.AddMinutes(60)
                });

                return Ok(new {
                    userName = user.UserName,
                    role = roles
                });
            }

            return Unauthorized();
        }

        [HttpPost("assign-role")]
        [Authorize(Roles = "Admin")]
        public async Task<IActionResult> AssignRole([FromBody] AssignRoleModel model)
        {
            var user = await _userManager.FindByNameAsync(model.UserName);
            if (user == null)
            {
                return NotFound("User Not Found");
            }

            var roleExisits = await _roleManager.RoleExistsAsync(model.RoleName);
            if (!roleExisits) 
            {
                return BadRequest($"Role '{model.RoleName}' does not exists.");
            }

            var result = await _userManager.AddToRoleAsync(user, model.RoleName);

            if (result.Succeeded)
            {
                return Ok($"User `{model.UserName}` added to role '{model.RoleName}'");
            }

            return BadRequest(result.Errors);
        }

        [HttpPost("logout")]
        public async Task<IActionResult> Logout()
        {
            Response.Cookies.Delete("jwt");
            return Ok();
        }

        [HttpGet("check-admin")]
        [Authorize(Roles = "Admin")]
        public IActionResult CheckAdmin()
        {
            return Ok(new { IsAdmin = true, Username = User.Identity.Name });
        }

        [HttpGet("debug-auth")]
        public IActionResult DebugAuth()
        {
            var authHeader = HttpContext.Request.Headers["Authorization"].ToString();

            return Ok(new
            {
                HasAuthHeader = !string.IsNullOrEmpty(authHeader),
                AuthHeaderValue = authHeader,
                AuthScheme = authHeader?.Split(' ')?.FirstOrDefault(),
                TokenPresent = authHeader?.Contains("Bearer") == true,
                TokenValue = authHeader?.Replace("Bearer ", "")
            });
        }

        [HttpGet("secure")]
        [Authorize]
        public async Task<IActionResult> Secure()
        {
            var user = await _userManager.FindByNameAsync(User.Identity.Name);
            if (user != null)
            {
                var roles = await _userManager.GetRolesAsync(user);
                return Ok(new {
                    userName = user.UserName,
                    role = roles
                });
            }
            return Ok();
        }

        // [Authorize] makes it so only authenticated users can access this end points
        [HttpGet("profile")]
        [Authorize] 
        public IActionResult GetProfile()
        {
            // Debug the authorization header
            var authHeader = Request.Headers["Authorization"].ToString();
            Console.WriteLine($"Auth Header: {authHeader}");

            var username = User.Identity.Name;
            Console.WriteLine($"Username from token: {username}");

            return Ok(new { Username = username });
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            if (ModelState.IsValid)
            {
                // check if both username and email already exists
                var existingUser = await _userManager.FindByNameAsync(model.UserName);
                if (existingUser != null)
                {
                    return BadRequest("Username already exists.");
                }

                var existingEmail = await _userManager.FindByEmailAsync(model.Email);
                if (existingEmail != null)
                {
                    return BadRequest("Email already exists.");
                }

                // else crete new identify user
                var user = new IdentityUser
                {
                    UserName = model.UserName,
                    Email = model.Email
                };
                
                // then create a user with the provided password
                var result = await _userManager.CreateAsync(user, model.Password);

                // if successful generate a JWT token 
                if (result.Succeeded)
                {
                    var token = GenerateJwtToken(user);
                    return Ok(new { Token = token });
                }

                return BadRequest(result.Errors);
            }

            return BadRequest("Invalid data.");
        }

        private async Task<string> GenerateJwtToken(IdentityUser user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            List<Claim> claims  =
            [
                // Sub is the subject of the token (the username of the authenticated user)
                // Jti is a unique identifier for the token aka GUID
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(ClaimTypes.Name, user.UserName)
            ];

            // add roles to claims
            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                claims.Add(new Claim(ClaimTypes.Role, role));
            }
            
            // we use the secret key from appsettins to sing the jwt
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Secret"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.Now.AddMinutes(Convert.ToDouble(jwtSettings["ExpireMinutes"])),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

    }
}
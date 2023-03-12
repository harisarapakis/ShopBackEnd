using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Shop.Database;
using Shop.Helpers;
using Shop.Model.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Shop.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UserController : Controller
    {
        private readonly MyDbContext _myDbContext;
        public UserController(MyDbContext myDbContext)
        {
            _myDbContext = myDbContext;
        }
        [HttpPost("authendicated")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();
            
            var user = await _myDbContext.Users.FirstOrDefaultAsync(x => x.UserName == userObj.UserName);
            if (user == null)
                return NotFound(new {Message = "User Not Found!"});
            if(!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
                {
                return BadRequest(new { Message = "Password is Incorect" });
            }

            return Ok(new
            {
                Token = user.Token,
                Message = "Login Success!"
            });
            
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();
            if (await CheckUsernameExists(userObj.UserName))
                return BadRequest(new { Message = "Username already exists" });
            if (await CheckEmailExists(userObj.Email))
                return BadRequest(new { Message = "Username already exists" });

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = GenerateJwtToken(userObj);
            await _myDbContext.Users.AddAsync(userObj);
            await _myDbContext.SaveChangesAsync();
            return Ok(new
            {
                Token = userObj.Token,
                Message = "User Registered!"
            });
        }
        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _myDbContext.Users.ToListAsync());
        }

        private async Task<bool> CheckUsernameExists(string userName)
        {
            return await _myDbContext.Users.AnyAsync<User>(x => x.UserName == userName);
        }
        private async Task<bool> CheckEmailExists(string email)
        {
            return await _myDbContext.Users.AnyAsync<User>(x => x.Email == email);
        }
        private string GenerateJwtToken(User user)
        {
            // Create a security key using the secret key
            var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("ThisismysecretCode................."));

            // Create the signing credentials
            var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

            var idenitty = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role, user.Role),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}"),
            });

            // Create the token descriptor
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Expires = DateTime.UtcNow.AddDays(1),
                SigningCredentials = signingCredentials,
                Subject = idenitty
            };

            // Create the token handler
            var tokenHandler = new JwtSecurityTokenHandler();

            // Create the token using the token handler
            var token = tokenHandler.CreateToken(tokenDescriptor);

            // Return the serialized token
            return tokenHandler.WriteToken(token);
        }
    }
}

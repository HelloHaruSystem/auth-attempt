using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace MuAuthApp.Data
{
    public class AppDbContext : IdentityDbContext<AppDbContext>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options)
        : base(options)
        {

        } 
    }
}
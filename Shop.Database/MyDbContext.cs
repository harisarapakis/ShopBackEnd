using Microsoft.EntityFrameworkCore;
using Shop.Model.Models;


namespace Shop.Database
{
    public class MyDbContext : DbContext
    {
        public MyDbContext(DbContextOptions options) : base(options){ }
        public DbSet<Employee> Employees { get; set; }
    }
}

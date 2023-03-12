using Microsoft.EntityFrameworkCore;
using Shop.Model.Models;
using System.Xml;


namespace Shop.Database
{
    public class MyDbContext : DbContext
    {
        public MyDbContext(DbContextOptions options) : base(options){ }
        public DbSet<Employee> Employees { get; set; }
        public DbSet<User> Users { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("users");
        }

    }
}

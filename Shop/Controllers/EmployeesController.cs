using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Shop.Database;
using Shop.Model.Models;

namespace Shop.Controllers
{
    [Authorize]
    [ApiController]
    [Route("api/[controller]")]
    public class EmployeesController : Controller
    {
        private readonly MyDbContext _myDbContext;
        public EmployeesController(MyDbContext myDbContext)
        {
            _myDbContext = myDbContext;
        }
        [HttpGet]
        public async Task<IActionResult> GetAllEmployees()
        {
            var employees = await _myDbContext.Employees.ToListAsync();
            return Ok(employees);
        }
        [HttpGet]
        [Route("{id:Guid}")]
        public async Task<IActionResult> GetEmployee([FromRoute] Guid Id)
        {
            var employee = await _myDbContext.Employees.FirstOrDefaultAsync( emp => emp.Id == Id);

            if (employee == null)
            {
                return NotFound(); // return 404 Not Found if employee is not found
            }
            return Ok(employee);
        }
        [HttpPost]
        public async Task<IActionResult> AddEmployees([FromBody] Employee request)
        {
            request.Id = Guid.NewGuid();
            await _myDbContext.Employees.AddAsync(request);
            await _myDbContext.SaveChangesAsync();
            return Ok(request);
        }

        [HttpPut]
        [Route("{id:Guid}")]
        public async Task<IActionResult> EditEmployee([FromRoute] Guid Id, Employee editReuqest)
        {
            var employee = await _myDbContext.Employees.FindAsync(Id);

            if (employee == null)
            {
                return NotFound(); // return 404 Not Found if employee is not found
            }

            employee.Email = editReuqest.Email;
            employee.Salary = editReuqest.Salary;
            employee.Phone = editReuqest.Phone;
            employee.Name = editReuqest.Name;
            employee.Department = editReuqest.Department;

            await _myDbContext.SaveChangesAsync();

            return Ok(employee);
        }

        [HttpDelete]
        [Route("{id:Guid}")]

        public async Task<IActionResult> DeleteEmployees([FromRoute] Guid Id)
        {
            var employee = await _myDbContext.Employees.FindAsync(Id);
            _myDbContext.Employees.Remove(employee);
            await _myDbContext.SaveChangesAsync();
            return Ok(employee);
        }
    }
}

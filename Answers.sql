-------Answrers:

--q1
with mx_salary as 
(
select max(salary) as mx_salary , e.department_id
from [dbo].[Employees] as e  join [Departments] as d on d.department_id=e.department_id
group by e.department_id
)


select distinct  ee.employee_id,ee.first_name+' '+ee.last_name as [Full Name], e.mx_salary,d.department_name

from [Employees] as ee  join mx_salary  as e on e.department_id=ee.department_id and mx_salary=ee.salary
                        join Departments as d on e.department_id=d.department_id
order by mx_salary desc


--q2

select t.*,(t.salary-t.[lead]) as [Salary_Diff] 
from 
(
select  e.employee_id,e.first_name+' '+e.last_name as [Full Name] ,e.salary , LEAD (e.salary) over (order by e.employee_id) as [lead]
from [dbo].[Employees] as e
) as t
order by 1


--q2

declare @Cnt int = (select count(*) from Employees)
--select @Cnt

select *,datediff(yy,hire_date,convert(date,getdate())) as Bigerthen3Year,@Cnt , employee_id / @Cnt as [percent]
from Employees
where datediff(yy,hire_date,convert(date,getdate()))>3
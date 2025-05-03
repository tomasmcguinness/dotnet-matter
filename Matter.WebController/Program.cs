using Matter.WebController;
using Matter.WebController.Hubs;
using Microsoft.Extensions.Hosting;
using Zeroconf;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddSignalR();

builder.Services.AddSingleton<DiscoveryMonitorLoop>();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();

app.MapHub<DiscoveryHub>("/discoveryHub");

var monitorLoop = app.Services.GetRequiredService<DiscoveryMonitorLoop>();
monitorLoop.StartMonitorLoop();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();

using optiCombat.Service;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;

var builder = Host.CreateApplicationBuilder(args);
builder.Services.AddWindowsService(options => options.ServiceName = "optiCombat Protection");
builder.Services.AddHostedService<ProtectionWindowsService>();
var host = builder.Build();
await host.RunAsync();
